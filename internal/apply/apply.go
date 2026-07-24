// Package apply executes a plan: writes the changes diff computed and updates
// the manifest accordingly. Per-resource error handling per the spec — one
// failed resource does not halt the rest, and the worst outcome wins.
//
// See docs/spec-reconciler.md "Apply mechanics".
package apply

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/lazypower/magus-cli/internal/applygraph"
	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/graph"
	"github.com/lazypower/magus-cli/internal/hostfs"
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/policy"
	"github.com/lazypower/magus-cli/internal/systemd"
)

// Status records what happened to one resource during apply.
type Status string

const (
	// StatusApplied — a change was successfully made (create, update, adopt,
	// delete, cleanup, daemon-reload, enable, restart). The summary
	// "Applied N changes" counts these.
	StatusApplied Status = "applied"
	// StatusUnchanged — the resource was already in its desired state. No-op.
	// Not surfaced in the summary; only in per-resource output.
	StatusUnchanged Status = "unchanged"
	// StatusSkipped — apply could not proceed (conflict, orphaned, or
	// adoption drift). Not an error; the resource simply couldn't converge.
	StatusSkipped Status = "skipped"
	// StatusErrored — a write or syscall failed mid-apply.
	StatusErrored Status = "errored"
)

// Outcome is the per-resource report apply emits. Reason is a one-line
// description suitable for human output; Err is set only for StatusErrored.
type Outcome struct {
	Path   string
	Action diff.Action
	Status Status
	Reason string
	Err    error
}

// Result is the collected outcome of one apply call.
type Result struct {
	Outcomes []Outcome
	// UnitStates is the observed is-active state of each managed unit and
	// quadlet generated service after apply settled (name → "active"/"inactive"/
	// …). Captured for the status observation file; empty when systemd is
	// unavailable.
	UnitStates map[string]string
}

// Counts groups outcomes by Status for the summary line.
func (r *Result) Counts() (applied, unchanged, skipped, errored int) {
	for _, o := range r.Outcomes {
		switch o.Status {
		case StatusApplied:
			applied++
		case StatusUnchanged:
			unchanged++
		case StatusSkipped:
			skipped++
		case StatusErrored:
			errored++
		}
	}
	return
}

// ExitCode picks per the spec: errors > skips > clean.
func (r *Result) ExitCode() int {
	var hasSkip, hasError bool
	for _, o := range r.Outcomes {
		switch o.Status {
		case StatusSkipped:
			hasSkip = true
		case StatusErrored:
			hasError = true
		}
	}
	if hasError {
		return 1
	}
	if hasSkip {
		return 2
	}
	return 0
}

// pendingResource is a unified view of a path the IR declares. Files, units,
// and directories flatten to the same shape; Contents is empty for
// directories and the apply path branches on Kind when content matters
// (writes vs mkdir+chmod+chown).
type pendingResource struct {
	Path     string
	Mode     uint32
	UID, GID *int
	Contents []byte
	Kind     manifest.Kind
}

// Apply executes plan against w and sd. The manifest is mutated in place; the
// caller is responsible for persisting it after Apply returns. `now` is
// injected so applied_at timestamps are deterministic in tests.
//
// Apply walks the apply-ordering graph (applygraph.Derive) in topological order
// rather than a fixed phase pipeline. Each node carries its own behavior —
// filesystem mutation, the single daemon-reload barrier, or a service reconcile
// — and the graph's typed edges drive two cross-node behaviors the old phases
// couldn't express:
//
//   - require: if a required predecessor fails (errors or skips), the dependent
//     node is skipped with "dependency <path> failed" rather than run against a
//     broken prerequisite (the honest fail-closed cascade).
//   - notify: if a node the graph marks as notifying a service actually changed
//     (an EnvironmentFile= the service consumes), the service is restarted even
//     when its own body did not change — closing the config-propagation gap.
//
// The invariants the phases used to enforce by ordering are preserved as node
// behavior: daemon-reload runs exactly once (an OR-join barrier), unit-body
// deletes disable-now before unlink, quadlet deletes stop the generated service
// before the source vanishes, and every path-governed mutation re-checks
// containment at apply time.
//
// Per-resource errors do not halt — the reconciler-pattern posture from the
// spec. One bad resource does not take the system hostage.
func Apply(plan *diff.Plan, in *ir.IR, w hostfs.Writer, m *manifest.Manifest, sd systemd.Manager, now time.Time) *Result {
	return ApplyWithPolicy(nil, plan, in, w, m, sd, now)
}

// ApplyWithPolicy is Apply plus an apply-time symlink-containment re-check: just
// before each path-governed write or delete it re-resolves the target and skips
// it if a symlinked ancestor now redirects it outside policy authority. This
// closes the plan→apply TOCTOU window (the plan was computed earlier; an ancestor
// could have been swapped to a symlink since). p may be nil to skip the re-check
// (unit-test callers). The residual race between this check and the syscall is
// only exploitable by an attacker who can write a file_root ancestor — i.e.
// root on the real core-base layout — which is out of scope.
func ApplyWithPolicy(p *policy.Policy, plan *diff.Plan, in *ir.IR, w hostfs.Writer, m *manifest.Manifest, sd systemd.Manager, now time.Time) *Result {
	resources := indexResources(in)
	r := &Result{Outcomes: make([]Outcome, 0, len(plan.Actions))}

	g := applygraph.Derive(plan, in)
	order, err := g.TopoSort()
	if err != nil {
		// A cyclic apply graph is a derivation contradiction — mutually
		// dependent resources with no safe order. Fail closed: apply nothing
		// and surface the cycle, rather than pick an arbitrary order and half
		// converge. Still observe so status reflects live state.
		r.Outcomes = append(r.Outcomes, Outcome{
			Path: "apply-graph", Action: diff.ActionError,
			Status: StatusErrored, Err: err,
		})
		r.UnitStates = ObserveUnits(in, sd)
		return r
	}

	ex := &executor{
		p: p, plan: plan, in: in, w: w, m: m, sd: sd, now: now,
		resources:     resources,
		actionByPath:  make(map[string]diff.ResourceAction, len(plan.Actions)),
		unitByService: make(map[string]ir.Unit, len(in.Units)),
		quadletByNode: map[string]quadletNode{},
		reqInto:       map[string][]string{},
		notifyInto:    map[string][]string{},
		changed:       map[string]bool{},
		failed:        map[string]bool{},
		events:        map[string]*unitEvents{},
		quadletEvents: map[string]*unitEvents{},
	}
	for _, a := range plan.Actions {
		ex.actionByPath[a.Path] = a
	}
	for _, u := range in.Units {
		ex.unitByService[u.Name] = u
	}
	for _, q := range in.Quadlets {
		if q.Scope == ir.ScopeUser {
			continue // user-scope quadlets reconcile through the user manager (ReconcileUserWorkloads)
		}
		if svc, err := diff.QuadletGeneratedService(q.Name); err == nil {
			ex.quadletByNode[svc] = quadletNode{quadlet: q, service: svc}
		}
	}
	// Incoming require/notify predecessors per node, derived once. g.Edges() is
	// globally sorted by (From,To,Kind), so each predecessor list is built in a
	// deterministic order — the failure cascade names a stable dependency.
	for _, e := range g.Edges() {
		switch e.Kind {
		case graph.Require:
			ex.reqInto[e.To] = append(ex.reqInto[e.To], e.From)
		case graph.Notify:
			ex.notifyInto[e.To] = append(ex.notifyInto[e.To], e.From)
		}
	}

	for _, n := range order {
		r.Outcomes = append(r.Outcomes, ex.visit(n)...)
	}

	// Observe the runtime state of every managed unit/quadlet service for the
	// status file.
	r.UnitStates = ObserveUnits(in, sd)
	return r
}

// quadletNode pairs a quadlet's generated-service node id with its IR source, so
// the executor can reconcile the service while reading the events recorded under
// the quadlet's own name.
type quadletNode struct {
	quadlet ir.Quadlet
	service string
}

// executor holds the mutable walk state for one ApplyWithPolicy call: the
// derived edge indexes, per-node results (changed drives notify, failed drives
// the require cascade), and the unit/quadlet event accumulators the service
// nodes read once their resource nodes have run.
type executor struct {
	p    *policy.Policy
	plan *diff.Plan
	in   *ir.IR
	w    hostfs.Writer
	m    *manifest.Manifest
	sd   systemd.Manager
	now  time.Time

	resources     map[string]pendingResource
	actionByPath  map[string]diff.ResourceAction
	unitByService map[string]ir.Unit
	quadletByNode map[string]quadletNode

	reqInto    map[string][]string
	notifyInto map[string][]string

	changed map[string]bool
	failed  map[string]bool

	events        map[string]*unitEvents
	quadletEvents map[string]*unitEvents
}

// visit executes one graph node and returns its outcome(s). Topological order
// guarantees every predecessor has already run, so the require/notify lookups
// read settled state.
func (ex *executor) visit(n string) []Outcome {
	// Dependency gate: a failed require-predecessor skips this node — the honest
	// fail-closed cascade. The daemon-reload barrier is exempt: it is an OR-join
	// over its triggers (it must still run for the writes that DID succeed), so
	// a single failed write must not suppress it.
	if n != applygraph.ReloadNode {
		if dep, ok := firstFailed(ex.reqInto[n], ex.failed); ok {
			ex.failed[n] = true
			return []Outcome{{
				Path: n, Action: diff.ActionSkip,
				Status: StatusSkipped, Reason: "dependency " + dep + " failed",
			}}
		}
	}

	switch {
	case n == applygraph.ReloadNode:
		return ex.visitReload(n)
	case ex.isUnitService(n):
		return ex.visitUnitService(n)
	case ex.isQuadletService(n):
		return ex.visitQuadletService(n)
	default:
		return ex.visitResource(n)
	}
}

func (ex *executor) isUnitService(n string) bool {
	_, ok := ex.unitByService[n]
	return ok
}

func (ex *executor) isQuadletService(n string) bool {
	_, ok := ex.quadletByNode[n]
	return ok
}

// visitReload runs the single daemon-reload, but only when at least one of its
// trigger predecessors actually changed on disk (reproducing the old
// anyUnitMutation gate). A reload failure propagates to the services that
// require it, which then skip honestly.
func (ex *executor) visitReload(n string) []Outcome {
	if !anyTrue(ex.reqInto[n], ex.changed) {
		return nil // every triggering write failed or was a no-op — nothing to reload
	}
	oc := Outcome{Path: applygraph.ReloadNode, Action: diff.ActionUpdate}
	if err := ex.sd.DaemonReload(); err != nil {
		oc.Status = StatusErrored
		oc.Err = err
		ex.failed[n] = true
	} else {
		oc.Status = StatusApplied
	}
	return []Outcome{oc}
}

// visitUnitService reconciles one IR unit's systemd state, restarting it if the
// unit changed OR a notify source it consumes changed.
func (ex *executor) visitUnitService(n string) []Outcome {
	u := ex.unitByService[n]
	ev := ex.events[u.Name]
	if ev == nil {
		ev = &unitEvents{}
	}
	notified := anyTrue(ex.notifyInto[n], ex.changed)
	outcomes := reconcileServiceState(u.Name, u.Enabled, ev, notified, ex.sd)
	ex.failed[n] = anyFailed(outcomes)
	return outcomes
}

// visitQuadletService reconciles one IR quadlet's generated service.
func (ex *executor) visitQuadletService(n string) []Outcome {
	qn := ex.quadletByNode[n]
	ev := ex.quadletEvents[qn.quadlet.Name]
	if ev == nil {
		ev = &unitEvents{}
	}
	notified := anyTrue(ex.notifyInto[n], ex.changed)
	outcomes := reconcileQuadletState(qn.service, ev, notified, ex.sd)
	ex.failed[n] = anyFailed(outcomes)
	return outcomes
}

// visitResource applies one filesystem node (file, dir, unit body, drop-in, or
// quadlet source) and records the unit/quadlet event its service node reads. The
// special service-aware deletes — disable-now before a unit-body unlink, stop
// the generated service before a quadlet source unlink — live here as node
// behavior; the graph's edges order them ahead of the reload barrier.
func (ex *executor) visitResource(n string) []Outcome {
	a, ok := ex.actionByPath[n]
	if !ok {
		return nil // node with no plan action (defensive; every node is classified)
	}

	var oc Outcome
	switch {
	case isUnitBodyDelete(a):
		oc = applyUnitBodyDelete(a, ex.w, ex.m, ex.sd)
		if oc.Status == StatusApplied {
			ex.getEvents(a.UnitName).bodyDeleted = true
		}
	case isQuadletDelete(a):
		oc = applyQuadletDelete(ex.p, a, ex.w, ex.m, ex.sd)
		if oc.Status == StatusApplied {
			ex.getQuadletEvents(a.UnitName).bodyDeleted = true
		}
	default:
		oc = applyOne(ex.p, a, ex.resources, ex.w, ex.m, ex.now)
		if oc.Status == StatusApplied {
			switch a.Kind {
			case diff.KindUnit:
				isBody := filepath.Base(a.Path) == a.UnitName
				recordUnitEvent(ex.getEvents(a.UnitName), a.Action, isBody)
			case diff.KindQuadlet:
				recordUnitEvent(ex.getQuadletEvents(a.UnitName), a.Action, true)
			}
		}
	}

	ex.changed[n] = oc.Status == StatusApplied && isMutationAction(a.Action)
	ex.failed[n] = oc.Status == StatusErrored || oc.Status == StatusSkipped
	return []Outcome{oc}
}

func (ex *executor) getEvents(name string) *unitEvents {
	if e, ok := ex.events[name]; ok {
		return e
	}
	e := &unitEvents{}
	ex.events[name] = e
	return e
}

func (ex *executor) getQuadletEvents(name string) *unitEvents {
	if e, ok := ex.quadletEvents[name]; ok {
		return e
	}
	e := &unitEvents{}
	ex.quadletEvents[name] = e
	return e
}

// firstFailed returns the first predecessor in preds whose node has failed, and
// whether one exists. Preds are in deterministic order, so the named dependency
// is stable run-to-run.
func firstFailed(preds []string, failed map[string]bool) (string, bool) {
	for _, p := range preds {
		if failed[p] {
			return p, true
		}
	}
	return "", false
}

// anyTrue reports whether any node in preds is marked true in m (used for both
// the reload OR-join over changed triggers and the notify test over changed
// sources).
func anyTrue(preds []string, m map[string]bool) bool {
	for _, p := range preds {
		if m[p] {
			return true
		}
	}
	return false
}

// anyFailed reports whether any outcome errored or skipped — a service node's
// contribution to the require cascade (a reference dependent skips if the
// network/volume service it requires didn't come up).
func anyFailed(ocs []Outcome) bool {
	for _, oc := range ocs {
		if oc.Status == StatusErrored || oc.Status == StatusSkipped {
			return true
		}
	}
	return false
}

// isMutationAction reports whether an action changes bytes on disk — the signal
// a notify edge propagates. Adopt (no write), cleanup (manifest-only), and the
// no-op/refused actions do not notify their consumers.
func isMutationAction(a diff.Action) bool {
	switch a {
	case diff.ActionCreate, diff.ActionUpdate, diff.ActionDelete:
		return true
	default:
		return false
	}
}

// ObserveUnits queries the is-active state of every IR-declared unit and quadlet
// generated service (name → "active"/"inactive"/"unknown"). Best-effort and
// read-only — used to populate the status observation, including on a no-op
// apply where the full Apply pass didn't run.
func ObserveUnits(in *ir.IR, sd systemd.Manager) map[string]string {
	out := map[string]string{}
	for _, u := range in.Units {
		out[u.Name] = activeState(sd, u.Name)
	}
	for _, q := range in.Quadlets {
		if q.Scope == ir.ScopeUser {
			continue // observed through the user manager, not the system one
		}
		if svc, err := diff.QuadletGeneratedService(q.Name); err == nil {
			out[svc] = activeState(sd, svc)
		}
	}
	return out
}

// activeState returns the observed runtime state of a service (active/inactive/
// failed/activating/…) or "unknown" if it can't be determined. Observation
// only — never fatal.
func activeState(sd systemd.Manager, name string) string {
	status, err := sd.Show(name)
	if err != nil {
		return "unknown"
	}
	return status.Active
}

func indexResources(in *ir.IR) map[string]pendingResource {
	out := map[string]pendingResource{}
	for _, f := range in.Files {
		out[f.Path] = pendingResource{
			Path:     f.Path,
			Mode:     f.Mode,
			UID:      f.UID,
			GID:      f.GID,
			Contents: f.Contents,
			Kind:     manifest.KindFile,
		}
	}
	for _, u := range in.Units {
		if len(u.Contents) > 0 {
			path := diff.UnitPath(u.Name)
			out[path] = pendingResource{
				Path:     path,
				Mode:     0o644,
				Contents: []byte(u.Contents),
				Kind:     manifest.KindUnit,
			}
		}
		for _, di := range u.DropIns {
			path := diff.DropInPath(u.Name, di.Name)
			out[path] = pendingResource{
				Path:     path,
				Mode:     0o644,
				Contents: []byte(di.Contents),
				Kind:     manifest.KindUnit,
			}
		}
	}
	for _, d := range in.Directories {
		out[d.Path] = pendingResource{
			Path: d.Path,
			Mode: d.Mode,
			UID:  d.UID,
			GID:  d.GID,
			Kind: manifest.KindDirectory,
		}
	}
	for _, q := range in.Quadlets {
		out[q.Path] = pendingResource{
			Path:     q.Path,
			Mode:     q.Mode,
			UID:      q.UID,
			GID:      q.GID,
			Contents: q.Contents,
			Kind:     manifest.KindQuadlet,
		}
	}
	return out
}

// isUnitBodyDelete reports whether a is the special "delete a unit's body
// file" case that requires disable-now before unlink. Drop-in deletes do
// not qualify — their parent unit's enablement is independent.
func isUnitBodyDelete(a diff.ResourceAction) bool {
	if a.Kind != diff.KindUnit || a.Action != diff.ActionDelete {
		return false
	}
	return filepath.Base(a.Path) == a.UnitName
}

// isQuadletDelete reports whether a is a quadlet source-file delete. Quadlet
// deletes need the *generated* service stopped before the source vanishes —
// otherwise systemd keeps running the old container until next boot.
func isQuadletDelete(a diff.ResourceAction) bool {
	return a.Kind == diff.KindQuadlet && a.Action == diff.ActionDelete
}

// applyUnitBodyDelete runs disable --now then unlinks the unit body file.
// Either step's failure is reported as the outcome's error; if disable-now
// fails the file is NOT unlinked (that would orphan systemd's runtime state).
func applyUnitBodyDelete(a diff.ResourceAction, w hostfs.Writer, m *manifest.Manifest, sd systemd.Manager) Outcome {
	oc := Outcome{Path: a.Path, Action: a.Action}
	if err := sd.DisableNow(a.UnitName); err != nil {
		oc.Status = StatusErrored
		oc.Err = fmt.Errorf("disable --now %s: %w", a.UnitName, err)
		return oc
	}
	if err := w.Remove(a.Path); err != nil {
		oc.Status = StatusErrored
		oc.Err = err
		return oc
	}
	m.Delete(a.Path)
	oc.Status = StatusApplied
	oc.Reason = "disabled, stopped, removed"
	return oc
}

// applyQuadletDelete stops the generated service, then unlinks the quadlet
// source. Daemon-reload runs later in the batched phase 2 — that's what
// causes the generator to drop the now-orphaned .service from systemd's view.
func applyQuadletDelete(p *policy.Policy, a diff.ResourceAction, w hostfs.Writer, m *manifest.Manifest, sd systemd.Manager) Outcome {
	oc := Outcome{Path: a.Path, Action: a.Action}
	if reason := containmentReason(p, w, a.Kind, a.Path); reason != "" {
		oc.Status = StatusSkipped
		oc.Reason = reason
		return oc
	}
	svc, err := diff.QuadletGeneratedService(a.UnitName)
	if err != nil {
		oc.Status = StatusErrored
		oc.Err = err
		return oc
	}
	// Stop (NOT disable --now): the generated service can't be disabled. Only
	// stop it if it's actually running — a quadlet whose generated service never
	// materialized (e.g. the generator rejected an invalid .container source)
	// isn't loaded, and `systemctl stop` on it would fail and wedge the delete
	// forever. Tolerating "not active" lets the reconciler remove the bad source
	// (D11). A real stop failure on a running service is still surfaced.
	if status, _ := sd.Show(svc); status.IsActive() {
		if err := sd.Stop(svc); err != nil {
			oc.Status = StatusErrored
			oc.Err = fmt.Errorf("stop %s: %w", svc, err)
			return oc
		}
	}
	if err := w.Remove(a.Path); err != nil {
		oc.Status = StatusErrored
		oc.Err = err
		return oc
	}
	m.Delete(a.Path)
	oc.Status = StatusApplied
	oc.Reason = fmt.Sprintf("stopped %s, removed source", svc)
	return oc
}

func applyOne(p *policy.Policy, a diff.ResourceAction, resources map[string]pendingResource, w hostfs.Writer, m *manifest.Manifest, now time.Time) Outcome {
	oc := Outcome{Path: a.Path, Action: a.Action}

	// Apply-time containment re-check for path-governed mutations, closing the
	// plan→apply TOCTOU window. A symlinked ancestor planted since planning that
	// redirects this path outside authority turns it into a skip, not a write.
	switch a.Action {
	case diff.ActionCreate, diff.ActionUpdate, diff.ActionAdopt, diff.ActionDelete:
		if reason := containmentReason(p, w, a.Kind, a.Path); reason != "" {
			oc.Status = StatusSkipped
			oc.Reason = reason
			return oc
		}
	}

	switch a.Action {
	case diff.ActionSkip:
		oc.Status = StatusUnchanged
		oc.Reason = "unchanged"
		return oc

	case diff.ActionError:
		// Diff couldn't determine this path's state (stat/read failure). Refuse
		// to touch it — fail-closed — and surface the error. Other resources
		// were still planned and apply normally.
		oc.Status = StatusErrored
		oc.Err = errors.New(a.Reason)
		return oc

	case diff.ActionConflict, diff.ActionOrphaned:
		oc.Status = StatusSkipped
		oc.Reason = a.Reason
		return oc

	case diff.ActionCleanup:
		m.Delete(a.Path)
		oc.Status = StatusApplied
		oc.Reason = "manifest cleanup (file already gone)"
		return oc

	case diff.ActionDelete:
		// Plain file delete or drop-in delete. Unit body deletes are routed
		// through applyUnitBodyDelete by the caller.
		if err := w.Remove(a.Path); err != nil {
			oc.Status = StatusErrored
			oc.Err = err
			return oc
		}
		m.Delete(a.Path)
		oc.Status = StatusApplied
		oc.Reason = "removed"
		return oc

	case diff.ActionCreate, diff.ActionUpdate:
		r, ok := resources[a.Path]
		if !ok {
			oc.Status = StatusErrored
			oc.Err = fmt.Errorf("internal: %s action references unknown IR path %s", a.Action, a.Path)
			return oc
		}
		if r.Kind == manifest.KindDirectory {
			return applyDirectoryCreateOrUpdate(a, r, w, m, now)
		}
		if err := w.WriteFile(a.Path, r.Contents, r.Mode, r.UID, r.GID); err != nil {
			oc.Status = StatusErrored
			oc.Err = err
			return oc
		}
		// Updates preserve their original origin (create vs adopt) so the
		// audit trail isn't lost when content evolves.
		origin := manifest.OriginCreate
		if a.Action == diff.ActionUpdate {
			if existing, ok := m.Get(a.Path); ok {
				origin = existing.Origin
			}
		}
		m.PutActive(a.Path, r.Kind, diff.HashContent(r.Contents, diffKind(r.Kind)), origin, now)
		oc.Status = StatusApplied
		return oc

	case diff.ActionAdopt:
		r, ok := resources[a.Path]
		if !ok {
			oc.Status = StatusErrored
			oc.Err = fmt.Errorf("internal: adopt action references unknown IR path %s", a.Path)
			return oc
		}
		if r.Kind == manifest.KindDirectory {
			return applyDirectoryAdopt(a, r, w, m, now)
		}
		// Re-verify on-disk hash equals declared hash. Conditions may have
		// changed between plan and apply — adoption is bounded by exact
		// content match at apply-time, not just plan-time.
		body, err := w.ReadFile(a.Path)
		if err != nil {
			oc.Status = StatusErrored
			oc.Err = err
			return oc
		}
		if diff.HashContent(body, diffKind(r.Kind)) != diff.HashContent(r.Contents, diffKind(r.Kind)) {
			oc.Status = StatusSkipped
			oc.Reason = "drifted between plan and apply"
			return oc
		}
		m.PutActive(a.Path, r.Kind, diff.HashContent(r.Contents, diffKind(r.Kind)), manifest.OriginAdopt, now)
		oc.Status = StatusApplied
		oc.Reason = "adopted, no write"
		return oc

	default:
		oc.Status = StatusErrored
		oc.Err = fmt.Errorf("unknown action: %s", a.Action)
		return oc
	}
}

// applyDirectoryCreateOrUpdate handles the directory create and update paths.
// Create: mkdir -p with declared mode, chown if specified. Update: chmod
// and/or chown only — directory contents are never touched. The same hash
// sentinel ("sha256:dir") is recorded for all directory entries since
// content is not part of equivalence.
func applyDirectoryCreateOrUpdate(a diff.ResourceAction, r pendingResource, w hostfs.Writer, m *manifest.Manifest, now time.Time) Outcome {
	oc := Outcome{Path: a.Path, Action: a.Action}
	if a.Action == diff.ActionCreate {
		if err := w.Mkdir(a.Path, r.Mode, r.UID, r.GID); err != nil {
			oc.Status = StatusErrored
			oc.Err = err
			return oc
		}
	} else { // Update
		// Re-verify the path is still a directory at apply time. If it was
		// replaced by a regular file since planning, chmod/chown-ing it and
		// recording a directory entry would be wrong — skip, fail-closed.
		if st, err := w.Stat(a.Path); err != nil {
			oc.Status = StatusErrored
			oc.Err = err
			return oc
		} else if !st.Exists || !st.IsDir {
			oc.Status = StatusSkipped
			oc.Reason = "drifted between plan and apply (no longer a directory)"
			return oc
		}
		if err := w.Chmod(a.Path, r.Mode); err != nil {
			oc.Status = StatusErrored
			oc.Err = err
			return oc
		}
		if err := w.Chown(a.Path, r.UID, r.GID); err != nil {
			oc.Status = StatusErrored
			oc.Err = err
			return oc
		}
	}
	origin := manifest.OriginCreate
	if a.Action == diff.ActionUpdate {
		if existing, ok := m.Get(a.Path); ok {
			origin = existing.Origin
		}
	}
	m.PutActive(a.Path, manifest.KindDirectory, dirHash, origin, now)
	oc.Status = StatusApplied
	return oc
}

// applyDirectoryAdopt records ownership of an existing directory whose mode
// and ownership already match the IR. Adoption re-verifies metadata at apply
// time so a directory whose mode changed between plan and apply is skipped
// rather than silently taken over.
func applyDirectoryAdopt(a diff.ResourceAction, r pendingResource, w hostfs.Writer, m *manifest.Manifest, now time.Time) Outcome {
	oc := Outcome{Path: a.Path, Action: a.Action}
	st, err := w.Stat(a.Path)
	if err != nil {
		oc.Status = StatusErrored
		oc.Err = err
		return oc
	}
	if !st.Exists || !st.IsDir ||
		st.Mode != r.Mode ||
		(r.UID != nil && st.UID != *r.UID) ||
		(r.GID != nil && st.GID != *r.GID) {
		oc.Status = StatusSkipped
		oc.Reason = "drifted between plan and apply"
		return oc
	}
	m.PutActive(a.Path, manifest.KindDirectory, dirHash, manifest.OriginAdopt, now)
	oc.Status = StatusApplied
	oc.Reason = "adopted, no write"
	return oc
}

// containmentReason returns a non-empty skip reason if mutating path would
// escape policy authority through a symlinked ancestor. Scoped to path-governed
// kinds (file/dir/quadlet); nil policy or a non-Resolver writer disables it
// (unit-test path). See diff.ContainmentEscape.
func containmentReason(p *policy.Policy, w hostfs.Writer, kind diff.Kind, path string) string {
	if p == nil {
		return ""
	}
	switch kind {
	case diff.KindFile, diff.KindDirectory, diff.KindQuadlet:
	default:
		return ""
	}
	r, ok := w.(hostfs.Resolver)
	if !ok {
		return ""
	}
	_, reason := diff.ContainmentEscape(p, r, path)
	return reason
}

// dirHash is the sentinel manifest hash for directory entries. Directories
// have no content equivalence; the hash field is populated for schema
// consistency only.
const dirHash = "sha256:dir"

// diffKind translates a manifest.Kind to a diff.Kind for hash computation.
// They mirror each other but live in separate packages to avoid coupling.
func diffKind(k manifest.Kind) diff.Kind {
	switch k {
	case manifest.KindUnit:
		return diff.KindUnit
	case manifest.KindQuadlet:
		// Quadlets canonicalize like units — without this they'd be stored with
		// a raw hash while diff/reclaim hash them canonically, making a clean
		// orphaned quadlet falsely read as drifted on reclaim.
		return diff.KindQuadlet
	case manifest.KindDirectory:
		return diff.KindDirectory
	default:
		return diff.KindFile
	}
}

// unitEvents tracks what happened to a unit's files during phase 1, so phase 3
// can decide whether to enable, start, restart, or skip. Only the three signals
// phase 2/3 actually consume are tracked: whether the body was created (→ enable
// --now on a new enabled unit), whether the body was deleted (→ already
// disabled+stopped), and whether any content mutation happened (→ daemon-reload
// and restart-if-active).
type unitEvents struct {
	bodyCreated   bool
	bodyDeleted   bool
	hasContentMut bool // any create/update/delete requiring daemon-reload (excludes adopts)
}

func recordUnitEvent(ev *unitEvents, action diff.Action, isBody bool) {
	switch action {
	case diff.ActionCreate:
		if isBody {
			ev.bodyCreated = true
		}
		ev.hasContentMut = true
	case diff.ActionUpdate:
		ev.hasContentMut = true
	case diff.ActionAdopt:
		// adopts don't trigger daemon-reload or restart
	case diff.ActionDelete:
		// Drop-in deletes get here (body deletes are routed elsewhere).
		ev.hasContentMut = true
	}
}

// reconcileServiceState drives systemd state for one service (a unit's name
// or a quadlet's *generated* .service name) after files + daemon-reload have
// settled. Returns one outcome per systemctl operation performed.
//
// desiredEnabled carries the IR's tri-state enablement (see ir.Unit.Enabled):
//
//	nil   → enablement is not declared; magus does not touch it. A unit
//	        declared only to attach a drop-in must not be enabled or disabled
//	        as a side effect of extending it.
//	true  → ensure enabled
//	false → ensure disabled
//
// notified is true when a graph notify source the service consumes (an
// EnvironmentFile=) changed this apply. It forces a restart-if-active even when
// the unit's own body did not change — the config-propagation the phase pipeline
// could not express.
func reconcileServiceState(serviceName string, desiredEnabled *bool, ev *unitEvents, notified bool, sd systemd.Manager) []Outcome {
	if ev.bodyDeleted {
		// Stop+disable already happened when the body-delete node ran.
		return nil
	}
	var outcomes []Outcome

	// Newly-created service: enable+start only when explicitly declared enabled.
	// A freshly-written unit file is not enabled by default, so nil/false need
	// no action at creation. A fresh start already reads the current
	// EnvironmentFile=, so notify is subsumed here.
	if ev.bodyCreated {
		if desiredEnabled != nil && *desiredEnabled {
			err := sd.EnableNow(serviceName)
			outcomes = append(outcomes, unitOutcome(serviceName, "enable --now", err))
		}
		return outcomes
	}

	// Existing service. Both the enablement decision and the restart decision
	// need live state, so fetch it once (Show = enablement + active in one
	// systemctl call) — but only when there's actually a decision to make: a
	// unit whose enablement is undeclared (nil), whose content didn't change,
	// and which no notify source touched needs no query at all.
	if desiredEnabled == nil && !ev.hasContentMut && !notified {
		return outcomes
	}
	status, err := sd.Show(serviceName)

	// Reconcile enablement every apply — but only when the IR declares it. The
	// enable/disable/skip decision comes from diff.EnablementOp, the single
	// authority the planner also uses, so plan and apply never diverge.
	if desiredEnabled != nil {
		if err != nil {
			outcomes = append(outcomes, unitOutcome(serviceName, "show", err))
		} else {
			switch op, reason := diff.EnablementOp(desiredEnabled, status.Enablement); op {
			case diff.ServiceEnable:
				outcomes = append(outcomes, unitOutcome(serviceName, "enable", sd.Enable(serviceName)))
			case diff.ServiceDisable:
				outcomes = append(outcomes, unitOutcome(serviceName, "disable", sd.Disable(serviceName)))
			case diff.ServiceSkip:
				// Declared intent is unachievable (masked/static/not-found).
				// Surface it as a skip instead of a silent no-op (D10).
				outcomes = append(outcomes, Outcome{
					Path:   serviceName,
					Action: diff.ActionSkip,
					Status: StatusSkipped,
					Reason: reason,
				})
			}
		}
	}

	// Restart-if-active for content changes or a notified config change
	// (excludes adopts and skips). Inactive services are rewritten only — the
	// new content/config takes effect on next start. Logged for visibility.
	if ev.hasContentMut || notified {
		if err == nil && status.IsActive() {
			outcomes = append(outcomes, unitOutcome(serviceName, restartReason(ev.hasContentMut), sd.Restart(serviceName)))
		} else {
			outcomes = append(outcomes, Outcome{
				Path:   serviceName,
				Action: diff.ActionUpdate,
				Status: StatusApplied,
				Reason: deferReason(ev.hasContentMut),
			})
		}
	}

	return outcomes
}

// restartReason names why a live service was restarted: its own content, or a
// notified EnvironmentFile= it consumes. The content wording is unchanged from
// the pre-graph pipeline.
func restartReason(contentMut bool) string {
	if contentMut {
		return "restart"
	}
	return "restart (EnvironmentFile= changed)"
}

// deferReason names why an inactive service was left for next start.
func deferReason(contentMut bool) string {
	if contentMut {
		return "content updated, inactive — change takes effect on next start"
	}
	return "environment changed, inactive — change takes effect on next start"
}

// reconcileQuadletState drives a quadlet's *generated* .service. Unlike units,
// generated services cannot be enabled/disabled (systemd rejects it), so there
// is no enablement reconciliation: magus starts the service on first creation
// (boot persistence is the generator's job, from the quadlet's [Install]) and
// restarts it if active when the source content changes.
func reconcileQuadletState(serviceName string, ev *unitEvents, notified bool, sd systemd.Manager) []Outcome {
	if ev.bodyDeleted {
		return nil // stop happened when the delete node ran
	}
	var outcomes []Outcome

	if ev.bodyCreated {
		// First materialization: start (NOT enable — it's a generated unit). A
		// fresh start already reads the current EnvironmentFile=, so notify is
		// subsumed here.
		err := sd.Start(serviceName)
		outcomes = append(outcomes, unitOutcome(serviceName, "start", err))
		return outcomes
	}

	if ev.hasContentMut || notified {
		status, _ := sd.Show(serviceName)
		if status.IsActive() {
			outcomes = append(outcomes, unitOutcome(serviceName, restartReason(ev.hasContentMut), sd.Restart(serviceName)))
		} else {
			outcomes = append(outcomes, Outcome{
				Path:   serviceName,
				Action: diff.ActionUpdate,
				Status: StatusApplied,
				Reason: deferReason(ev.hasContentMut),
			})
		}
	}
	return outcomes
}

func unitOutcome(unit, op string, err error) Outcome {
	oc := Outcome{Path: unit, Action: diff.ActionUpdate, Reason: op}
	if err != nil {
		oc.Status = StatusErrored
		oc.Err = err
	} else {
		oc.Status = StatusApplied
	}
	return oc
}
