package apply

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/systemd"
)

// UserManagerFactory yields the user-scope manager for a principal (name, uid).
// Injected so apply can be driven with a FakeUser in tests; production passes
// systemd.OSUser. A nil factory disables user-workload activation entirely
// (unit-test callers that declare no user quadlets).
type UserManagerFactory func(name string, uid int) systemd.UserManager

// Chowner sets ownership of a path — the bounded chown of a principal's config
// tree. hostfs.Writer satisfies it; nil disables the chown (test callers).
type Chowner interface {
	Chown(path string, uid, gid *int) error
}

// UserWorkloads bundles the inputs to ReconcileUserWorkloads. Blocked and the
// manage_users filtering (done by the caller before this runs) are the security
// gates Codex's review demanded: a workload activates ONLY for a managed
// principal that reconciled cleanly.
type UserWorkloads struct {
	IR      *ir.IR
	Changed map[string]bool   // source paths written this apply (start vs no-op)
	Blocked map[string]string // owner -> reason its principal is not reconciled (conflict/error) → stage, never activate
	Chown   Chowner           // owns the config tree, bounded below the home
	NewUser UserManagerFactory
}

// ReconcileUserWorkloads is the far end of ADR-0003's rootless spine: it
// activates each principal's user-scope quadlets through that principal's user
// manager, after the identity + subuid + linger provisioning (which runs before
// this) and after the quadlet source files have been written to the home.
//
// It is deliberately NOT part of the system apply graph: user services live on a
// different bus, reached over a different transport, gated by a prerequisite
// (the user manager being operational) the system graph cannot see. The honest
// skip lives here instead: when the user manager is not ready, every one of that
// owner's workloads is reported staged-not-activated with the dependency reason —
// never a green that lies.
//
// changed carries the source paths this apply actually wrote (from the system
// apply Result), so an unchanged, already-running workload is a no-op and only a
// changed or not-yet-started one is (re)started — the same idempotence the system
// quadlet path has.
func ReconcileUserWorkloads(w UserWorkloads) []Outcome {
	if w.NewUser == nil {
		return nil
	}
	byOwner := userQuadletsByOwner(w.IR)
	if len(byOwner) == 0 {
		return nil
	}
	uidOf := userUIDs(w.IR)
	homes := userHomes(w.IR)

	var outcomes []Outcome
	for _, owner := range sortedKeys(byOwner) {
		quads := byOwner[owner]

		// #2 — a principal that was refused (privileged-group conflict, uid
		// collision) or whose prerequisites failed does NOT get its workload run.
		// Activating it would hand code execution to the exact identity the gate
		// denied. Stage it with the reason instead.
		if reason, blocked := w.Blocked[owner]; blocked {
			for _, q := range orderQuadlets(quads) {
				outcomes = append(outcomes, userOutcome(q, diff.ActionSkip, StatusSkipped,
					"staged, not activated: owner principal not reconciled ("+reason+")", nil))
			}
			continue
		}

		uid, ok := uidOf[owner]
		if !ok {
			// A user-scoped workload whose owner declares no uid can't be reached
			// (the manager is user@<uid>). Managed principals require a uid at
			// validate, so this is defensive — surface it, don't guess.
			for _, q := range quads {
				outcomes = append(outcomes, userOutcome(q, diff.ActionError, StatusErrored,
					fmt.Sprintf("owner %q has no uid — cannot resolve user@<uid>", owner), nil))
			}
			continue
		}

		// #1 — own the config tree magus created, BOUNDED strictly below the
		// principal's home (never a system dir). A chown failure fails closed:
		// stage the workloads rather than activate over a wrong-owned tree.
		if err := ownConfigTrees(w.Chown, homes[owner], quads, uid); err != nil {
			for _, q := range orderQuadlets(quads) {
				outcomes = append(outcomes, userOutcome(q, diff.ActionSkip, StatusSkipped,
					"staged, not activated: could not own config tree: "+err.Error(), nil))
			}
			continue
		}

		outcomes = append(outcomes, reconcileOwnerWorkloads(quads, w.Changed, w.NewUser(owner, uid))...)
	}
	return outcomes
}

// ownConfigTrees chowns each quadlet's ancestor directories — strictly below the
// principal's home — to the owner uid, so rootless podman owns its config path.
// It is deliberately bounded: it refuses a home outside the user-home roots and
// never touches the home itself or anything above it, so it cannot be turned into
// an ownership-escalation of a system directory (Codex P1 #1). A nil chowner
// (test callers) is a no-op.
func ownConfigTrees(ch Chowner, home string, quads []ir.Quadlet, uid int) error {
	if ch == nil {
		return nil
	}
	for _, q := range quads {
		for _, dir := range configTreeDirs(home, q.Path) {
			if err := ch.Chown(dir, &uid, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// configTreeDirs returns the ancestor directories of quadletPath that lie
// STRICTLY below home, shallowest-first — the .config/... tree magus creates and
// must hand to the principal. Returns nothing (own nothing, fail closed) unless
// home is a plausible user home (/var/home/<u> or /home/<u>) and a strict path
// ancestor of the quadlet. This is the boundary that stops home_dir=/etc from
// turning into a chown of /etc/.config.
func configTreeDirs(home, quadletPath string) []string {
	home = filepath.Clean(home)
	if !underUserHomeRoot(home) || !strictlyUnder(quadletPath, home) {
		return nil
	}
	var dirs []string
	for d := filepath.Dir(quadletPath); len(d) > len(home); d = filepath.Dir(d) {
		if !strictlyUnder(d, home) {
			break
		}
		dirs = append(dirs, d)
	}
	// Reverse to shallowest-first (home-ward) for deterministic, top-down chown.
	for i, j := 0, len(dirs)-1; i < j; i, j = i+1, j-1 {
		dirs[i], dirs[j] = dirs[j], dirs[i]
	}
	return dirs
}

// underUserHomeRoot reports whether home is directly beneath a user-home root
// (/var/home/<name> or /home/<name>) — the only locations a managed rootless
// principal's home may live (also gated at validate). Defense in depth against a
// system-path home reaching the chown.
func underUserHomeRoot(home string) bool {
	for _, root := range []string{"/var/home/", "/home/"} {
		if rest, ok := strings.CutPrefix(home, root); ok && rest != "" && !strings.Contains(rest, "/") {
			return true
		}
	}
	return false
}

// strictlyUnder reports whether path is a proper descendant of dir.
func strictlyUnder(path, dir string) bool {
	return strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// userHomes maps each declared user's name to its home dir.
func userHomes(in *ir.IR) map[string]string {
	out := map[string]string{}
	for _, u := range in.Users {
		if u.HomeDir != "" {
			out[u.Name] = u.HomeDir
		}
	}
	return out
}

// reconcileOwnerWorkloads activates one owner's quadlets through um. When um is
// not ready, all are staged-not-activated (the honest skip). When ready, the
// user generator is reloaded once if any source changed, then services are
// (re)started in dependency order: networks/volumes before the containers that
// reference them.
func reconcileOwnerWorkloads(quads []ir.Quadlet, changed map[string]bool, um systemd.UserManager) []Outcome {
	if ok, reason := um.Ready(); !ok {
		var out []Outcome
		for _, q := range orderQuadlets(quads) {
			out = append(out, userOutcome(q, diff.ActionSkip, StatusSkipped,
				"staged, not activated: "+reason, nil))
		}
		return out
	}

	var out []Outcome
	if anyChanged(quads, changed) {
		if err := um.DaemonReload(); err != nil {
			// A failed user daemon-reload means no source is (re)generated — every
			// workload is staged, not activated, fail-closed.
			for _, q := range orderQuadlets(quads) {
				out = append(out, userOutcome(q, diff.ActionSkip, StatusSkipped,
					"staged, not activated: user daemon-reload failed: "+err.Error(), nil))
			}
			return out
		}
	}

	for _, q := range orderQuadlets(quads) {
		out = append(out, activateOne(q, changed[q.Path], um))
	}
	return out
}

// activateOne (re)starts a single user quadlet's generated service: start when
// inactive, restart when active and its source changed, no-op when active and
// unchanged — mirroring reconcileQuadletState for user scope.
func activateOne(q ir.Quadlet, sourceChanged bool, um systemd.UserManager) Outcome {
	svc, err := diff.QuadletGeneratedService(q.Name)
	if err != nil {
		return userOutcome(q, diff.ActionError, StatusErrored, "", err)
	}
	st, _ := um.Show(svc)
	switch {
	case !st.IsActive():
		if err := um.Start(svc); err != nil {
			return userSvcOutcome(svc, diff.ActionUpdate, StatusErrored, "start", err)
		}
		return userSvcOutcome(svc, diff.ActionUpdate, StatusApplied, "started (user@)", nil)
	case sourceChanged:
		if err := um.Restart(svc); err != nil {
			return userSvcOutcome(svc, diff.ActionUpdate, StatusErrored, "restart", err)
		}
		return userSvcOutcome(svc, diff.ActionUpdate, StatusApplied, "restarted (user@)", nil)
	default:
		return userSvcOutcome(svc, diff.ActionSkip, StatusUnchanged, "already active", nil)
	}
}

// FilterUnmanagedUserQuadlets removes user-scope quadlets whose owner is not in
// manage_users: magus ignores them exactly as it ignores an unmanaged principal,
// so they are never written, planned, or activated (Codex P1 #3 — otherwise a
// quadlet under an unmanaged principal's home would be run as that user,
// bypassing the allowlist). Returns a shallow IR copy with Quadlets filtered;
// a nil gate is a no-op. System quadlets and managed-owner user quadlets are kept.
func FilterUnmanagedUserQuadlets(in *ir.IR, managed func(name string) bool) *ir.IR {
	if managed == nil {
		return in
	}
	kept := make([]ir.Quadlet, 0, len(in.Quadlets))
	for _, q := range in.Quadlets {
		if q.Scope == ir.ScopeUser && q.Owner != "" && !managed(q.Owner) {
			continue // unmanaged owner — Ignition's concern, not magus's
		}
		kept = append(kept, q)
	}
	out := *in
	out.Quadlets = kept
	return &out
}

// HasUserWorkloads reports whether the IR declares any user-scope quadlet — the
// signal that this apply must run the user-workload reconciler (and therefore
// must not early-exit "nothing to apply" purely on a converged file/principal
// plan: a workload can be staged-but-not-activated with everything on disk in
// place).
func HasUserWorkloads(in *ir.IR) bool {
	for _, q := range in.Quadlets {
		if q.Scope == ir.ScopeUser {
			return true
		}
	}
	return false
}

// userQuadletsByOwner groups the IR's user-scope quadlets by owning principal.
func userQuadletsByOwner(in *ir.IR) map[string][]ir.Quadlet {
	out := map[string][]ir.Quadlet{}
	for _, q := range in.Quadlets {
		if q.Scope == ir.ScopeUser && q.Owner != "" {
			out[q.Owner] = append(out[q.Owner], q)
		}
	}
	return out
}

// userUIDs maps each declared user's name to its uid (only the declared ones;
// the rootless spine requires a deterministic uid).
func userUIDs(in *ir.IR) map[string]int {
	out := map[string]int{}
	for _, u := range in.Users {
		if u.UID != nil {
			out[u.Name] = *u.UID
		}
	}
	return out
}

// orderQuadlets sorts an owner's quadlets so networks and volumes precede the
// containers that reference them — the common Network=/Volume= dependency —
// with a stable secondary sort by name for determinism. This covers the
// single-owner reference case; a full reference toposort is deferred (the
// system graph's referenceEdges remain the model for that).
func orderQuadlets(quads []ir.Quadlet) []ir.Quadlet {
	out := append([]ir.Quadlet(nil), quads...)
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := quadletStartRank(out[i].Name), quadletStartRank(out[j].Name)
		if pi != pj {
			return pi < pj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// quadletStartRank orders quadlet types by start dependency: networks and
// volumes (0) before containers (1). Unknown types sort last.
func quadletStartRank(name string) int {
	switch {
	case strings.HasSuffix(name, ".network"), strings.HasSuffix(name, ".volume"):
		return 0
	case strings.HasSuffix(name, ".container"):
		return 1
	default:
		return 2
	}
}

func anyChanged(quads []ir.Quadlet, changed map[string]bool) bool {
	for _, q := range quads {
		if changed[q.Path] {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string][]ir.Quadlet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// userOutcome reports against the quadlet source path (what the operator
// declared); userSvcOutcome reports against the generated service (what ran).
func userOutcome(q ir.Quadlet, action diff.Action, status Status, reason string, err error) Outcome {
	return Outcome{Path: q.Path, Action: action, Status: status, Reason: reason, Err: err}
}

func userSvcOutcome(svc string, action diff.Action, status Status, reason string, err error) Outcome {
	return Outcome{Path: svc, Action: action, Status: status, Reason: reason, Err: err}
}
