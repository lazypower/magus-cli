// Package diff joins IR ∪ manifest ∪ disk and computes the per-resource
// action magus should take. The join is the central decision point of the
// reconciler — see docs/spec-reconciler.md "Diff model".
package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"gitea.wabash.place/lab/magus-cli/internal/hostfs"
	"gitea.wabash.place/lab/magus-cli/internal/ir"
	"gitea.wabash.place/lab/magus-cli/internal/manifest"
	"gitea.wabash.place/lab/magus-cli/internal/policy"
)

// Action is the per-resource verb the planner picks.
type Action string

const (
	ActionCreate   Action = "create"
	ActionUpdate   Action = "update"
	ActionAdopt    Action = "adopt"
	ActionDelete   Action = "delete"
	ActionSkip     Action = "skip"
	ActionConflict Action = "conflict"
	ActionOrphaned Action = "orphaned"
	ActionCleanup  Action = "cleanup"
)

// Kind identifies what type of resource this action targets.
type Kind string

const (
	KindFile      Kind = "file"
	KindDirectory Kind = "directory"
	KindUnit      Kind = "unit"
	KindQuadlet   Kind = "quadlet"
)

// ResourceAction is one row of the plan. Hashes and modes are populated when
// they're useful for explaining the action — empty otherwise. UnitName is set
// only for KindUnit actions so apply can bucket drop-ins with their parent
// unit for daemon-reload + restart semantics.
type ResourceAction struct {
	Path       string
	Kind       Kind
	UnitName   string // populated only for KindUnit actions
	Action     Action
	Reason     string
	OnDiskHash string
	IRHash     string
	OnDiskMode uint32
	IRMode     uint32
}

// Plan is the full set of actions for one diff. Counts() summarizes for the
// CLI footer.
type Plan struct {
	Actions []ResourceAction
}

// HasChanges reports whether anything other than skips/cleanup would run.
// Used to pick exit codes (0 vs 2).
func (p *Plan) HasChanges() bool {
	for _, a := range p.Actions {
		switch a.Action {
		case ActionCreate, ActionUpdate, ActionAdopt, ActionDelete, ActionConflict, ActionOrphaned:
			return true
		}
	}
	return false
}

// HasConflicts reports whether any resource is in conflict or orphaned —
// both states block apply progress for the affected resource.
func (p *Plan) HasConflicts() bool {
	for _, a := range p.Actions {
		if a.Action == ActionConflict || a.Action == ActionOrphaned {
			return true
		}
	}
	return false
}

// declared is the desired-state record for one path: what the IR says should
// be on disk, plus how to hash it for equivalence (raw bytes for files, post-
// canonicalization bytes for units).
type declaredResource struct {
	Path     string
	Mode     uint32
	UID      *int
	GID      *int
	Contents []byte
	Kind     Kind
	UnitName string // "" for KindFile
}

// hash returns the equivalence hash of this resource's IR-declared content.
// Units canonicalize before hashing so behavior-preserving formatting changes
// in the unit file do not register as drift.
func (d declaredResource) hash() string {
	return HashContent(d.Contents, d.Kind)
}

// HashContent is the cross-package canonical hash. Units and quadlets share
// the same INI-shaped canonicalization (drop blanks/comments, normalize
// equals spacing, preserve order); files hash raw bytes.
func HashContent(b []byte, kind Kind) string {
	if kind == KindUnit || kind == KindQuadlet {
		b = []byte(CanonicalizeUnit(string(b)))
	}
	return hashBytes(b)
}

// Compute joins the three inputs and produces a plan. fsys reads disk state;
// in normal operation pass hostfs.OS(). This is the policy-unaware entry point
// (no symlink containment) — production callers use ComputeWithPolicy.
func Compute(in *ir.IR, m *manifest.Manifest, fsys hostfs.Reader) (*Plan, error) {
	return ComputeWithPolicy(nil, in, m, fsys)
}

// ComputeWithPolicy is Compute plus symlink-resolved containment: for path-
// governed resources (files, directories, quadlets) whose declared path is
// lexically in-bounds but resolves — through a symlinked ancestor — to a
// location the policy denies, the action is downgraded to a Conflict so apply
// skips it rather than writing outside magus's authority. Requires fsys to
// implement hostfs.Resolver; otherwise containment is a no-op (test fakes).
// p may be nil to skip containment entirely.
func ComputeWithPolicy(p *policy.Policy, in *ir.IR, m *manifest.Manifest, fsys hostfs.Reader) (*Plan, error) {
	plan, err := computeCore(in, m, fsys)
	if err != nil {
		return nil, err
	}
	if p != nil {
		applyContainment(p, plan, fsys)
	}
	return plan, nil
}

// ContainmentEscape reports whether mutating path would land outside the
// policy's authority because a symlink in its resolved ancestry redirects it.
// It returns the resolved path and a non-empty reason when the mutation
// escapes — including a fail-closed reason if resolution itself fails. An empty
// reason means the mutation is safe. Used by both the plan-time downgrade
// (applyContainment) and the apply-time re-check (which closes the plan→apply
// TOCTOU window).
func ContainmentEscape(p *policy.Policy, r hostfs.Resolver, path string) (resolved, reason string) {
	resolved, err := r.ResolvePath(path)
	if err != nil {
		return "", "path resolution failed (fail-closed): " + err.Error()
	}
	if resolved == filepath.Clean(path) {
		return resolved, "" // no symlink rewrote the path
	}
	if dr := p.DenyPathReason(resolved); dr != "" {
		return resolved, fmt.Sprintf("resolves outside authority via symlink → %s (%s)", resolved, dr)
	}
	return resolved, ""
}

// applyContainment downgrades create/update/adopt/DELETE actions whose resolved
// path escapes the policy to a Conflict (skipped). Scoped to path-governed
// kinds (file/dir/quadlet); units are governed by unit_patterns (name), not
// file_roots. Deletes are included because unlink follows a symlinked PARENT —
// a redirected delete is data loss outside authority.
func applyContainment(p *policy.Policy, plan *Plan, fsys hostfs.Reader) {
	r, ok := fsys.(hostfs.Resolver)
	if !ok {
		return
	}
	for i := range plan.Actions {
		a := &plan.Actions[i]
		switch a.Kind {
		case KindFile, KindDirectory, KindQuadlet:
		default:
			continue
		}
		switch a.Action {
		case ActionCreate, ActionUpdate, ActionAdopt, ActionDelete:
		default:
			continue
		}
		if _, reason := ContainmentEscape(p, r, a.Path); reason != "" {
			a.Action = ActionConflict
			a.Reason = reason
		}
	}
}

// computeCore joins the three inputs and produces a plan without policy-aware
// containment. fsys reads disk state.
func computeCore(in *ir.IR, m *manifest.Manifest, fsys hostfs.Reader) (*Plan, error) {
	plan := &Plan{}
	declared := map[string]bool{}

	for _, f := range in.Files {
		declared[f.Path] = true
		ra, err := diffDeclared(declaredResource{
			Path:     f.Path,
			Mode:     f.Mode,
			UID:      f.UID,
			GID:      f.GID,
			Contents: f.Contents,
			Kind:     KindFile,
		}, m, fsys)
		if err != nil {
			return nil, err
		}
		plan.Actions = append(plan.Actions, ra)
	}

	for _, u := range in.Units {
		// The unit body file at /etc/systemd/system/<name>. Only emitted
		// when the IR provides body content; a Unit with only drop-ins
		// extends a system-shipped unit and magus does not own the body.
		if len(u.Contents) > 0 {
			path := UnitPath(u.Name)
			declared[path] = true
			ra, err := diffDeclared(declaredResource{
				Path:     path,
				Mode:     0o644,
				Contents: []byte(u.Contents),
				Kind:     KindUnit,
				UnitName: u.Name,
			}, m, fsys)
			if err != nil {
				return nil, err
			}
			plan.Actions = append(plan.Actions, ra)
		}
		for _, di := range u.DropIns {
			path := DropInPath(u.Name, di.Name)
			declared[path] = true
			ra, err := diffDeclared(declaredResource{
				Path:     path,
				Mode:     0o644,
				Contents: []byte(di.Contents),
				Kind:     KindUnit,
				UnitName: u.Name,
			}, m, fsys)
			if err != nil {
				return nil, err
			}
			plan.Actions = append(plan.Actions, ra)
		}
	}

	for _, d := range in.Directories {
		declared[d.Path] = true
		ra, err := diffDirectory(d, m, fsys)
		if err != nil {
			return nil, err
		}
		plan.Actions = append(plan.Actions, ra)
	}

	for _, q := range in.Quadlets {
		declared[q.Path] = true
		ra, err := diffDeclared(declaredResource{
			Path:     q.Path,
			Mode:     q.Mode,
			UID:      q.UID,
			GID:      q.GID,
			Contents: q.Contents,
			Kind:     KindQuadlet,
			UnitName: q.Name,
		}, m, fsys)
		if err != nil {
			return nil, err
		}
		plan.Actions = append(plan.Actions, ra)
	}

	// Manifest sweep: anything magus owns (or has orphaned) that isn't in
	// the IR needs an action — delete, stale-clean, or orphaned-skip.
	for path, entry := range m.Resources {
		if declared[path] {
			continue
		}
		ra, err := diffOrphan(path, entry, fsys)
		if err != nil {
			return nil, err
		}
		plan.Actions = append(plan.Actions, ra)
	}

	return plan, nil
}

// diffDirectory diffs an IR-declared directory. Equivalence is metadata-only:
// existence + mode + ownership. Magus does not recurse into directory
// contents and never deletes directories — even on IR omission, per spec.
func diffDirectory(d ir.Directory, m *manifest.Manifest, fsys hostfs.Reader) (ResourceAction, error) {
	ra := ResourceAction{
		Path:   d.Path,
		Kind:   KindDirectory,
		IRMode: d.Mode,
	}

	if entry, ok := m.Get(d.Path); ok && entry.State == manifest.StateOrphaned {
		ra.Action = ActionOrphaned
		ra.Reason = "orphaned: " + entry.OrphanedReason
		return ra, nil
	}

	st, err := fsys.Stat(d.Path)
	if err != nil {
		return ra, fmt.Errorf("stat %s: %w", d.Path, err)
	}

	if !st.Exists {
		ra.Action = ActionCreate
		return ra, nil
	}

	ra.OnDiskMode = st.Mode
	metaMatch := st.Mode == d.Mode &&
		(d.UID == nil || st.UID == *d.UID) &&
		(d.GID == nil || st.GID == *d.GID)
	owned := m.Owns(d.Path)

	switch {
	case metaMatch && owned:
		ra.Action = ActionSkip
		ra.Reason = "unchanged"
	case metaMatch && !owned:
		ra.Action = ActionAdopt
		ra.Reason = "matches IR, claiming ownership"
	case owned:
		ra.Action = ActionUpdate
		ra.Reason = explainDirDiff(st, d)
	default:
		ra.Action = ActionConflict
		ra.Reason = "exists, " + explainDirDiff(st, d) + ", not in manifest"
	}
	return ra, nil
}

func explainDirDiff(st hostfs.FileInfo, d ir.Directory) string {
	switch {
	case st.Mode != d.Mode:
		return fmt.Sprintf("mode %#o → %#o", st.Mode, d.Mode)
	case d.UID != nil && st.UID != *d.UID, d.GID != nil && st.GID != *d.GID:
		return fmt.Sprintf("ownership %d:%d → %s", st.UID, st.GID, ownershipDesc(d.UID, d.GID))
	default:
		return "differs"
	}
}

func diffDeclared(d declaredResource, m *manifest.Manifest, fsys hostfs.Reader) (ResourceAction, error) {
	ra := ResourceAction{
		Path:     d.Path,
		Kind:     d.Kind,
		UnitName: d.UnitName,
		IRHash:   d.hash(),
		IRMode:   d.Mode,
	}

	// Orphan check first: a manifest orphan dominates everything else.
	if entry, ok := m.Get(d.Path); ok && entry.State == manifest.StateOrphaned {
		ra.Action = ActionOrphaned
		ra.Reason = "orphaned: " + entry.OrphanedReason
		return ra, nil
	}

	st, err := fsys.Stat(d.Path)
	if err != nil {
		return ra, fmt.Errorf("stat %s: %w", d.Path, err)
	}

	if !st.Exists {
		ra.Action = ActionCreate
		return ra, nil
	}

	ra.OnDiskMode = st.Mode

	body, err := fsys.ReadFile(d.Path)
	if err != nil {
		return ra, fmt.Errorf("read %s: %w", d.Path, err)
	}
	ra.OnDiskHash = HashContent(body, d.Kind)

	contentMatch := ra.OnDiskHash == ra.IRHash
	metaMatch := st.Mode == d.Mode &&
		(d.UID == nil || st.UID == *d.UID) &&
		(d.GID == nil || st.GID == *d.GID)
	owned := m.Owns(d.Path)

	switch {
	case contentMatch && metaMatch && owned:
		ra.Action = ActionSkip
		ra.Reason = "unchanged"
	case contentMatch && metaMatch && !owned:
		ra.Action = ActionAdopt
		ra.Reason = "matches IR, claiming ownership"
	case owned:
		ra.Action = ActionUpdate
		ra.Reason = explainDiff(contentMatch, metaMatch, st, d)
	default:
		ra.Action = ActionConflict
		ra.Reason = "exists, " + explainDiff(contentMatch, metaMatch, st, d) + ", not in manifest"
	}
	return ra, nil
}

func diffOrphan(path string, entry manifest.Resource, fsys hostfs.Reader) (ResourceAction, error) {
	ra := ResourceAction{Path: path, Kind: kindFromManifest(entry.Kind)}
	if ra.Kind == KindUnit {
		ra.UnitName = UnitNameFromPath(path)
	}
	if ra.Kind == KindQuadlet {
		// For quadlets, UnitName is the source filename (e.g.,
		// "ollama.container"). Apply uses it to compute the generated
		// .service name for stop-before-unlink.
		ra.UnitName = filepath.Base(path)
	}

	st, err := fsys.Stat(path)
	if err != nil {
		return ra, fmt.Errorf("stat %s: %w", path, err)
	}

	if entry.State == manifest.StateOrphaned {
		// Orphans age out: if the underlying file is gone (removed out of band),
		// drop the orphan entry so the manifest doesn't accumulate forever.
		// While the file exists, the orphan is held (audit) and skip+warned.
		if !st.Exists {
			ra.Action = ActionCleanup
			ra.Reason = "orphaned entry without on-disk file — aged out"
			return ra, nil
		}
		ra.Action = ActionOrphaned
		ra.Reason = "orphaned: " + entry.OrphanedReason
		return ra, nil
	}

	// Active manifest entry, no IR declaration → delete, stale-clean, or
	// (for directories) skip-with-reason since v1 does not delete dirs.
	if !st.Exists {
		ra.Action = ActionCleanup
		ra.Reason = "manifest entry without on-disk file"
		return ra, nil
	}
	if ra.Kind == KindDirectory {
		// Spec: directories are never removed even on IR omission. They
		// may hold user data magus didn't track. The manifest entry stays
		// for audit; reconciliation does not.
		ra.Action = ActionSkip
		ra.Reason = "directory removed from IR; v1 does not delete directories"
		return ra, nil
	}
	ra.Action = ActionDelete
	ra.Reason = "owned, no longer declared"
	return ra, nil
}

// kindFromManifest converts a manifest-tracked Kind to the diff Kind. The
// manifest stores its own Kind constants for forwards/backwards compat;
// translating here keeps the manifest package independent of diff.
func kindFromManifest(k manifest.Kind) Kind {
	switch k {
	case manifest.KindUnit:
		return KindUnit
	case manifest.KindDirectory:
		return KindDirectory
	case manifest.KindQuadlet:
		return KindQuadlet
	default:
		return KindFile
	}
}

// QuadletGeneratedService is the canonical generated-service mapping, kept here
// as a thin alias for existing diff/apply call sites; the implementation lives
// in ir so the policy gate can reuse it without an import cycle.
func QuadletGeneratedService(quadletName string) (string, error) {
	return ir.QuadletGeneratedService(quadletName)
}

// UnitPath is the on-disk location magus owns a unit body at.
func UnitPath(unitName string) string {
	return filepath.Join("/etc/systemd/system", unitName)
}

// DropInPath is the on-disk location magus owns a drop-in at. Drop-ins live
// in <unit>.d/ siblings and are named per the policy precedence rule
// (10-magus.conf only) so they sort predictably.
func DropInPath(unitName, dropInName string) string {
	return filepath.Join("/etc/systemd/system", unitName+".d", dropInName)
}

// UnitNameFromPath is a thin alias; the implementation lives in ir so the
// policy gate can derive unit names without an import cycle.
func UnitNameFromPath(p string) string {
	return ir.UnitNameFromPath(p)
}

// explainDiff produces a short reason string for update/conflict rows.
// Keeps things grep-friendly: "content differs", "mode differs", or both.
func explainDiff(contentMatch, metaMatch bool, st hostfs.FileInfo, d declaredResource) string {
	switch {
	case !contentMatch && !metaMatch:
		return "content and metadata differ"
	case !contentMatch:
		return "content differs"
	case st.Mode != d.Mode:
		return fmt.Sprintf("mode %#o → %#o", st.Mode, d.Mode)
	case d.UID != nil && st.UID != *d.UID, d.GID != nil && st.GID != *d.GID:
		return fmt.Sprintf("ownership %d:%d → %s", st.UID, st.GID, ownershipDesc(d.UID, d.GID))
	default:
		// Should not happen — caller only invokes this when something differs.
		return "differs"
	}
}

func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// ownershipDesc renders an IR-side uid:gid where either may be unspecified
// ("*" means "no change") for explainDiff output.
func ownershipDesc(uid, gid *int) string {
	u := "*"
	if uid != nil {
		u = fmt.Sprintf("%d", *uid)
	}
	g := "*"
	if gid != nil {
		g = fmt.Sprintf("%d", *gid)
	}
	return u + ":" + g
}
