package principal

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lazypower/magus-cli/internal/ir"
)

// Rootless capability is *provisioned, not declared* (ADR-0003): magus derives
// subuid/subgid and linger from a single fact — this principal owns rootless
// workloads. The operator declares the principal and its user quadlets; the
// prerequisites follow.

// Subordinate-id defaults, matching shadow-utils' login.defs (SUB_UID_MIN /
// SUB_UID_COUNT). A per-principal range is 65536 ids wide, allocated from
// 100000 up, so ranges never collide with the real uid space or each other.
const (
	subIDMin   = 100000
	subIDCount = 65536
)

// RootlessOwners returns the managed principals that own at least one
// user-scoped workload — the principals for which magus provisions subuid +
// linger. Derived purely from path-scoped ownership (ir.Quadlet.Owner), gated to
// the manage_users allowlist, sorted and deduped for a deterministic plan.
func RootlessOwners(desired *ir.IR, g Gate) []string {
	seen := map[string]bool{}
	for _, q := range desired.Quadlets {
		if q.Scope != ir.ScopeUser || q.Owner == "" {
			continue
		}
		if !g.Manages(q.Owner) {
			continue // an unmanaged owner is Ignition's concern, not magus's
		}
		seen[q.Owner] = true
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// diffRootless produces the subuid + linger actions for every managed rootless
// owner: a create (provision) when the prerequisite is absent, an adopt (present,
// no write) when it already holds. Ordered subuid-before-linger, and the caller
// appends these after the user actions so the owner exists first — the spine
// principal ⊳ subuid ⊳ linger.
func diffRootless(desired *ir.IR, r Reader, g Gate) ([]PrincipalAction, error) {
	var acts []PrincipalAction
	for _, name := range RootlessOwners(desired, g) {
		hasSubid, err := r.HasSubid(name)
		if err != nil {
			return nil, fmt.Errorf("check subuid %s: %w", name, err)
		}
		acts = append(acts, provisionAction(KindSubid, name, hasSubid,
			"provision subordinate uid/gid range", "subuid range present"))

		lingering, err := r.Linger(name)
		if err != nil {
			return nil, fmt.Errorf("check linger %s: %w", name, err)
		}
		acts = append(acts, provisionAction(KindLinger, name, lingering,
			"enable linger (user manager runs at boot)", "linger enabled"))
	}
	return acts, nil
}

// provisionAction renders one rootless-prerequisite row: adopt when present,
// create otherwise. Conflict never applies — these are magus-owned, additive,
// idempotent provisions on a principal magus already manages.
func provisionAction(kind Kind, name string, present bool, createReason, adoptReason string) PrincipalAction {
	a := PrincipalAction{Kind: kind, Name: name}
	if present {
		a.Action, a.Reason = ActionAdopt, adoptReason
	} else {
		a.Action, a.Reason = ActionCreate, createReason
	}
	return a
}

// subRange is a half-open [start, start+count) subordinate-id range.
type subRange struct {
	start int
	count int
}

// nextFreeSubStart returns the lowest start >= min that lies above every
// allocated range — max(min, highest existing end). Packing dense from the
// bottom matches shadow-utils' own auto-allocation, so magus-provisioned ranges
// interleave cleanly with useradd-provisioned ones and never overlap.
func nextFreeSubStart(used []subRange, min int) int {
	start := min
	for _, r := range used {
		if end := r.start + r.count; end > start {
			start = end
		}
	}
	return start
}

// parseSubidFile parses /etc/subuid or /etc/subgid (name:start:count per line)
// into the allocated ranges, ignoring the owner names — only the numeric extents
// matter for picking a free range. Malformed lines are skipped, not fatal: these
// shared registries may carry entries from other tools, and a best-effort read
// that packs above whatever it *can* parse is safer than refusing to provision.
func parseSubidFile(data string) []subRange {
	var out []subRange
	for _, line := range strings.Split(data, "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) != 3 {
			continue
		}
		start, err1 := strconv.Atoi(f[1])
		count, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, subRange{start: start, count: count})
	}
	return out
}
