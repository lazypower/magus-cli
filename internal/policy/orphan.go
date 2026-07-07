package policy

import (
	"path/filepath"
	"sort"
	"time"

	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/manifest"
)

// OrphanDenied transitions every actively-owned manifest entry whose path the
// policy now denies (an explicit deny rule, or having fallen outside
// file_roots) into the orphaned state. This is the manifest↔policy contention
// rule from the spec: when a new policy revokes authority over a path magus
// owns, magus must STOP reconciling it — and crucially must NOT delete it on the
// next manifest sweep merely because it's no longer declared. Orphaning is
// sticky (audit-retained, excluded from diff/apply, warned every run) and is
// cleared only by `magus reclaim`.
//
// It returns the paths it transitioned, for logging. Callers persist the
// manifest (apply) or discard it (plan is read-only) as appropriate. Run this
// before diff.Compute so the now-orphaned entries surface as [orphaned] rows.
func OrphanDenied(p *Policy, m *manifest.Manifest, now time.Time) []string {
	var orphaned []string
	for path, r := range m.Resources {
		if r.State != manifest.StateActive {
			continue
		}
		if reason := deniedReason(p, path, r.Kind); reason != "" {
			m.Orphan(path, "policy deny: "+reason, now)
			orphaned = append(orphaned, path)
		}
	}
	// Sort so the warnings emitted from this list are stable run-to-run (the
	// map iteration above is otherwise nondeterministic — D9).
	sort.Strings(orphaned)
	return orphaned
}

// deniedReason reports why the policy no longer permits an owned resource, by
// kind. Units are governed by NAME everywhere (unit_patterns + deny.units), not
// by path: their bodies live at a fixed /etc/systemd/system location that is an
// implementation detail, not something the operator lists in file_roots.
// Checking the path here too would orphan a unit that Check happily created by
// name under a policy whose file_roots omit the systemd dir (D7) — one authority
// per resource kind. Quadlets legitimately have both authorities: the source
// file is path-governed (under file_roots) and the generated service is
// name-governed (deny.units), so both are consulted for them.
func deniedReason(p *Policy, path string, kind manifest.Kind) string {
	switch kind {
	case manifest.KindUnit:
		return p.DenyUnitReason(ir.UnitNameFromPath(path))
	case manifest.KindQuadlet:
		if r := p.DenyPathReason(path); r != "" {
			return r
		}
		svc, err := ir.QuadletGeneratedService(filepath.Base(path))
		if err != nil {
			return "" // unknown quadlet type: path authority already checked
		}
		return p.DenyServiceReason(svc)
	default:
		return p.DenyPathReason(path)
	}
}
