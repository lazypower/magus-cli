package policy

import (
	"path/filepath"
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
	return orphaned
}

// deniedReason reports why the policy no longer permits an owned resource, by
// kind. Units and quadlets must consult the UNIT/SERVICE deny lists too — not
// just the path — so that a newly deny.units'd unit/quadlet is orphaned (kept)
// rather than deleted by the sweep.
func deniedReason(p *Policy, path string, kind manifest.Kind) string {
	switch kind {
	case manifest.KindUnit:
		if r := p.DenyPathReason(path); r != "" {
			return r
		}
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
