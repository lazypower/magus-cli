package policy

import (
	"time"

	"gitea.wabash.place/lab/magus-cli/internal/manifest"
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
		if reason := p.DenyPathReason(path); reason != "" {
			m.Orphan(path, "policy deny: "+reason, now)
			orphaned = append(orphaned, path)
		}
	}
	return orphaned
}
