package policy

import (
	"fmt"

	"github.com/lazypower/magus-cli/internal/ir"
)

// Violation is a single policy-vs-IR conflict reported by Check. Each
// violation is independent; magus collects all violations before halting,
// so the operator sees the full picture rather than one error at a time.
type Violation struct {
	// Resource identifies the offending IR element ("file:/path" or
	// "unit:foo.service") so output groups cleanly.
	Resource string
	// Reason is a single-line explanation suitable for `error: <reason>`
	// surfacing.
	Reason string
}

func (v Violation) String() string {
	return v.Resource + ": " + v.Reason
}

// Check validates ir against p. The slice is empty when ir is fully permitted.
//
// Check enforces the hard rules from the spec's Policy section: path allowlist,
// unit namespace, deny lists, mode caps, and reserved-state-path protection. It
// does not touch the filesystem or check on-disk state — that's the diff stage
// (which also applies symlink-resolved containment).
//
// extraReserved lists additional reserved paths beyond the built-in magus state
// files — callers pass the configured --manifest/--status paths so an IR can't
// declare magus's own ledger even when it's been relocated.
func Check(p *Policy, in *ir.IR, extraReserved ...string) []Violation {
	var v []Violation

	for _, f := range in.Files {
		if reason := p.DenyPathReason(f.Path); reason != "" {
			v = append(v, Violation{Resource: "file:" + f.Path, Reason: reason})
		}
		if reason := ReservedReason(f.Path, extraReserved...); reason != "" {
			v = append(v, Violation{Resource: "file:" + f.Path, Reason: reason})
		}
		if escalated := modeEscalation(f.Mode); escalated != "" {
			v = append(v, Violation{Resource: "file:" + f.Path, Reason: escalated})
		}
	}

	for _, d := range in.Directories {
		if reason := p.DenyPathReason(d.Path); reason != "" {
			v = append(v, Violation{Resource: "dir:" + d.Path, Reason: reason})
		}
		if reason := ReservedReason(d.Path, extraReserved...); reason != "" {
			v = append(v, Violation{Resource: "dir:" + d.Path, Reason: reason})
		}
		if escalated := modeEscalation(d.Mode); escalated != "" {
			v = append(v, Violation{Resource: "dir:" + d.Path, Reason: escalated})
		}
	}

	for _, q := range in.Quadlets {
		// Quadlet SOURCE path: same path authority as any file (file_roots,
		// deny.paths, reserved, mode caps).
		if reason := p.DenyPathReason(q.Path); reason != "" {
			v = append(v, Violation{Resource: "quadlet:" + q.Path, Reason: reason})
		}
		if reason := ReservedReason(q.Path, extraReserved...); reason != "" {
			v = append(v, Violation{Resource: "quadlet:" + q.Path, Reason: reason})
		}
		if escalated := modeEscalation(q.Mode); escalated != "" {
			v = append(v, Violation{Resource: "quadlet:" + q.Path, Reason: escalated})
		}
		// Quadlet GENERATED service: deny.units only (not unit_patterns), so a
		// quadlet can't materialize a denied service (e.g. core-reconcile.*).
		svc, err := ir.QuadletGeneratedService(q.Name)
		if err != nil {
			v = append(v, Violation{Resource: "quadlet:" + q.Path, Reason: err.Error()})
		} else if reason := p.DenyServiceReason(svc); reason != "" {
			v = append(v, Violation{Resource: "quadlet:" + q.Path, Reason: reason})
		}
	}

	for _, u := range in.Units {
		if reason := p.DenyUnitReason(u.Name); reason != "" {
			v = append(v, Violation{
				Resource: "unit:" + u.Name,
				Reason:   reason,
			})
		}
		for _, di := range u.DropIns {
			// Drop-in precedence rule: all magus drop-ins must be 10-magus.conf
			// so they sort predictably and are identifiable on disk.
			if di.Name != "10-magus.conf" {
				v = append(v, Violation{
					Resource: fmt.Sprintf("unit:%s/%s", u.Name, di.Name),
					Reason:   `drop-in must be named "10-magus.conf" (drop-in precedence rule)`,
				})
			}
		}
	}

	// Principals (passwd.users/groups): the manage_users boundary, deterministic
	// uids, the privileged-group gate, and v1-deferred secret fields.
	v = append(v, p.checkPrincipals(in)...)

	return v
}

// modeEscalation enforces "no privilege escalation" — setuid and setgid are
// off-limits — and rejects any mode magus can't faithfully reconcile.
//
// The sticky bit is rejected too: magus manages the standard 0o777 permission
// bits only (hostfs.Stat reports Mode().Perm(), and os.Chmod ignores the raw
// 0o1000 bit — it's ModeSticky it honors, a different flag). A declared 0o1755
// would therefore never converge: declared 0o1755 vs observed 0o755 flaps to
// ActionUpdate on every apply forever. Rejecting it at load turns a silent
// infinite flap into a clear "not supported" (D12). The classic sticky /tmp
// mode 0o1777 is already rejected below for being world-writable.
func modeEscalation(mode uint32) string {
	if mode&0o4000 != 0 {
		return fmt.Sprintf("mode %#o: setuid bit not permitted", mode)
	}
	if mode&0o2000 != 0 {
		return fmt.Sprintf("mode %#o: setgid bit not permitted", mode)
	}
	if mode&0o1000 != 0 {
		return fmt.Sprintf("mode %#o: sticky bit not supported (magus manages 0o777 permission bits only)", mode)
	}
	if mode&0o0002 != 0 {
		return fmt.Sprintf("mode %#o: world-writable not permitted", mode)
	}
	return ""
}
