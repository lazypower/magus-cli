package policy

import (
	"strings"
	"testing"

	"github.com/lazypower/magus-cli/internal/ir"
)

// workloadLike mirrors the real core-image workload policy shape: quadlets live
// under /etc/containers/systemd, unit_patterns is drop-in-only, and the
// substrate/secret denies are present.
const workloadLike = `
version: 1
file_roots: ["/etc/containers/systemd", "/etc/core", "/var/lib/magus"]
unit_patterns: ["*.d/10-magus.conf"]
deny:
  paths: ["/etc/core/reconcile.env"]
  units: ["core-reconcile.*", "sshd.*"]
`

func TestCheckQuadletPathOutsideRoots(t *testing.T) {
	p := mustLoad(t, workloadLike)
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Path: "/etc/systemd/system/evil.container", Name: "evil.container"},
	}}
	v := Check(p, in)
	if !hasReason(v, "outside file_roots") {
		t.Errorf("quadlet outside file_roots not rejected: %v", v)
	}
}

func TestCheckQuadletAllowedUnderWorkloadPolicy(t *testing.T) {
	// A normal quadlet whose generated service (ollama.service) does NOT match
	// the drop-in-only unit_patterns must still be ALLOWED — generated services
	// are gated by deny.units only, not unit_patterns.
	p := mustLoad(t, workloadLike)
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Path: "/etc/containers/systemd/ollama.container", Name: "ollama.container", Mode: 0o644},
	}}
	if v := Check(p, in); len(v) != 0 {
		t.Errorf("valid workload quadlet rejected: %v", v)
	}
}

func TestCheckQuadletDeniedGeneratedService(t *testing.T) {
	// A quadlet whose generated service matches a deny.units rule must be
	// rejected even though its path is inside file_roots.
	p := mustLoad(t, workloadLike)
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Path: "/etc/containers/systemd/core-reconcile.container", Name: "core-reconcile.container", Mode: 0o644},
	}}
	v := Check(p, in)
	if !hasReason(v, "generated service denied") {
		t.Errorf("denied generated service not rejected: %v", v)
	}
}

func TestCheckQuadletModeEscalation(t *testing.T) {
	p := mustLoad(t, workloadLike)
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Path: "/etc/containers/systemd/x.container", Name: "x.container", Mode: 0o4755},
	}}
	if v := Check(p, in); !hasReason(v, "setuid") {
		t.Errorf("quadlet setuid not rejected: %v", v)
	}
}

func TestCheckQuadletUnsupportedType(t *testing.T) {
	p := mustLoad(t, workloadLike)
	in := &ir.IR{Quadlets: []ir.Quadlet{
		{Path: "/etc/containers/systemd/x.pod", Name: "x.pod", Mode: 0o644},
	}}
	if v := Check(p, in); !hasReason(v, "unsupported quadlet type") {
		t.Errorf("unsupported quadlet type not rejected: %v", v)
	}
}

func TestCheckReservedStatePaths(t *testing.T) {
	p := mustLoad(t, workloadLike)
	for _, path := range []string{"/var/lib/magus/manifest.json", "/var/lib/magus/status.json"} {
		in := &ir.IR{Files: []ir.File{{Path: path, Mode: 0o644}}}
		v := Check(p, in)
		if !hasReason(v, "reserved magus state path") {
			t.Errorf("reserved path %s not rejected: %v", path, v)
		}
	}
}

func TestCheckReservedTmpSiblings(t *testing.T) {
	// The .magus.tmp write-staging siblings of reserved state files must also be
	// rejected — else an IR could pre-create one with attacker-chosen perms that
	// the atomic rename would carry onto the real state file.
	p := mustLoad(t, workloadLike)
	for _, path := range []string{
		"/var/lib/magus/manifest.json.magus.tmp",
		"/var/lib/magus/status.json.magus.tmp",
	} {
		in := &ir.IR{Files: []ir.File{{Path: path, Mode: 0o644}}}
		if v := Check(p, in); !hasReason(v, "reserved magus state path") {
			t.Errorf("reserved tmp sibling %s not rejected: %v", path, v)
		}
	}
}

func TestCheckReservedExtra(t *testing.T) {
	// A relocated manifest (passed as extraReserved) is also protected.
	p := mustLoad(t, workloadLike)
	in := &ir.IR{Files: []ir.File{{Path: "/etc/core/custom-manifest.json", Mode: 0o644}}}
	if v := Check(p, in, "/etc/core/custom-manifest.json"); !hasReason(v, "reserved magus state path") {
		t.Errorf("relocated manifest not protected: %v", v)
	}
}

func TestDenyServiceReasonIgnoresUnitPatterns(t *testing.T) {
	p := mustLoad(t, workloadLike)
	// Not denied: a generated service that matches no deny rule is permitted,
	// regardless of unit_patterns.
	if r := p.DenyServiceReason("ollama.service"); r != "" {
		t.Errorf("ollama.service should be permitted, got %q", r)
	}
	// Denied: matches a deny.units rule.
	if r := p.DenyServiceReason("core-reconcile.service"); r == "" {
		t.Errorf("core-reconcile.service should be denied")
	}
}

func hasReason(v []Violation, substr string) bool {
	for _, x := range v {
		if strings.Contains(x.Reason, substr) {
			return true
		}
	}
	return false
}
