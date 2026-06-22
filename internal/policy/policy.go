// Package policy loads and enforces /etc/magus/policy.yaml.
//
// Policy is the pre-flight authority boundary: it gates what magus may
// attempt at all, before any diff or apply runs. See docs/spec-reconciler.md
// "Policy" section for the full contract.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where magus looks for the policy file when no override is
// passed. The spec requires this exact location.
const DefaultPath = "/etc/magus/policy.yaml"

// Policy is the parsed contents of policy.yaml.
type Policy struct {
	Version      int      `yaml:"version"`
	FileRoots    []string `yaml:"file_roots"`
	UnitPatterns []string `yaml:"unit_patterns"`
	Deny         Deny     `yaml:"deny"`
}

// Deny lists paths and unit patterns that are off-limits even when they fall
// inside FileRoots / UnitPatterns. Deny is the explicit "never touch this"
// override.
type Deny struct {
	Paths []string `yaml:"paths"`
	Units []string `yaml:"units"`
}

// Load reads and parses the policy at path. A missing file is an error —
// magus refuses to run without an explicit policy.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("invalid policy %s: %w", path, err)
	}
	return &p, nil
}

// validate checks that the policy itself is well-formed. Bad input here is an
// input-bad case — apply halts before any reconciliation runs.
func (p *Policy) validate() error {
	if p.Version != 1 {
		return fmt.Errorf("version: want 1, got %d", p.Version)
	}
	if len(p.FileRoots) == 0 {
		return fmt.Errorf("file_roots: at least one root required")
	}
	for _, r := range p.FileRoots {
		if !filepath.IsAbs(r) {
			return fmt.Errorf("file_roots: %q is not absolute", r)
		}
	}
	for _, d := range p.Deny.Paths {
		if !filepath.IsAbs(strings.TrimSuffix(d, "/*")) {
			return fmt.Errorf("deny.paths: %q is not absolute", d)
		}
	}
	return nil
}

// AllowsPath reports whether path is permitted to be written.
//
// A path is allowed when it falls under at least one file_root and is not
// matched by any deny rule. Symlinks are not resolved here — callers that
// need symlink-resolved checks should pass a resolved path.
func (p *Policy) AllowsPath(path string) bool {
	if !p.underFileRoots(path) {
		return false
	}
	for _, d := range p.Deny.Paths {
		if pathMatches(d, path) {
			return false
		}
	}
	return true
}

// AllowsUnit reports whether unit is permitted to be managed.
func (p *Policy) AllowsUnit(unit string) bool {
	matched := false
	for _, pat := range p.UnitPatterns {
		if globMatch(pat, unit) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, d := range p.Deny.Units {
		if globMatch(d, unit) {
			return false
		}
	}
	return true
}

// DenyPathReason returns the deny rule that blocks path, or "" if not denied.
// Useful for generating actionable error messages.
func (p *Policy) DenyPathReason(path string) string {
	if !p.underFileRoots(path) {
		return "outside file_roots"
	}
	for _, d := range p.Deny.Paths {
		if pathMatches(d, path) {
			return fmt.Sprintf("denied by policy (rule: %s)", d)
		}
	}
	return ""
}

// reservedStatePaths are magus's own state files. The IR must never declare
// them even though they live inside a file_root (/var/lib/magus is a normal
// root): letting an IR manage manifest.json/status.json would let magus clobber
// its own ownership ledger outside the manifest contract.
var reservedStatePaths = []string{
	"/var/lib/magus/manifest.json",
	"/var/lib/magus/status.json",
}

// ReservedReason returns a non-empty reason if path is one of magus's reserved
// state files — the built-in set plus any extra paths passed in (typically the
// configured --manifest/--status/--policy overrides), AND their ".magus.tmp"
// write-staging siblings. The tmp siblings must be reserved too: otherwise an IR
// could pre-create one with an attacker-chosen owner/mode that the atomic
// tmp+rename would then carry onto the real state file. Comparison is on the
// cleaned path.
func ReservedReason(path string, extra ...string) string {
	clean := filepath.Clean(path)
	for _, r := range append(reservedStatePaths, extra...) {
		rc := filepath.Clean(r)
		if clean == rc || clean == rc+".magus.tmp" {
			return "reserved magus state path (cannot be declared in the IR)"
		}
	}
	return ""
}

// DenyServiceReason returns why a systemd service name is denied, or "" if it
// is permitted. Unlike DenyUnitReason this checks ONLY the deny.units list and
// does NOT require a unit_patterns match — it is for quadlet GENERATED services
// (e.g. ollama.service from ollama.container), which are a side effect of a
// file under file_roots, not a directly-declared unit. Requiring them to match
// unit_patterns would reject every quadlet under a drop-in-only policy.
func (p *Policy) DenyServiceReason(name string) string {
	for _, d := range p.Deny.Units {
		if globMatch(d, name) {
			return fmt.Sprintf("generated service denied by policy (rule: %s)", d)
		}
	}
	return ""
}

// DenyUnitReason returns why unit is denied, or "" if it's allowed.
func (p *Policy) DenyUnitReason(unit string) string {
	matched := false
	for _, pat := range p.UnitPatterns {
		if globMatch(pat, unit) {
			matched = true
			break
		}
	}
	if !matched {
		return "does not match unit_patterns"
	}
	for _, d := range p.Deny.Units {
		if globMatch(d, unit) {
			return fmt.Sprintf("denied by policy (rule: %s)", d)
		}
	}
	return ""
}

func (p *Policy) underFileRoots(path string) bool {
	clean := filepath.Clean(path)
	for _, r := range p.FileRoots {
		root := filepath.Clean(r)
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// pathMatches handles deny-path entries, which may end in "/*" to match any
// child path. Otherwise it's an exact match.
func pathMatches(rule, path string) bool {
	if strings.HasSuffix(rule, "/*") {
		prefix := strings.TrimSuffix(rule, "/*")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	return rule == path
}

// globMatch is a minimal glob: '*' matches any run of characters. Sufficient
// for unit patterns like "magus-*" and "sshd.*".
func globMatch(pattern, s string) bool {
	matched, err := filepath.Match(pattern, s)
	if err != nil {
		return false
	}
	return matched
}
