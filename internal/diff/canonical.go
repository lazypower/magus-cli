package diff

import "strings"

// UnitValues returns every value assigned to key in a unit/quadlet/drop-in body,
// in file order. It reuses CanonicalizeUnit so there is exactly one opinion about
// unit-file shape: the body is canonicalized (blank/comment lines dropped,
// "k = v" spacing normalized) and then each "key=value" line whose key matches is
// collected. A key may legitimately repeat (EnvironmentFile=, Network=,
// Volume=), so all values are returned.
//
// Matching is case-sensitive and section-agnostic — magus's edge derivation only
// consults keys whose value is a plain path or quadlet name (EnvironmentFile=,
// Network=, Volume=), and those key names are unambiguous across sections.
func UnitValues(contents, key string) []string {
	var out []string
	for line := range strings.SplitSeq(CanonicalizeUnit(contents), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			out = append(out, v)
		}
	}
	return out
}

// CanonicalizeUnit normalizes a systemd unit file or drop-in to its
// behavior-significant form. The output is what diff hashes for equivalence:
// two unit files that canonicalize to the same bytes have the same effect on
// systemd, even if they differ in whitespace or comments.
//
// The 7 rules, from docs/spec-reconciler.md "Equivalence":
//  1. Drop blank lines.
//  2. Drop comment lines (first non-whitespace character is # or ;).
//  3. Trim trailing whitespace from each line.
//  4. Normalize key=value spacing: collapse to "key=value" (no whitespace
//     around =).
//  5. Preserve section headers exactly — case-sensitive, brackets included.
//  6. Preserve key order within each section.
//  7. Preserve section order across the file.
//
// Rules 5–7 are "preserve, don't reorder" — order is behavior-significant in
// systemd (ExecStart*, Environment, etc.), so canonicalization is intentionally
// limited to dropping noise rather than rearranging structure.
func CanonicalizeUnit(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		// Rule 3: trim trailing whitespace first so "key = value   " becomes
		// "key = value", which then normalizes cleanly.
		line = strings.TrimRight(line, " \t\r")

		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" {
			continue // Rule 1: drop blank
		}
		if trimmed[0] == '#' || trimmed[0] == ';' {
			continue // Rule 2: drop comment
		}

		// Rule 5: section headers preserved exactly — no normalization.
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			out = append(out, trimmed)
			continue
		}

		// Rule 4: collapse whitespace around the first =. systemd parses
		// "key = value" identically to "key=value", but the canonical form
		// has no surrounding whitespace.
		if eq := strings.IndexByte(trimmed, '='); eq >= 0 {
			key := strings.TrimRight(trimmed[:eq], " \t")
			val := strings.TrimLeft(trimmed[eq+1:], " \t")
			out = append(out, key+"="+val)
			continue
		}

		// Bare line with no = and no section markers — rare but valid (e.g.,
		// continuation lines after a backslash). Preserve as-is.
		out = append(out, trimmed)
	}
	return strings.Join(out, "\n")
}
