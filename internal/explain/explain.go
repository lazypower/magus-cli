// Package explain renders the per-resource detail blocks for
// `magus plan --explain`: unified diffs for owned updates, sha256-of-each-side
// for binary content, and hashes-only for unowned conflicts (with -v to reveal
// the diff), plus mode/ownership delta lines.
//
// Content passed in is already canonicalized for its kind — raw bytes for
// files, canonical unit text for units/quadlets — i.e. the same bytes used for
// the equivalence hash, so the diff matches what drove the action.
package explain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/pmezard/go-difflib/difflib"
)

// Input is one resource's on-disk vs IR state to explain.
type Input struct {
	OnDisk, IR           []byte
	OnDiskMode, IRMode   uint32 // permission bits; compared only when IRMode != 0
	OnDiskUID, OnDiskGID int
	IRUID, IRGID         *int // nil = ownership not declared (no owner line)
	Owned                bool // true = [update] (safe to diff); false = [conflict]
	Verbose              bool // reveal conflict content despite Owned=false
}

// Render returns the indented detail block for one action, without a trailing
// newline. Empty string means nothing to explain (everything matches).
func Render(in Input) string {
	var b strings.Builder

	if !bytes.Equal(in.OnDisk, in.IR) {
		b.WriteString(renderContent(in))
	}
	if in.IRMode != 0 && in.OnDiskMode != in.IRMode {
		fmt.Fprintf(&b, "    mode %#o → %#o\n", in.OnDiskMode, in.IRMode)
	}
	if line := ownerLine(in); line != "" {
		b.WriteString(line)
	}
	return strings.TrimRight(b.String(), "\n")
}

func renderContent(in Input) string {
	// Unowned conflict: do NOT leak the file's content into CLI/log/LLM output
	// unless the operator explicitly asked with -v.
	if !in.Owned && !in.Verbose {
		return "    content differs (hashes only; -v to show diff)\n" + hashes(in)
	}
	// Non-text on either side: a unified diff would be noise — show hashes.
	if !isText(in.OnDisk) || !isText(in.IR) {
		return "    binary content differs\n" + hashes(in)
	}
	return unified(in.OnDisk, in.IR)
}

func hashes(in Input) string {
	return fmt.Sprintf("      on disk: %s\n      IR:      %s\n", sha(in.OnDisk), sha(in.IR))
}

func unified(a, b []byte) string {
	ud := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(a)),
		B:        difflib.SplitLines(string(b)),
		FromFile: "on disk",
		ToFile:   "IR",
		Context:  3,
	}
	text, err := difflib.GetUnifiedDiffString(ud)
	if err != nil {
		// Fall back to hashes rather than producing nothing.
		return "    content differs\n      on disk: " + sha(a) + "\n      IR:      " + sha(b) + "\n"
	}
	return indent(text, "    ")
}

func ownerLine(in Input) string {
	if in.IRUID == nil && in.IRGID == nil {
		return "" // ownership not declared — magus leaves it alone, nothing to show
	}
	wantUID, wantGID := in.OnDiskUID, in.OnDiskGID
	if in.IRUID != nil {
		wantUID = *in.IRUID
	}
	if in.IRGID != nil {
		wantGID = *in.IRGID
	}
	if wantUID == in.OnDiskUID && wantGID == in.OnDiskGID {
		return ""
	}
	return fmt.Sprintf("    owner %d:%d → %d:%d\n", in.OnDiskUID, in.OnDiskGID, wantUID, wantGID)
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// isText reports whether b is safe to render as a textual diff: valid UTF-8 and
// free of NUL bytes.
func isText(b []byte) bool {
	if bytes.IndexByte(b, 0) != -1 {
		return false
	}
	return utf8.Valid(b)
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}
