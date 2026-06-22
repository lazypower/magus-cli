package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gitea.wabash.place/lab/magus-cli/internal/diff"
	"gitea.wabash.place/lab/magus-cli/internal/hostfs"
	"gitea.wabash.place/lab/magus-cli/internal/ir"
	"gitea.wabash.place/lab/magus-cli/internal/manifest"
	"gitea.wabash.place/lab/magus-cli/internal/policy"
)

const reclaimUsage = `magus reclaim — restore an orphaned path to active reconciliation

Usage: magus reclaim [--yes] [--force] [--policy <path>] [--manifest <path>] <butane-source> <path>

<butane-source> is either a local filesystem path or an http(s) URL.

Reclaim transitions an orphaned manifest entry back to active state. The IR
must declare the path; the policy must currently permit it; the path must
exist on disk.

If on-disk content has drifted from the manifest hash during the orphan
period, reclaim refuses unless --force is passed. With --force, the IR
content is written over the existing file before the state transition.

Reclaim never auto-runs — the operator decides when to take a path back
under management.

Flags:
  --yes               Skip the confirmation prompt
  --force             Overwrite drifted on-disk content with IR content
  --policy <path>     Override policy file (default: /etc/magus/policy.yaml)
  --manifest <path>   Override manifest file (default: /var/lib/magus/manifest.json)
`

func runReclaim(args []string) int {
	fs := flag.NewFlagSet("reclaim", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, reclaimUsage) }
	policyPath := fs.String("policy", policy.DefaultPath, "policy file path")
	manifestPath := fs.String("manifest", manifest.DefaultPath, "manifest file path")
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	force := fs.Bool("force", false, "overwrite drifted on-disk content")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 2 {
		fmt.Fprint(os.Stderr, reclaimUsage)
		return 1
	}
	butanePath, target := fs.Arg(0), fs.Arg(1)

	p, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	parsed, _, err := ir.LoadButane(butanePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if violations := policy.Check(p, parsed, *manifestPath, *policyPath); len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "error: %s\n", v)
		}
		return 1
	}
	m, err := manifest.Load(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	entry, exists := m.Get(target)
	if !exists {
		fmt.Fprintf(os.Stderr, "error: %s is not in the manifest\n", target)
		return 1
	}
	if entry.State != manifest.StateOrphaned {
		fmt.Fprintf(os.Stderr, "error: %s is %s, not orphaned — nothing to reclaim\n", target, entry.State)
		return 1
	}
	// Verify the policy that orphaned the path no longer denies it. If it
	// still denies, reclaiming would re-orphan on next apply — so refuse.
	if reason := p.DenyPathReason(target); reason != "" {
		fmt.Fprintf(os.Stderr, "error: %s is still denied by policy (%s) — amend the policy first\n",
			target, reason)
		return 1
	}

	declared, ok := findDeclared(parsed, target)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: %s is not declared in %s\n", target, butanePath)
		return 1
	}

	w := hostfs.OS()
	st, err := w.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: stat %s: %v\n", target, err)
		return 1
	}
	if !st.Exists {
		fmt.Fprintf(os.Stderr, "error: %s no longer exists on disk\n", target)
		return 1
	}
	// Symlink-resolved containment, unconditionally (not just on --force): a
	// path that now resolves outside authority must not be returned to active
	// reconciliation at all, write or no write.
	if r, ok := w.(hostfs.Resolver); ok {
		if _, reason := diff.ContainmentEscape(p, r, target); reason != "" {
			fmt.Fprintf(os.Stderr, "error: refusing to reclaim %s: %s\n", target, reason)
			return 1
		}
	}

	body, err := w.ReadFile(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read %s: %v\n", target, err)
		return 1
	}
	// Hash with the resource's equivalence rule (canonical for units/quadlets,
	// raw for files) so unit/quadlet drift detection matches the manifest hash.
	onDisk := diff.HashContent(body, declared.diffKind)
	declaredHash := diff.HashContent(declared.contents, declared.diffKind)

	drifted := onDisk != entry.Hash
	mismatchedFromIR := onDisk != declaredHash

	// Refuse if on-disk drifted from manifest hash unless --force. The case
	// the spec is protecting against: an orphaned file that was hand-edited
	// during the orphan period would silently re-enter reconciliation with
	// the new content if reclaim accepted drift unconditionally.
	if drifted && !*force {
		fmt.Fprintf(os.Stderr,
			"error: on-disk content has drifted from the manifest hash since orphaning\n"+
				"  manifest hash: %s\n"+
				"  on-disk hash:  %s\n"+
				"Pass --force to overwrite with IR content, or resolve the drift manually.\n",
			entry.Hash, onDisk)
		return 1
	}

	orphanedAt := time.Time{}
	if entry.OrphanedAt != nil {
		orphanedAt = *entry.OrphanedAt
	}
	fmt.Printf("This path is orphaned (orphaned %s by %s).\n",
		orphanedAt.Format(time.RFC3339), entry.OrphanedReason)
	fmt.Println()
	fmt.Printf("  - manifest hash:  %s%s\n", entry.Hash, matchAnnotation(entry.Hash == onDisk))
	fmt.Printf("  - on-disk hash:   %s%s\n", onDisk, matchAnnotation(onDisk == entry.Hash))
	fmt.Printf("  - IR hash:        %s%s\n", declaredHash, matchAnnotation(declaredHash == onDisk))
	fmt.Println()

	switch {
	case *force && mismatchedFromIR:
		fmt.Println("Reclaiming with --force will overwrite the on-disk content with the IR's content.")
	default:
		fmt.Println("Reclaiming will resume reconciliation from this state.")
	}

	if !*yes {
		if !confirmReclaim(os.Stdin, os.Stdout, target) {
			fmt.Println("Aborted.")
			return 0
		}
	}
	fmt.Println()

	if *force && mismatchedFromIR {
		// Containment already verified above (unconditionally).
		if err := w.WriteFile(target, declared.contents, declared.mode, declared.uid, declared.gid); err != nil {
			fmt.Fprintf(os.Stderr, "error: write %s: %v\n", target, err)
			return 1
		}
	}

	// Transition manifest entry to active. Hash is updated to whatever now
	// represents the canonical content (IR-write hash if --force, otherwise
	// the on-disk hash that was equivalent to the manifest hash).
	finalHash := onDisk
	if *force && mismatchedFromIR {
		finalHash = declaredHash
	}
	// Preserve the kind from the orphaned entry — reclaiming a unit must
	// not silently demote it to a file.
	m.PutActive(target, entry.Kind, finalHash, entry.Origin, time.Now().UTC())
	if err := m.Save(*manifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: save manifest: %v\n", err)
		return 1
	}
	fmt.Printf("  ✓ %s  (state: orphaned → active)\n", target)
	return 0
}

// declaredTarget is a path's declared desired state, normalized across IR kinds
// so reclaim can restore a file, a unit body, a drop-in, or a quadlet — every
// kind OrphanDenied can orphan.
type declaredTarget struct {
	contents []byte
	mode     uint32
	uid, gid *int
	diffKind diff.Kind
}

// manifestKind maps a diff.Kind to the manifest.Kind recorded for ownership.
func manifestKind(k diff.Kind) manifest.Kind {
	switch k {
	case diff.KindUnit:
		return manifest.KindUnit
	case diff.KindQuadlet:
		return manifest.KindQuadlet
	case diff.KindDirectory:
		return manifest.KindDirectory
	default:
		return manifest.KindFile
	}
}

// findDeclared locates the IR resource that owns the given on-disk path across
// files, unit bodies, drop-ins, and quadlets.
func findDeclared(in *ir.IR, path string) (declaredTarget, bool) {
	for _, f := range in.Files {
		if f.Path == path {
			return declaredTarget{f.Contents, f.Mode, f.UID, f.GID, diff.KindFile}, true
		}
	}
	for _, u := range in.Units {
		if len(u.Contents) > 0 && diff.UnitPath(u.Name) == path {
			return declaredTarget{[]byte(u.Contents), 0o644, nil, nil, diff.KindUnit}, true
		}
		for _, di := range u.DropIns {
			if diff.DropInPath(u.Name, di.Name) == path {
				return declaredTarget{[]byte(di.Contents), 0o644, nil, nil, diff.KindUnit}, true
			}
		}
	}
	for _, q := range in.Quadlets {
		if q.Path == path {
			return declaredTarget{q.Contents, q.Mode, q.UID, q.GID, diff.KindQuadlet}, true
		}
	}
	return declaredTarget{}, false
}

func matchAnnotation(matches bool) string {
	if matches {
		return "  (matches)"
	}
	return "  (differs)"
}

func confirmReclaim(in io.Reader, out io.Writer, path string) bool {
	fmt.Fprintf(out, "Reclaim %s? [y/N] ", path)
	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
