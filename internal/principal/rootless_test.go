package principal

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lazypower/magus-cli/internal/ir"
)

// userQuadlet is a small helper: a user-scoped quadlet owned by owner.
func userQuadlet(name, owner string) ir.Quadlet {
	return ir.Quadlet{Name: name, Scope: ir.ScopeUser, Owner: owner}
}

func TestRootlessOwners(t *testing.T) {
	in := &ir.IR{Quadlets: []ir.Quadlet{
		userQuadlet("argusd.container", "argus"),
		userQuadlet("argus-egress.network", "argus"),   // same owner, deduped
		userQuadlet("bob.container", "bob"),            // unmanaged owner, dropped
		{Name: "sys.container", Scope: ir.ScopeSystem}, // system, no owner
	}}
	got := RootlessOwners(in, manages("argus"))
	if !reflect.DeepEqual(got, []string{"argus"}) {
		t.Errorf("RootlessOwners = %v, want [argus] (deduped, managed-only, system excluded)", got)
	}
}

func TestParseSubidFileAndNextFreeStart(t *testing.T) {
	ranges := parseSubidFile("core:100000:65536\nargus:165536:65536\n# comment\nbad:line\n")
	if len(ranges) != 2 {
		t.Fatalf("parsed %d ranges, want 2 (comment + malformed skipped): %+v", len(ranges), ranges)
	}
	// Next free packs above the highest end: 165536 + 65536 = 231072.
	if got := nextFreeSubStart(ranges, subIDMin); got != 231072 {
		t.Errorf("nextFreeSubStart = %d, want 231072", got)
	}
	// Empty registry → the floor.
	if got := nextFreeSubStart(nil, subIDMin); got != subIDMin {
		t.Errorf("nextFreeSubStart(empty) = %d, want %d", got, subIDMin)
	}
}

func TestSubidArgs(t *testing.T) {
	// Both sides missing → both added.
	got := subidArgs("argus", 231072, 65536, true, true)
	want := []string{"--add-subuids", "231072-296607", "--add-subgids", "231072-296607", "argus"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("subidArgs(both) = %v\nwant %v", got, want)
	}
	// Only subgid missing → only --add-subgids (no duplicate subuid).
	got = subidArgs("argus", 231072, 65536, false, true)
	want = []string{"--add-subgids", "231072-296607", "argus"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("subidArgs(gid only) = %v\nwant %v", got, want)
	}
}

// The rootless diff emits create-or-adopt per prerequisite: a principal with no
// subuid and no linger gets two creates; one already lingering with a subuid gets
// two adopts. Ordered subuid-before-linger.
func TestDiffRootless(t *testing.T) {
	in := &ir.IR{
		Users:    []ir.User{{Name: "argus", UID: intp(1000)}},
		Quadlets: []ir.Quadlet{userQuadlet("argusd.container", "argus")},
	}

	// Nothing provisioned yet → two creates.
	fresh := fakeReader{}
	plan, err := Diff(in, fresh, manages("argus"))
	if err != nil {
		t.Fatal(err)
	}
	subid, linger := rootlessActions(plan)
	if subid == nil || subid.Action != ActionCreate {
		t.Errorf("subid action = %+v, want create", subid)
	}
	if linger == nil || linger.Action != ActionCreate {
		t.Errorf("linger action = %+v, want create", linger)
	}
	// Ordering: the user create precedes both, subuid precedes linger.
	assertOrder(t, plan, "user:argus", "subuid:argus", "linger:argus")

	// Already provisioned → two adopts (no write).
	warm := fakeReader{
		users:  map[string]ActualUser{"argus": {Exists: true, Name: "argus", UID: 1000}},
		subid:  map[string]bool{"argus": true},
		linger: map[string]bool{"argus": true},
	}
	plan2, err := Diff(in, warm, manages("argus"))
	if err != nil {
		t.Fatal(err)
	}
	subid2, linger2 := rootlessActions(plan2)
	if subid2.Action != ActionAdopt || linger2.Action != ActionAdopt {
		t.Errorf("already-provisioned should adopt: subid=%+v linger=%+v", subid2, linger2)
	}
}

// A REFUSED owner (its user is a conflict) gets NO subuid/linger provisioning —
// magus must not enable linger or grant subuid for an identity it refused, or its
// user manager could start a workload as the refused identity (Codex round-3).
func TestDiffRootlessSkipsConflictedOwner(t *testing.T) {
	in := &ir.IR{
		// argus declares uid 1000, but 1000 already belongs to a different user →
		// the argus user is a conflict.
		Users:    []ir.User{{Name: "argus", UID: intp(1000)}},
		Quadlets: []ir.Quadlet{userQuadlet("argusd.container", "argus")},
	}
	r := fakeReader{uidOwner: map[int]string{1000: "squatter"}}
	plan, err := Diff(in, r, manages("argus"))
	if err != nil {
		t.Fatal(err)
	}
	// The user is a conflict...
	var userConflict bool
	for _, a := range plan.Actions {
		if a.Kind == KindUser && a.Name == "argus" && a.Action == ActionConflict {
			userConflict = true
		}
	}
	if !userConflict {
		t.Fatal("precondition: argus should be a uid-collision conflict")
	}
	// ...so NO subuid/linger rows are emitted for it.
	if s, l := rootlessActions(plan); s != nil || l != nil {
		t.Errorf("a refused owner must get no subuid/linger; got subid=%+v linger=%+v", s, l)
	}
}

// A rootless owner whose DECLARED group did not reconcile (host has it at a
// different gid) is itself turned into a conflict — so magus won't create/modify
// it against the wrong-gid group NOR provision its subuid/linger. This makes the
// group-dependency refusal atomic across every gate (Codex round-5).
func TestDiffGroupDependencyMakesOwnerConflict(t *testing.T) {
	in := &ir.IR{
		Groups:   []ir.Group{{Name: "appgrp", GID: intp(2000)}},
		Users:    []ir.User{{Name: "argus", UID: intp(1000), PrimaryGroup: "appgrp"}},
		Quadlets: []ir.Quadlet{userQuadlet("argusd.container", "argus")},
	}
	// Host already has appgrp at gid 3000 → the group is a conflict.
	r := fakeReader{groups: map[string]int{"appgrp": 3000}}
	plan, err := Diff(in, r, manages("argus", "appgrp"))
	if err != nil {
		t.Fatal(err)
	}
	var userConflict bool
	for _, a := range plan.Actions {
		if a.Kind == KindUser && a.Name == "argus" {
			if a.Action != ActionConflict || !strings.Contains(a.Reason, "appgrp") {
				t.Errorf("argus should be a conflict citing its group: %+v", a)
			}
			userConflict = true
		}
	}
	if !userConflict {
		t.Fatal("argus (depending on a conflicted group) must become a conflict")
	}
	// And therefore NO subuid/linger for it.
	if s, l := rootlessActions(plan); s != nil || l != nil {
		t.Errorf("a group-refused owner must get no subuid/linger; got subid=%+v linger=%+v", s, l)
	}
}

// No user-scoped workload → no rootless prerequisites (they are consequences of
// owning one, never emitted for a plain identity).
func TestDiffRootlessNoWorkloadNoPrereqs(t *testing.T) {
	in := &ir.IR{Users: []ir.User{{Name: "argus", UID: intp(1000)}}}
	plan, err := Diff(in, fakeReader{}, manages("argus"))
	if err != nil {
		t.Fatal(err)
	}
	if s, l := rootlessActions(plan); s != nil || l != nil {
		t.Errorf("no workload → no subuid/linger; got subid=%+v linger=%+v", s, l)
	}
}

// A reader failure on the subuid/linger probe is fail-closed, exactly like the
// identity getent probe.
func TestDiffRootlessProbeErrorPropagates(t *testing.T) {
	in := &ir.IR{
		Users:    []ir.User{{Name: "argus", UID: intp(1000)}},
		Quadlets: []ir.Quadlet{userQuadlet("argusd.container", "argus")},
	}
	if _, err := Diff(in, fakeReader{err: errors.New("subuid read failed")}, manages("argus")); err == nil {
		t.Error("a rootless probe failure must propagate (fail-closed)")
	}
}

// Apply runs the provisions; EnsureSubid/EnableLinger reach the executor.
func TestApplyRunsRootlessProvisions(t *testing.T) {
	in := &ir.IR{
		Users:    []ir.User{{Name: "argus", UID: intp(1000)}},
		Quadlets: []ir.Quadlet{userQuadlet("argusd.container", "argus")},
	}
	plan, _ := Diff(in, fakeReader{}, manages("argus"))
	ex := &fakeExecutor{failOn: map[string]error{}}
	Apply(plan, in, ex)
	if !has(ex.calls, "EnsureSubid(argus)") {
		t.Errorf("EnsureSubid not called: %v", ex.calls)
	}
	if !has(ex.calls, "EnableLinger(argus)") {
		t.Errorf("EnableLinger not called: %v", ex.calls)
	}
}

// The OS executor's EnsureSubid is detect-then-provision: no-op when a range
// already exists, next-free usermod otherwise.
func TestOSExecutorEnsureSubid(t *testing.T) {
	rec := &recorder{}
	// argus has BOTH ranges → no write.
	ex := osExecutor{run: rec.run, subidState: func() (map[string]bool, map[string]bool, []subRange, error) {
		return map[string]bool{"argus": true}, map[string]bool{"argus": true}, []subRange{{100000, 65536}}, nil
	}}
	if err := ex.EnsureSubid("argus"); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("both ranges present → no usermod; got %v", rec.calls)
	}

	// argus missing both → usermod adds both, next free range above core's.
	rec2 := &recorder{}
	ex2 := osExecutor{run: rec2.run, subidState: func() (map[string]bool, map[string]bool, []subRange, error) {
		return map[string]bool{"core": true}, map[string]bool{"core": true}, []subRange{{100000, 65536}}, nil
	}}
	if err := ex2.EnsureSubid("argus"); err != nil {
		t.Fatal(err)
	}
	if len(rec2.calls) != 1 || rec2.calls[0][0] != "usermod" ||
		rec2.calls[0][1] != "--add-subuids" || rec2.calls[0][2] != "165536-231071" {
		t.Errorf("EnsureSubid argv = %v (want usermod --add-subuids 165536-231071 --add-subgids ...)", rec2.calls)
	}

	// Asymmetric: subuid present, subgid absent → add ONLY subgid (no duplicate).
	rec3 := &recorder{}
	ex3 := osExecutor{run: rec3.run, subidState: func() (map[string]bool, map[string]bool, []subRange, error) {
		return map[string]bool{"argus": true}, map[string]bool{}, []subRange{{100000, 65536}}, nil
	}}
	if err := ex3.EnsureSubid("argus"); err != nil {
		t.Fatal(err)
	}
	if len(rec3.calls) != 1 || rec3.calls[0][1] != "--add-subgids" {
		t.Errorf("asymmetric repair should add only subgid; got %v", rec3.calls)
	}
}

// The host reads resolve real registry/marker state against a temp tree.
func TestSubidAndLingerHostReads(t *testing.T) {
	dir := t.TempDir()
	su := filepath.Join(dir, "subuid")
	sg := filepath.Join(dir, "subgid")
	linger := filepath.Join(dir, "linger")
	if err := os.WriteFile(su, []byte("core:100000:65536\nargus:165536:65536\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sg, []byte("core:100000:65536\nargus:165536:65536\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linger, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linger, "argus"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	defer swapPaths(su, sg, linger)()

	// subidPresent: argus has both, bob has neither.
	if ok, err := subidPresent("argus"); err != nil || !ok {
		t.Errorf("subidPresent(argus) = %v,%v want true", ok, err)
	}
	if ok, err := subidPresent("bob"); err != nil || ok {
		t.Errorf("subidPresent(bob) = %v,%v want false", ok, err)
	}
	// A name in subuid but not subgid is NOT present (rootless needs both).
	if err := os.WriteFile(su, []byte("core:100000:65536\nhalf:300000:65536\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _ := subidPresent("half"); ok {
		t.Errorf("subidPresent(half) must be false — only in subuid, not subgid")
	}

	// readSubidState records names PER FILE and unions ranges across both.
	inUID, inGID, used, err := readSubidState()
	if err != nil {
		t.Fatal(err)
	}
	if !inUID["core"] || !inUID["half"] {
		t.Errorf("inUID = %v, want core+half", inUID)
	}
	if !inGID["core"] || !inGID["argus"] || inGID["half"] {
		t.Errorf("inGID = %v, want core+argus (not half — subgid never got it)", inGID)
	}
	if got := nextFreeSubStart(used, subIDMin); got != 365536 {
		t.Errorf("nextFreeSubStart over both files = %d, want 365536", got)
	}

	// lingerEnabled reflects the marker file.
	if ok, err := lingerEnabled("argus"); err != nil || !ok {
		t.Errorf("lingerEnabled(argus) = %v,%v want true", ok, err)
	}
	if ok, _ := lingerEnabled("bob"); ok {
		t.Error("lingerEnabled(bob) must be false — no marker")
	}
}

// A missing registry file is empty, not an error.
func TestSubidReadsTolerateMissingFiles(t *testing.T) {
	dir := t.TempDir()
	defer swapPaths(filepath.Join(dir, "nope-subuid"), filepath.Join(dir, "nope-subgid"), filepath.Join(dir, "nope-linger"))()
	if ok, err := subidPresent("argus"); err != nil || ok {
		t.Errorf("missing subuid → absent, not error; got %v,%v", ok, err)
	}
	inUID, inGID, used, err := readSubidState()
	if err != nil || len(inUID) != 0 || len(inGID) != 0 || len(used) != 0 {
		t.Errorf("missing files → empty state; got %v,%v,%v,%v", inUID, inGID, used, err)
	}
	if ok, err := lingerEnabled("argus"); err != nil || ok {
		t.Errorf("missing marker → not lingering, not error; got %v,%v", ok, err)
	}
}

// swapPaths repoints the host-path vars and returns a restore func.
func swapPaths(su, sg, linger string) func() {
	osu, osg, ol := subuidPath, subgidPath, lingerDir
	subuidPath, subgidPath, lingerDir = su, sg, linger
	return func() { subuidPath, subgidPath, lingerDir = osu, osg, ol }
}

// rootlessActions pulls the subuid and linger rows out of a plan (nil if absent).
func rootlessActions(p *Plan) (subid, linger *PrincipalAction) {
	for i := range p.Actions {
		switch p.Actions[i].Kind {
		case KindSubid:
			subid = &p.Actions[i]
		case KindLinger:
			linger = &p.Actions[i]
		}
	}
	return
}

// assertOrder checks that rows keyed "<kind>:<name>" appear in the given order.
func assertOrder(t *testing.T, p *Plan, want ...string) {
	t.Helper()
	pos := map[string]int{}
	for i, a := range p.Actions {
		pos[string(a.Kind)+":"+a.Name] = i
	}
	for i := 1; i < len(want); i++ {
		a, b := want[i-1], want[i]
		pa, oka := pos[a]
		pb, okb := pos[b]
		if !oka || !okb || pa >= pb {
			t.Errorf("order violated: %s (%d) should precede %s (%d)", a, pa, b, pb)
		}
	}
}
