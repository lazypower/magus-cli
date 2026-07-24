package principal

import (
	"errors"
	"testing"

	"github.com/lazypower/magus-cli/internal/ir"
)

func intp(i int) *int { return &i }

// fakeReader is an in-memory Reader for tests.
type fakeReader struct {
	users    map[string]ActualUser
	uidOwner map[int]string
	groups   map[string]int
	gidOwner map[int]string
	subid    map[string]bool // names with an existing subuid range
	linger   map[string]bool // names with linger enabled
	err      error           // if set, every lookup returns it (getent-failure path)
}

func (f fakeReader) LookupUser(name string) (ActualUser, error) {
	if f.err != nil {
		return ActualUser{}, f.err
	}
	if u, ok := f.users[name]; ok {
		return u, nil
	}
	return ActualUser{Exists: false}, nil
}
func (f fakeReader) UserByID(uid int) (string, bool, error) {
	n, ok := f.uidOwner[uid]
	return n, ok, nil
}
func (f fakeReader) LookupGroup(name string) (int, bool, error) {
	g, ok := f.groups[name]
	return g, ok, nil
}
func (f fakeReader) GroupByID(gid int) (string, bool, error) {
	n, ok := f.gidOwner[gid]
	return n, ok, nil
}
func (f fakeReader) HasSubid(name string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.subid[name], nil
}
func (f fakeReader) Linger(name string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.linger[name], nil
}

// fakeGate drives the policy surface directly.
type fakeGate struct {
	managed    map[string]bool
	privileged map[string]bool
	grants     map[string]map[string]bool
}

func (g fakeGate) Manages(name string) bool          { return g.managed[name] }
func (g fakeGate) IsPrivilegedGroup(grp string) bool { return g.privileged[grp] }
func (g fakeGate) GrantsPrivilegedGroup(p, grp string) bool {
	return g.grants[p] != nil && g.grants[p][grp]
}

// manages builds a gate that manages the given names, with wheel privileged.
func manages(names ...string) fakeGate {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return fakeGate{managed: m, privileged: map[string]bool{"wheel": true}}
}

func onlyUser(u ir.User) *ir.IR { return &ir.IR{Users: []ir.User{u}} }

func TestDiffCreateWhenAbsent(t *testing.T) {
	in := onlyUser(ir.User{Name: "argus", UID: intp(1000)})
	plan, err := Diff(in, fakeReader{}, manages("argus"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Action != ActionCreate {
		t.Fatalf("want one create, got %+v", plan.Actions)
	}
}

func TestDiffUnmanagedIgnored(t *testing.T) {
	// core is declared but not in manage_users → ignored, no getent, no action.
	in := onlyUser(ir.User{Name: "core", UID: intp(1000)})
	plan, err := Diff(in, fakeReader{err: errors.New("getent must not be called")}, manages("argus"))
	if err != nil {
		t.Fatalf("unmanaged principal must not touch the reader: %v", err)
	}
	if len(plan.Actions) != 0 {
		t.Fatalf("unmanaged principal must yield no actions, got %+v", plan.Actions)
	}
}

func TestDiffAdoptWhenMatches(t *testing.T) {
	r := fakeReader{users: map[string]ActualUser{
		"argus": {Exists: true, Name: "argus", UID: 1000, PrimaryGroup: "argus", Shell: "/usr/sbin/nologin", Home: "/var/home/argus"},
	}}
	in := onlyUser(ir.User{Name: "argus", UID: intp(1000), Shell: "/usr/sbin/nologin", HomeDir: "/var/home/argus"})
	plan, _ := Diff(in, r, manages("argus"))
	if plan.Actions[0].Action != ActionAdopt {
		t.Fatalf("want adopt, got %s (%s)", plan.Actions[0].Action, plan.Actions[0].Reason)
	}
}

func TestDiffConvergeOnShellDrift(t *testing.T) {
	r := fakeReader{users: map[string]ActualUser{
		"argus": {Exists: true, Name: "argus", UID: 1000, Shell: "/bin/bash"},
	}}
	in := onlyUser(ir.User{Name: "argus", UID: intp(1000), Shell: "/usr/sbin/nologin"})
	plan, _ := Diff(in, r, manages("argus"))
	if plan.Actions[0].Action != ActionConverge {
		t.Fatalf("shell drift must converge, got %s", plan.Actions[0].Action)
	}
}

func TestDiffConflictOnUIDCollision(t *testing.T) {
	// argus absent, but uid 1000 belongs to someone else → conflict, no clobber.
	r := fakeReader{uidOwner: map[int]string{1000: "other"}}
	in := onlyUser(ir.User{Name: "argus", UID: intp(1000)})
	plan, _ := Diff(in, r, manages("argus"))
	if plan.Actions[0].Action != ActionConflict {
		t.Fatalf("uid collision must conflict, got %s", plan.Actions[0].Action)
	}
}

func TestDiffConflictOnImmutableIdentity(t *testing.T) {
	cases := []struct {
		name   string
		actual ActualUser
		want   ir.User
	}{
		{"uid", ActualUser{Exists: true, Name: "argus", UID: 1001}, ir.User{Name: "argus", UID: intp(1000)}},
		{"home", ActualUser{Exists: true, Name: "argus", UID: 1000, Home: "/var/home/argus"}, ir.User{Name: "argus", UID: intp(1000), HomeDir: "/srv/argus"}},
		{"primary-group", ActualUser{Exists: true, Name: "argus", UID: 1000, PrimaryGroup: "argus"}, ir.User{Name: "argus", UID: intp(1000), PrimaryGroup: "staff"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fakeReader{users: map[string]ActualUser{"argus": c.actual}}
			plan, _ := Diff(onlyUser(c.want), r, manages("argus"))
			if plan.Actions[0].Action != ActionConflict {
				t.Errorf("immutable %s change must conflict, got %s (%s)", c.name, plan.Actions[0].Action, plan.Actions[0].Reason)
			}
		})
	}
}

func TestDiffConflictAdoptingPrivilegedPrincipal(t *testing.T) {
	// argus already exists and is in wheel, no grant → adoption must NOT absorb
	// the escalation; it's a conflict.
	r := fakeReader{users: map[string]ActualUser{
		"argus": {Exists: true, Name: "argus", UID: 1000, PrimaryGroup: "argus", Groups: []string{"wheel"}},
	}}
	plan, _ := Diff(onlyUser(ir.User{Name: "argus", UID: intp(1000)}), r, manages("argus"))
	if plan.Actions[0].Action != ActionConflict {
		t.Fatalf("privileged existing principal must conflict, got %s (%s)", plan.Actions[0].Action, plan.Actions[0].Reason)
	}
}

func TestDiffGrantedPrivilegedAdopts(t *testing.T) {
	// Same as above but policy grants argus→wheel → adopts cleanly.
	r := fakeReader{users: map[string]ActualUser{
		"argus": {Exists: true, Name: "argus", UID: 1000, PrimaryGroup: "argus", Groups: []string{"wheel"}},
	}}
	g := manages("argus")
	g.grants = map[string]map[string]bool{"argus": {"wheel": true}}
	plan, _ := Diff(onlyUser(ir.User{Name: "argus", UID: intp(1000)}), r, g)
	if plan.Actions[0].Action != ActionAdopt {
		t.Fatalf("granted privileged principal should adopt, got %s (%s)", plan.Actions[0].Action, plan.Actions[0].Reason)
	}
}

func TestDiffReaderErrorFailsClosed(t *testing.T) {
	in := onlyUser(ir.User{Name: "argus", UID: intp(1000)})
	if _, err := Diff(in, fakeReader{err: errors.New("getent down")}, manages("argus")); err == nil {
		t.Fatal("a reader failure must propagate (fail-closed), not be swallowed")
	}
}

// fakeExecutor records calls and can be primed to fail.
type fakeExecutor struct {
	calls  []string
	failOn map[string]error
}

func (e *fakeExecutor) rec(s string) error {
	e.calls = append(e.calls, s)
	return e.failOn[s]
}
func (e *fakeExecutor) UserAdd(u ir.User, locked bool) error {
	return e.rec("UserAdd(" + u.Name + ")")
}
func (e *fakeExecutor) UserSetShell(name, shell string) error {
	return e.rec("UserSetShell(" + name + ")")
}
func (e *fakeExecutor) UserAddGroups(name string, groups []string) error {
	return e.rec("UserAddGroups(" + name + ")")
}
func (e *fakeExecutor) GroupAdd(g ir.Group) error { return e.rec("GroupAdd(" + g.Name + ")") }
func (e *fakeExecutor) EnsureSubid(name string) error {
	return e.rec("EnsureSubid(" + name + ")")
}
func (e *fakeExecutor) EnableLinger(name string) error {
	return e.rec("EnableLinger(" + name + ")")
}

func has(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

func TestApplyCreateRunsUserAdd(t *testing.T) {
	in := onlyUser(ir.User{Name: "argus", UID: intp(1000)})
	plan, _ := Diff(in, fakeReader{}, manages("argus"))
	ex := &fakeExecutor{failOn: map[string]error{}}
	r := Apply(plan, in, ex)
	if !has(ex.calls, "UserAdd(argus)") {
		t.Errorf("create must call UserAdd, got %v", ex.calls)
	}
	if r.ExitCode() != 0 {
		t.Errorf("clean create exit = %d", r.ExitCode())
	}
}

func TestApplyAdoptDoesNotWrite(t *testing.T) {
	r := fakeReader{users: map[string]ActualUser{"argus": {Exists: true, Name: "argus", UID: 1000}}}
	in := onlyUser(ir.User{Name: "argus", UID: intp(1000)})
	plan, _ := Diff(in, r, manages("argus"))
	ex := &fakeExecutor{failOn: map[string]error{}}
	res := Apply(plan, in, ex)
	if len(ex.calls) != 0 {
		t.Errorf("adopt must not mutate, got %v", ex.calls)
	}
	if _, u, _, _ := res.Counts(); u != 1 {
		t.Errorf("adopt should be unchanged, got %+v", res.Outcomes)
	}
}

func TestApplyConflictSkipsExit2(t *testing.T) {
	r := fakeReader{uidOwner: map[int]string{1000: "other"}}
	in := onlyUser(ir.User{Name: "argus", UID: intp(1000)})
	plan, _ := Diff(in, r, manages("argus"))
	ex := &fakeExecutor{failOn: map[string]error{}}
	res := Apply(plan, in, ex)
	if len(ex.calls) != 0 {
		t.Errorf("conflict must not mutate, got %v", ex.calls)
	}
	if res.ExitCode() != 2 {
		t.Errorf("conflict exit = %d, want 2", res.ExitCode())
	}
}

func onlyGroup(g ir.Group) *ir.IR { return &ir.IR{Groups: []ir.Group{g}} }

func TestDiffGroupCreate(t *testing.T) {
	plan, _ := Diff(onlyGroup(ir.Group{Name: "argus", GID: intp(1600)}), fakeReader{}, manages("argus"))
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != KindGroup || plan.Actions[0].Action != ActionCreate {
		t.Fatalf("want one group create, got %+v", plan.Actions)
	}
}

func TestDiffGroupAdopt(t *testing.T) {
	r := fakeReader{groups: map[string]int{"argus": 1600}}
	plan, _ := Diff(onlyGroup(ir.Group{Name: "argus", GID: intp(1600)}), r, manages("argus"))
	if plan.Actions[0].Action != ActionAdopt {
		t.Fatalf("matching group must adopt, got %s", plan.Actions[0].Action)
	}
}

func TestDiffGroupConflicts(t *testing.T) {
	// gid immutable: exists with a different gid.
	r := fakeReader{groups: map[string]int{"argus": 1601}}
	plan, _ := Diff(onlyGroup(ir.Group{Name: "argus", GID: intp(1600)}), r, manages("argus"))
	if plan.Actions[0].Action != ActionConflict {
		t.Errorf("changed gid must conflict, got %s", plan.Actions[0].Action)
	}
	// gid collision: absent, but the gid belongs to another group.
	r2 := fakeReader{gidOwner: map[int]string{1600: "other"}}
	plan2, _ := Diff(onlyGroup(ir.Group{Name: "argus", GID: intp(1600)}), r2, manages("argus"))
	if plan2.Actions[0].Action != ActionConflict {
		t.Errorf("gid collision must conflict, got %s", plan2.Actions[0].Action)
	}
}

func TestApplyGroupCreateRunsGroupAdd(t *testing.T) {
	in := onlyGroup(ir.Group{Name: "argus", GID: intp(1600)})
	plan, _ := Diff(in, fakeReader{}, manages("argus"))
	ex := &fakeExecutor{failOn: map[string]error{}}
	if r := Apply(plan, in, ex); r.ExitCode() != 0 {
		t.Fatalf("group create exit %d", r.ExitCode())
	}
	if !has(ex.calls, "GroupAdd(argus)") {
		t.Errorf("group create must call GroupAdd, got %v", ex.calls)
	}
}

func TestApplyConvergeSetsShellAndGroups(t *testing.T) {
	r := fakeReader{users: map[string]ActualUser{
		"argus": {Exists: true, Name: "argus", UID: 1500, PrimaryGroup: "argus", Shell: "/bin/bash"},
	}}
	in := onlyUser(ir.User{Name: "argus", UID: intp(1500), Shell: "/usr/sbin/nologin", Groups: []string{"kvm"}})
	plan, _ := Diff(in, r, manages("argus"))
	if plan.Actions[0].Action != ActionConverge {
		t.Fatalf("want converge, got %s", plan.Actions[0].Action)
	}
	ex := &fakeExecutor{failOn: map[string]error{}}
	res := Apply(plan, in, ex)
	if !has(ex.calls, "UserSetShell(argus)") || !has(ex.calls, "UserAddGroups(argus)") {
		t.Errorf("converge must set shell and add groups, got %v", ex.calls)
	}
	if a, _, _, _ := res.Counts(); a != 1 {
		t.Errorf("converge should count as applied, got %+v", res.Outcomes)
	}
}

func TestPlanHasWork(t *testing.T) {
	create, _ := Diff(onlyUser(ir.User{Name: "argus", UID: intp(1500)}), fakeReader{}, manages("argus"))
	if !create.HasWork() {
		t.Error("a create plan has work")
	}
	adopt, _ := Diff(onlyUser(ir.User{Name: "argus", UID: intp(1500)}),
		fakeReader{users: map[string]ActualUser{"argus": {Exists: true, Name: "argus", UID: 1500}}}, manages("argus"))
	if adopt.HasWork() {
		t.Error("an adopt-only plan has no work")
	}
}

func TestApplyErrorIsolation(t *testing.T) {
	in := &ir.IR{Users: []ir.User{
		{Name: "a", UID: intp(1000)},
		{Name: "b", UID: intp(1001)},
	}}
	plan, _ := Diff(in, fakeReader{}, manages("a", "b"))
	ex := &fakeExecutor{failOn: map[string]error{"UserAdd(a)": errors.New("useradd boom")}}
	res := Apply(plan, in, ex)
	if !has(ex.calls, "UserAdd(b)") {
		t.Errorf("one failed useradd must not halt the rest: %v", ex.calls)
	}
	if res.ExitCode() != 1 {
		t.Errorf("errored exit = %d, want 1", res.ExitCode())
	}
}
