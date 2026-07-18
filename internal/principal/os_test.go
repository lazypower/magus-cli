package principal

import (
	"errors"
	"reflect"
	"testing"

	"github.com/lazypower/magus-cli/internal/ir"
)

// --- pure parsing ------------------------------------------------------------

func TestParsePasswdEntry(t *testing.T) {
	a, err := parsePasswdEntry("argus:x:1500:1600:Argus Worker:/var/home/argus:/usr/sbin/nologin\n")
	if err != nil {
		t.Fatal(err)
	}
	want := ActualUser{Exists: true, Name: "argus", UID: 1500, GID: 1600, Home: "/var/home/argus", Shell: "/usr/sbin/nologin"}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("parsed %+v, want %+v", a, want)
	}
}

func TestParsePasswdEntryErrors(t *testing.T) {
	for _, line := range []string{
		"too:few:fields",               // < 7 fields
		"argus:x:notanumber:1600:::/",  // bad uid (and short, but uid parse fires first only if 7 fields)
		"argus:x:1500:bad:g:/home:/sh", // bad gid
	} {
		if _, err := parsePasswdEntry(line); err == nil {
			t.Errorf("expected error for %q", line)
		}
	}
}

func TestParseGroupGID(t *testing.T) {
	gid, err := parseGroupGID("argus:x:1600:member\n")
	if err != nil || gid != 1600 {
		t.Errorf("gid=%d err=%v, want 1600", gid, err)
	}
	if _, err := parseGroupGID("bad:x"); err == nil {
		t.Error("short group entry should error")
	}
	if _, err := parseGroupGID("g:x:notnum"); err == nil {
		t.Error("bad gid should error")
	}
}

func TestFirstFieldAndFilterPrimary(t *testing.T) {
	if got := firstField("argus:x:1500:"); got != "argus" {
		t.Errorf("firstField = %q", got)
	}
	got := filterPrimary([]string{"argus", "wheel", "docker"}, "argus")
	if !reflect.DeepEqual(got, []string{"wheel", "docker"}) {
		t.Errorf("filterPrimary = %v, want [wheel docker]", got)
	}
}

// --- reader behavior via injected seams --------------------------------------

// stubReader builds an osReader whose getent answers from a map keyed "db/key"
// and whose id -nG answers from a groups map.
func stubReader(entries map[string]string, groups map[string][]string, fail error) osReader {
	return osReader{
		lookup: func(db, key string) (string, bool, error) {
			if fail != nil {
				return "", false, fail
			}
			if line, ok := entries[db+"/"+key]; ok {
				return line, true, nil
			}
			return "", false, nil // absent
		},
		idGroups: func(name string) ([]string, error) { return groups[name], nil },
	}
}

func TestLookupUserResolvesGroups(t *testing.T) {
	r := stubReader(map[string]string{
		"passwd/argus": "argus:x:1500:1600:::/var/home/argus:/usr/sbin/nologin",
		"group/1600":   "argus:x:1600:",
	}, map[string][]string{"argus": {"argus", "docker"}}, nil)

	a, err := r.LookupUser("argus")
	if err != nil {
		t.Fatal(err)
	}
	if a.PrimaryGroup != "argus" {
		t.Errorf("primary group = %q, want argus", a.PrimaryGroup)
	}
	if !reflect.DeepEqual(a.Groups, []string{"docker"}) {
		t.Errorf("supplementary = %v, want [docker] (primary filtered out)", a.Groups)
	}
}

func TestLookupUserAbsent(t *testing.T) {
	r := stubReader(map[string]string{}, nil, nil)
	a, err := r.LookupUser("ghost")
	if err != nil || a.Exists {
		t.Errorf("absent user: exists=%v err=%v", a.Exists, err)
	}
}

func TestLookupUserGetentError(t *testing.T) {
	r := stubReader(nil, nil, errors.New("getent down"))
	if _, err := r.LookupUser("argus"); err == nil {
		t.Error("getent failure must propagate")
	}
}

func TestUserByIDAndGroupLookups(t *testing.T) {
	r := stubReader(map[string]string{
		"passwd/1500": "argus:x:1500:1600:::/:/bin/sh",
		"group/staff": "staff:x:50:",
		"group/50":    "staff:x:50:",
	}, nil, nil)

	if name, ok, _ := r.UserByID(1500); !ok || name != "argus" {
		t.Errorf("UserByID(1500) = %q,%v", name, ok)
	}
	if _, ok, _ := r.UserByID(9999); ok {
		t.Error("UserByID for a free uid should report not-taken")
	}
	if gid, ok, _ := r.LookupGroup("staff"); !ok || gid != 50 {
		t.Errorf("LookupGroup(staff) = %d,%v", gid, ok)
	}
	if name, ok, _ := r.GroupByID(50); !ok || name != "staff" {
		t.Errorf("GroupByID(50) = %q,%v", name, ok)
	}
}

// --- executor argv construction ----------------------------------------------

func TestUserAddArgs(t *testing.T) {
	uid := 1500
	got := userAddArgs(ir.User{Name: "argus", UID: &uid, PrimaryGroup: "argus", HomeDir: "/var/home/argus"})
	want := []string{"-u", "1500", "-g", "argus", "-d", "/var/home/argus", "-m", "-s", "/usr/sbin/nologin", "argus"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("userAddArgs = %v\nwant %v", got, want)
	}
	// Declared shell overrides the nologin default; system flag leads.
	got = userAddArgs(ir.User{Name: "svc", System: true, Shell: "/bin/bash"})
	want = []string{"--system", "-m", "-s", "/bin/bash", "svc"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("system userAddArgs = %v\nwant %v", got, want)
	}
}

func TestGroupAddArgs(t *testing.T) {
	gid := 1600
	if got := groupAddArgs(ir.Group{Name: "argus", GID: &gid}); !reflect.DeepEqual(got, []string{"-g", "1600", "argus"}) {
		t.Errorf("groupAddArgs = %v", got)
	}
	if got := groupAddArgs(ir.Group{Name: "svc", System: true}); !reflect.DeepEqual(got, []string{"--system", "svc"}) {
		t.Errorf("system groupAddArgs = %v", got)
	}
}

// recorder captures the argv each run receives.
type recorder struct {
	calls [][]string
	fail  map[string]error
}

func (rec *recorder) run(name string, args ...string) error {
	rec.calls = append(rec.calls, append([]string{name}, args...))
	return rec.fail[name]
}

func TestExecutorUserAddLocks(t *testing.T) {
	rec := &recorder{}
	ex := osExecutor{run: rec.run}
	uid := 1500
	if err := ex.UserAdd(ir.User{Name: "argus", UID: &uid}, true); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 2 || rec.calls[0][0] != "useradd" || rec.calls[1][0] != "usermod" {
		t.Fatalf("want useradd then usermod -L, got %v", rec.calls)
	}
	last := rec.calls[1]
	if last[len(last)-2] != "-L" {
		t.Errorf("account was not locked: %v", last)
	}
}

func TestExecutorUserAddFailurePropagates(t *testing.T) {
	rec := &recorder{fail: map[string]error{"useradd": errors.New("boom")}}
	ex := osExecutor{run: rec.run}
	if err := ex.UserAdd(ir.User{Name: "argus"}, true); err == nil {
		t.Error("useradd failure must propagate (and skip the lock)")
	}
	if len(rec.calls) != 1 {
		t.Errorf("lock must not run after useradd failed: %v", rec.calls)
	}
}

func TestExecutorShellAndGroupsAndGroupAdd(t *testing.T) {
	rec := &recorder{}
	ex := osExecutor{run: rec.run}
	_ = ex.UserSetShell("argus", "/usr/sbin/nologin")
	_ = ex.UserAddGroups("argus", []string{"docker", "kvm"})
	_ = ex.UserAddGroups("argus", nil) // no-op, records nothing
	_ = ex.GroupAdd(ir.Group{Name: "argus"})

	if got := rec.calls[0]; got[0] != "usermod" || got[1] != "-s" {
		t.Errorf("UserSetShell argv = %v", got)
	}
	if got := rec.calls[1]; got[0] != "usermod" || got[2] != "docker,kvm" {
		t.Errorf("UserAddGroups must comma-join: %v", got)
	}
	if len(rec.calls) != 3 {
		t.Errorf("empty group add should be a no-op; calls=%v", rec.calls)
	}
	if got := rec.calls[2]; got[0] != "groupadd" {
		t.Errorf("GroupAdd argv = %v", got)
	}
}
