package status

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status.json")
	r := &Report{
		Version:   CurrentVersion,
		LastApply: time.Unix(1000, 0).UTC(),
		Result:    ResultWithSkips,
		Units:     map[string]string{"magus-x.service": "active"},
		Conflicts: []Conflict{{Path: "/etc/core/a", Reason: "differs", FirstSeen: time.Unix(900, 0).UTC()}},
		Errors:    []ErrEntry{},
	}
	if err := r.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || got == nil {
		t.Fatalf("Load: %v (got %v)", err, got)
	}
	if got.Result != ResultWithSkips || got.Units["magus-x.service"] != "active" {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if len(got.Conflicts) != 1 || !got.Conflicts[0].FirstSeen.Equal(time.Unix(900, 0).UTC()) {
		t.Errorf("conflict not preserved: %+v", got.Conflicts)
	}
}

func TestLoadMissingIsNeverApplied(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil || got != nil {
		t.Errorf("missing status should be (nil,nil), got (%v,%v)", got, err)
	}
}

func TestLoadCorruptIsIgnored(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status.json")
	if err := writeFile(p, "{not json"); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || got != nil {
		t.Errorf("corrupt status should be ignored (nil,nil), got (%v,%v)", got, err)
	}
}

func TestLoadWrongVersionIgnored(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status.json")
	if err := writeFile(p, `{"version":99,"result":"ok"}`); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(p); got != nil {
		t.Errorf("wrong-version status should be ignored, got %+v", got)
	}
}

func TestLoadUnreadableIsSurfaced(t *testing.T) {
	// D21: a genuine read failure (here, the path is a directory) is distinct
	// from "never applied" — it must return an error so the caller can warn
	// instead of reporting last-apply (never).
	dir := t.TempDir() // a directory is not a regular file → ReadFile errors
	got, err := Load(dir)
	if err == nil {
		t.Error("unreadable status should surface an error, got nil")
	}
	if got != nil {
		t.Errorf("unreadable status should return nil report, got %+v", got)
	}
}

func TestBuildCarriesFirstSeenForward(t *testing.T) {
	prior := &Report{Conflicts: []Conflict{
		{Path: "/etc/core/old", Reason: "differs", FirstSeen: time.Unix(100, 0).UTC()},
	}}
	now := time.Unix(5000, 0).UTC()
	r := Build(now, ResultWithSkips,
		map[string]string{},
		[]Conflict{
			{Path: "/etc/core/old", Reason: "differs"}, // recurring → keep first_seen
			{Path: "/etc/core/new", Reason: "differs"}, // fresh → now
		}, nil, prior)

	seen := map[string]time.Time{}
	for _, c := range r.Conflicts {
		seen[c.Path] = c.FirstSeen
	}
	if !seen["/etc/core/old"].Equal(time.Unix(100, 0).UTC()) {
		t.Errorf("recurring conflict first_seen not carried forward: %v", seen["/etc/core/old"])
	}
	if !seen["/etc/core/new"].Equal(now) {
		t.Errorf("fresh conflict first_seen should be now: %v", seen["/etc/core/new"])
	}
	if r.LastApply != now || r.Result != ResultWithSkips || r.Version != CurrentVersion {
		t.Errorf("report header wrong: %+v", r)
	}
}

func TestBuildNilPriorStampsNow(t *testing.T) {
	now := time.Unix(7000, 0).UTC()
	r := Build(now, ResultOK, nil, []Conflict{{Path: "/x", Reason: "r"}}, nil, nil)
	if !r.Conflicts[0].FirstSeen.Equal(now) {
		t.Errorf("nil prior should stamp now, got %v", r.Conflicts[0].FirstSeen)
	}
	// nil maps/slices normalized so JSON emits {}/[] not null.
	if r.Units == nil || r.Errors == nil {
		t.Errorf("nil units/errors not normalized")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
