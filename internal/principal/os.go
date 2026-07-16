package principal

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/lazypower/magus-cli/internal/ir"
)

// nologinShell is the safe-default login shell for a created workload account.
const nologinShell = "/usr/sbin/nologin"

// OSReader observes principal state through getent / id. It is the production
// Reader; tests use a fake.
func OSReader() Reader { return osReader{} }

type osReader struct{}

func (osReader) LookupUser(name string) (ActualUser, error) {
	line, found, err := getent("passwd", name)
	if err != nil || !found {
		return ActualUser{Exists: false}, err
	}
	// name:x:uid:gid:gecos:home:shell
	f := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(f) < 7 {
		return ActualUser{}, fmt.Errorf("malformed passwd entry for %s: %q", name, line)
	}
	uid, err := strconv.Atoi(f[2])
	if err != nil {
		return ActualUser{}, fmt.Errorf("passwd uid for %s: %w", name, err)
	}
	gid, err := strconv.Atoi(f[3])
	if err != nil {
		return ActualUser{}, fmt.Errorf("passwd gid for %s: %w", name, err)
	}
	a := ActualUser{Exists: true, Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]}
	if pg, ok, err := groupNameByID(gid); err != nil {
		return ActualUser{}, err
	} else if ok {
		a.PrimaryGroup = pg
	}
	a.Groups = supplementaryGroups(name, a.PrimaryGroup)
	return a, nil
}

func (osReader) UserByID(uid int) (string, bool, error) {
	line, found, err := getent("passwd", strconv.Itoa(uid))
	if err != nil || !found {
		return "", false, err
	}
	name, _, _ := strings.Cut(line, ":")
	return name, true, nil
}

func (osReader) LookupGroup(name string) (int, bool, error) {
	line, found, err := getent("group", name)
	if err != nil || !found {
		return 0, false, err
	}
	f := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(f) < 3 {
		return 0, false, fmt.Errorf("malformed group entry for %s: %q", name, line)
	}
	gid, err := strconv.Atoi(f[2])
	if err != nil {
		return 0, false, fmt.Errorf("group gid for %s: %w", name, err)
	}
	return gid, true, nil
}

func (osReader) GroupByID(gid int) (string, bool, error) {
	line, found, err := getent("group", strconv.Itoa(gid))
	if err != nil || !found {
		return "", false, err
	}
	name, _, _ := strings.Cut(line, ":")
	return name, true, nil
}

// groupNameByID resolves a gid to its group name.
func groupNameByID(gid int) (string, bool, error) {
	line, found, err := getent("group", strconv.Itoa(gid))
	if err != nil || !found {
		return "", false, err
	}
	name, _, _ := strings.Cut(line, ":")
	return name, true, nil
}

// supplementaryGroups returns the user's group memberships minus the primary,
// via `id -nG`. Best-effort: on any error it returns nil (the diff then treats
// the user as holding no supplementary groups, which only ever under-counts and
// so never fabricates a spurious membership).
func supplementaryGroups(name, primary string) []string {
	out, err := exec.Command("id", "-nG", name).Output()
	if err != nil {
		return nil
	}
	var groups []string
	for _, g := range strings.Fields(string(out)) {
		if g != primary {
			groups = append(groups, g)
		}
	}
	return groups
}

// getent runs `getent <db> <key>`. It distinguishes three outcomes: found
// (line, true, nil), absent (getent exit 2 → "", false, nil), and a real
// failure ("", false, err) — so a missing principal is never confused with a
// broken lookup (fail-closed on the latter).
func getent(db, key string) (string, bool, error) {
	out, err := exec.Command("getent", db, key).Output()
	if err == nil {
		return string(out), true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 2 {
		return "", false, nil // key not found
	}
	return "", false, fmt.Errorf("getent %s %s: %w", db, key, err)
}

// OSExecutor mutates principals through useradd / usermod / groupadd as root.
func OSExecutor() Executor { return osExecutor{} }

type osExecutor struct{}

func (osExecutor) UserAdd(u ir.User, locked bool) error {
	args := []string{}
	if u.System {
		args = append(args, "--system")
	}
	if u.UID != nil {
		args = append(args, "-u", strconv.Itoa(*u.UID))
	}
	if u.PrimaryGroup != "" {
		args = append(args, "-g", u.PrimaryGroup)
	}
	if u.HomeDir != "" {
		args = append(args, "-d", u.HomeDir)
	}
	shell := u.Shell
	if shell == "" {
		shell = nologinShell
	}
	args = append(args, "-m", "-s", shell, u.Name)
	if err := run("useradd", args...); err != nil {
		return err
	}
	// useradd already leaves the account password-locked (no password set); make
	// it explicit so the safe-default is not an accident of shadow-utils config.
	if locked {
		if err := run("usermod", "-L", u.Name); err != nil {
			return err
		}
	}
	return nil
}

func (osExecutor) UserSetShell(name, shell string) error {
	return run("usermod", "-s", shell, name)
}

func (osExecutor) UserAddGroups(name string, groups []string) error {
	if len(groups) == 0 {
		return nil
	}
	return run("usermod", "-aG", strings.Join(groups, ","), name)
}

func (osExecutor) GroupAdd(g ir.Group) error {
	args := []string{}
	if g.System {
		args = append(args, "--system")
	}
	if g.GID != nil {
		args = append(args, "-g", strconv.Itoa(*g.GID))
	}
	args = append(args, g.Name)
	return run("groupadd", args...)
}

// run executes a shadow-utils command, folding stderr into the error so a
// failure is diagnosable.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return fmt.Errorf("%s: %w", name, err)
		}
		return fmt.Errorf("%s: %w: %s", name, err, msg)
	}
	return nil
}
