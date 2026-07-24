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
// Reader; the getent and idGroups seams are injectable so the parsing logic is
// unit-tested without a live host.
func OSReader() Reader {
	return osReader{lookup: getent, idGroups: idGroups}
}

type osReader struct {
	lookup   func(db, key string) (string, bool, error)
	idGroups func(name string) ([]string, error)
}

func (r osReader) LookupUser(name string) (ActualUser, error) {
	line, found, err := r.lookup("passwd", name)
	if err != nil || !found {
		return ActualUser{Exists: false}, err
	}
	a, err := parsePasswdEntry(line)
	if err != nil {
		return ActualUser{}, err
	}
	if pg, ok, err := r.groupName(a.GID); err != nil {
		return ActualUser{}, err
	} else if ok {
		a.PrimaryGroup = pg
	}
	// Fail closed: a supplementary-group read that errors (NSS/SSSD/LDAP
	// transient, `id` unavailable) must NOT look like "member of no groups" —
	// that would let adoption silently absorb an existing privileged membership
	// (e.g. wheel) the create path would have refused. Halt instead of guessing.
	all, err := r.idGroups(name)
	if err != nil {
		return ActualUser{}, fmt.Errorf("read supplementary groups for %s: %w", name, err)
	}
	a.Groups = filterPrimary(all, a.PrimaryGroup)
	return a, nil
}

func (r osReader) UserByID(uid int) (string, bool, error) {
	line, found, err := r.lookup("passwd", strconv.Itoa(uid))
	if err != nil || !found {
		return "", false, err
	}
	return firstField(line), true, nil
}

func (r osReader) LookupGroup(name string) (int, bool, error) {
	line, found, err := r.lookup("group", name)
	if err != nil || !found {
		return 0, false, err
	}
	gid, err := parseGroupGID(line)
	return gid, err == nil, err
}

func (r osReader) GroupByID(gid int) (string, bool, error) {
	line, found, err := r.lookup("group", strconv.Itoa(gid))
	if err != nil || !found {
		return "", false, err
	}
	return firstField(line), true, nil
}

// groupName resolves a gid to its group name via the same getent seam.
func (r osReader) groupName(gid int) (string, bool, error) {
	line, found, err := r.lookup("group", strconv.Itoa(gid))
	if err != nil || !found {
		return "", false, err
	}
	return firstField(line), true, nil
}

// --- pure parsing (unit-tested directly) --------------------------------------

// parsePasswdEntry parses a getent passwd line (name:x:uid:gid:gecos:home:shell)
// into the base ActualUser fields (group names are resolved separately).
func parsePasswdEntry(line string) (ActualUser, error) {
	f := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(f) < 7 {
		return ActualUser{}, fmt.Errorf("malformed passwd entry: %q", line)
	}
	uid, err := strconv.Atoi(f[2])
	if err != nil {
		return ActualUser{}, fmt.Errorf("passwd uid %q: %w", f[2], err)
	}
	gid, err := strconv.Atoi(f[3])
	if err != nil {
		return ActualUser{}, fmt.Errorf("passwd gid %q: %w", f[3], err)
	}
	return ActualUser{Exists: true, Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]}, nil
}

// parseGroupGID parses the gid from a getent group line (name:x:gid:members).
func parseGroupGID(line string) (int, error) {
	f := strings.Split(strings.TrimRight(line, "\n"), ":")
	if len(f) < 3 {
		return 0, fmt.Errorf("malformed group entry: %q", line)
	}
	gid, err := strconv.Atoi(f[2])
	if err != nil {
		return 0, fmt.Errorf("group gid %q: %w", f[2], err)
	}
	return gid, nil
}

// firstField returns the first colon-separated field (the name) of a getent line.
func firstField(line string) string {
	name, _, _ := strings.Cut(line, ":")
	return name
}

// filterPrimary drops the primary group from the full group list, leaving the
// supplementary set.
func filterPrimary(all []string, primary string) []string {
	var out []string
	for _, g := range all {
		if g != primary {
			out = append(out, g)
		}
	}
	return out
}

// --- host exec seams (thin; behavior above is what's tested) ------------------

// getent runs `getent <db> <key>`, distinguishing found / absent (exit 2) /
// failure so a missing principal is never confused with a broken lookup.
func getent(db, key string) (string, bool, error) {
	out, err := exec.Command("getent", db, key).Output()
	if err == nil {
		return string(out), true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 2 {
		return "", false, nil
	}
	return "", false, fmt.Errorf("getent %s %s: %w", db, key, err)
}

// idGroups returns every group name a user belongs to (`id -nG`); best-effort.
func idGroups(name string) ([]string, error) {
	out, err := exec.Command("id", "-nG", name).Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// OSExecutor mutates principals through useradd / usermod / groupadd as root.
// The run seam is injectable so argv construction is unit-tested.
func OSExecutor() Executor { return osExecutor{run: runCmd} }

type osExecutor struct {
	run func(name string, args ...string) error
}

func (e osExecutor) UserAdd(u ir.User, locked bool) error {
	if err := e.run("useradd", userAddArgs(u)...); err != nil {
		return err
	}
	// useradd already leaves the account password-locked; make it explicit so
	// the safe default is not an accident of shadow-utils config.
	if locked {
		return e.run("usermod", "-L", u.Name)
	}
	return nil
}

func (e osExecutor) UserSetShell(name, shell string) error {
	return e.run("usermod", "-s", shell, name)
}

func (e osExecutor) UserAddGroups(name string, groups []string) error {
	if len(groups) == 0 {
		return nil
	}
	return e.run("usermod", "-aG", strings.Join(groups, ","), name)
}

func (e osExecutor) GroupAdd(g ir.Group) error {
	return e.run("groupadd", groupAddArgs(g)...)
}

// userAddArgs builds the useradd argv for u, applying the safe-default nologin
// shell when none is declared. Pure — unit-tested.
func userAddArgs(u ir.User) []string {
	var args []string
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
	return append(args, "-m", "-s", shell, u.Name)
}

// groupAddArgs builds the groupadd argv for g. Pure — unit-tested.
func groupAddArgs(g ir.Group) []string {
	var args []string
	if g.System {
		args = append(args, "--system")
	}
	if g.GID != nil {
		args = append(args, "-g", strconv.Itoa(*g.GID))
	}
	return append(args, g.Name)
}

// runCmd executes a shadow-utils command, folding stderr into the error so a
// failure is diagnosable.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
