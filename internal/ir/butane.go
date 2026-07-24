package ir

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	butane "github.com/coreos/butane/config"
	"github.com/coreos/butane/config/common"
	"github.com/coreos/vcontext/report"
)

// maxButaneSize caps fetched Butane bodies at 10 MB. A magus Butane file is
// typically a few KB to low-tens-of-KB; 10 MB is a runaway-upstream guard,
// not a soft target. Past this we stop reading and surface an error rather
// than blow up memory on a wrong URL pointing at a binary download.
const maxButaneSize = 10 * 1024 * 1024

// fetchTimeout bounds HTTP reads. Picked so a slow link doesn't stall apply
// indefinitely, but long enough that a transient blip doesn't kill a real run.
const fetchTimeout = 30 * time.Second

// readButaneSource dispatches on source scheme: local file otherwise.
//
// Plain-HTTP sources are refused unless allowInsecureHTTP is set: a
// root-privileged process that fetches its desired state over http:// and
// applies it is a remote-code-execution primitive for an on-path attacker (they
// can substitute a unit file that magus then starts). https is required by
// default; --insecure-http is the explicit opt-out (D19).
func readButaneSource(source string, allowInsecureHTTP bool) ([]byte, error) {
	if isHTTPURL(source) {
		if strings.HasPrefix(source, "http://") && !allowInsecureHTTP {
			return nil, fmt.Errorf("refusing to fetch Butane over plain HTTP (%s): an on-path attacker could substitute a unit magus runs as root — use https, or pass --insecure-http to override", source)
		}
		return fetchButaneHTTP(source, allowInsecureHTTP)
	}
	return readLocalButane(source)
}

func readLocalButane(source string) ([]byte, error) {
	f, err := os.Open(source)
	if err != nil {
		return nil, fmt.Errorf("read butane: %w", err)
	}
	defer f.Close()
	// Same 10 MB guard as the HTTP path (D20): read one byte past the cap to
	// detect an oversize file rather than silently truncating.
	data, err := io.ReadAll(io.LimitReader(f, maxButaneSize+1))
	if err != nil {
		return nil, fmt.Errorf("read butane: %w", err)
	}
	if int64(len(data)) > maxButaneSize {
		return nil, fmt.Errorf("read butane %s: file exceeds %d bytes", source, maxButaneSize)
	}
	return data, nil
}

func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// rejectInsecureRedirect is the http.Client CheckRedirect that closes the
// redirect hole in the https gate: an https:// source that 302s to http:// would
// otherwise fetch over plain HTTP with no flag, reintroducing the on-path
// substitution risk. It refuses any redirect that downgrades to http (unless
// --insecure-http) and caps the chain length.
func rejectInsecureRedirect(allowInsecureHTTP bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme == "http" && !allowInsecureHTTP {
			return fmt.Errorf("refusing redirect to plain HTTP (%s): use https, or pass --insecure-http", req.URL)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
}

func fetchButaneHTTP(rawurl string, allowInsecureHTTP bool) ([]byte, error) {
	client := &http.Client{
		Timeout:       fetchTimeout,
		CheckRedirect: rejectInsecureRedirect(allowInsecureHTTP),
	}
	resp, err := client.Get(rawurl)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", rawurl, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d %s", rawurl, resp.StatusCode, resp.Status)
	}
	// LimitReader+1 trick: read one byte past the cap so we can detect when
	// the upstream had more to give and surface a clear error rather than
	// silently truncating.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxButaneSize+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: read body: %w", rawurl, err)
	}
	if int64(len(body)) > maxButaneSize {
		return nil, fmt.Errorf("fetch %s: body exceeds %d bytes — refusing to read further", rawurl, maxButaneSize)
	}
	return body, nil
}

// quadletRoot is the canonical search path the systemd-quadlet generator
// uses for operator-supplied quadlets. /usr/share/containers/systemd is the
// image-baked location and is read-only on bootc — we don't manage it.
const quadletRoot = "/etc/containers/systemd/"

// quadletExtensions are the v1-supported quadlet types. .pod, .kube, .image,
// and .build are deferred — they have different generated-service-name
// mappings and aren't on the immediate use case.
var quadletExtensions = []string{".container", ".volume", ".network"}

// deferredQuadletExtensions are quadlet types systemd-quadlet recognizes but
// magus does not support in v1. They MUST be rejected (not silently treated as
// ordinary files): a file at /etc/containers/systemd/x.kube would be processed
// by the generator at daemon-reload and could materialize a service magus never
// got to gate against deny.units. Refusing at load keeps the authority boundary
// honest.
var deferredQuadletExtensions = []string{".pod", ".kube", ".image", ".build"}

// hasQuadletExt reports whether path carries a v1-supported quadlet extension
// (location-agnostic; callers combine it with a root-prefix check).
func hasQuadletExt(path string) bool {
	ext := filepath.Ext(path)
	for _, q := range quadletExtensions {
		if ext == q {
			return true
		}
	}
	return false
}

func isQuadletPath(path string) bool {
	return strings.HasPrefix(path, quadletRoot) && hasQuadletExt(path)
}

// userQuadletSubdir is the per-principal quadlet root, relative to the home dir:
// systemd-quadlet's user generator scans <home>/.config/containers/systemd/.
const userQuadletSubdir = ".config/containers/systemd/"

// userQuadletRoot returns the absolute quadlet root for a principal's home
// (empty home → empty, so an undeclared home derives no user scope).
func userQuadletRoot(home string) string {
	if home == "" {
		return ""
	}
	return filepath.Clean(home) + "/" + userQuadletSubdir
}

// deferredQuadletType returns the deferred quadlet extension if path is a
// not-yet-supported quadlet under any quadlet root (system or user), else "".
// The user generator processes a deferred type under a home just as the system
// one does, so both must be refused at load to keep the authority boundary honest.
func deferredQuadletType(path string, userRoots []userRoot) string {
	underRoot := strings.HasPrefix(path, quadletRoot)
	for _, r := range userRoots {
		if strings.HasPrefix(path, r.prefix) {
			underRoot = true
			break
		}
	}
	if !underRoot {
		return ""
	}
	ext := filepath.Ext(path)
	for _, q := range deferredQuadletExtensions {
		if ext == q {
			return ext
		}
	}
	return ""
}

// userRoot binds a declared principal's quadlet root prefix to its name, so a
// quadlet under that prefix is promoted to a user-scoped Quadlet owned by name.
type userRoot struct {
	name   string
	prefix string
}

// userQuadletOwner returns the owning principal if path is a supported quadlet
// under one of userRoots, matching the longest (most specific) prefix so nested
// homes cannot mis-attribute. ok is false for a non-quadlet or a path under no
// declared home.
func userQuadletOwner(path string, userRoots []userRoot) (owner string, ok bool) {
	if !hasQuadletExt(path) {
		return "", false
	}
	best := ""
	for _, r := range userRoots {
		if strings.HasPrefix(path, r.prefix) && len(r.prefix) > len(best) {
			owner, best = r.name, r.prefix
		}
	}
	return owner, best != ""
}

// LoadButane reads source, runs the Butane → Ignition translation, and
// extracts the magus IR subset from the resulting Ignition spec.
//
// source may be a local filesystem path or an http(s) URL. URLs are fetched
// on every call — there is no local cache and no fallback to a last-known-good
// IR. The reconciler-pattern guarantee is "what apply runs against is what
// the operator currently declared," and silently applying a cached copy
// after a fetch failure would break that.
//
// Translation warnings (non-fatal) are returned in warnings; translation
// errors are returned as the error.
//
// allowInsecureHTTP relaxes the https-by-default rule for remote sources — see
// readButaneSource. Local sources ignore it.
func LoadButane(source string, allowInsecureHTTP bool) (*IR, []string, error) {
	data, err := readButaneSource(source, allowInsecureHTTP)
	if err != nil {
		return nil, nil, err
	}
	ignBytes, report, err := butane.TranslateBytes(data, common.TranslateBytesOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("translate butane %s: %w", source, err)
	}
	warnings := collectWarnings(report)

	var ign ignitionSubset
	if err := json.Unmarshal(ignBytes, &ign); err != nil {
		return nil, warnings, fmt.Errorf("parse ignition output: %w", err)
	}

	out := &IR{}

	// Derive each declared principal's quadlet root up front: a quadlet under a
	// principal's <home>/.config/containers/systemd/ is a *user*-scoped workload
	// owned by that principal (ADR-0003 path-derived scope). Scope is a physical
	// fact of location; whether magus reconciles the owner is a downstream policy
	// decision (manage_users), exactly as with the principal itself.
	var userRoots []userRoot
	for _, u := range ign.Passwd.Users {
		if root := userQuadletRoot(derefString(u.HomeDir)); root != "" {
			userRoots = append(userRoots, userRoot{name: u.Name, prefix: root})
		}
	}

	for _, f := range ign.Storage.Files {
		contents, err := decodeSource(f.Contents.Source, f.Contents.Compression)
		if err != nil {
			return nil, warnings, fmt.Errorf("file %s: %w", f.Path, err)
		}
		// Reject deferred quadlet types under the quadlet root before anything
		// else: the generator would act on them but magus can't gate their
		// generated service in v1.
		if dt := deferredQuadletType(f.Path, userRoots); dt != "" {
			return nil, warnings, fmt.Errorf("file %s: quadlet type %q is not supported in v1 (deferred) but systemd-quadlet would still process it — remove it from the quadlet root", f.Path, dt)
		}
		// Auto-promote quadlet-shaped files: anything under
		// /etc/containers/systemd/ with a recognized quadlet extension
		// becomes a Quadlet rather than a plain File. The systemd-quadlet
		// generator only scans this path, so detection by location is
		// authoritative — a file at /etc/magus.d/foo.container is not a
		// quadlet to systemd, and it shouldn't be one to magus either.
		if isQuadletPath(f.Path) {
			out.Quadlets = append(out.Quadlets, Quadlet{
				Path:     f.Path,
				Name:     filepath.Base(f.Path),
				Mode:     f.Mode.value(0644),
				UID:      f.User.ID.v,
				GID:      f.Group.ID.v,
				Contents: contents,
				Scope:    ScopeSystem,
			})
			continue
		}
		// The same promotion, one scope down: a quadlet under a declared
		// principal's home is that principal's rootless workload. The user
		// generator materializes its .service under the owner's user manager, so
		// magus must see it as a Quadlet (owner-attributed) to gate and order it —
		// not as an opaque file (the argus.bu isolated-node gap ADR-0003 names).
		if owner, ok := userQuadletOwner(f.Path, userRoots); ok {
			out.Quadlets = append(out.Quadlets, Quadlet{
				Path:     f.Path,
				Name:     filepath.Base(f.Path),
				Mode:     f.Mode.value(0644),
				UID:      f.User.ID.v,
				GID:      f.Group.ID.v,
				Contents: contents,
				Scope:    ScopeUser,
				Owner:    owner,
			})
			continue
		}
		out.Files = append(out.Files, File{
			Path:     f.Path,
			Mode:     f.Mode.value(0644),
			UID:      f.User.ID.v,
			GID:      f.Group.ID.v,
			Contents: contents,
		})
	}

	for _, d := range ign.Storage.Directories {
		out.Directories = append(out.Directories, Directory{
			Path: d.Path,
			Mode: d.Mode.value(0755),
			UID:  d.User.ID.v,
			GID:  d.Group.ID.v,
		})
	}

	for _, u := range ign.Systemd.Units {
		// Reject mask up front rather than silently dropping it. Masking is a
		// security-relevant declaration ("this unit must not run"); magus does
		// not reconcile mask state in v1, and honoring it partially — or
		// ignoring it while the operator believes it took effect — is worse
		// than refusing. This mirrors how deferred quadlet types are rejected
		// at load: the authority boundary stays honest.
		if u.Mask != nil && *u.Mask {
			return nil, warnings, fmt.Errorf("unit %s: mask is not supported in v1 — magus does not reconcile masked state; remove \"mask\" or mask the unit out of band", u.Name)
		}
		unit := Unit{
			Name: u.Name,
			// Preserve the tri-state directly: nil means "enablement not
			// declared, don't touch it" — see ir.Unit.Enabled.
			Enabled:  u.Enabled,
			Contents: derefString(u.Contents),
		}
		for _, di := range u.Dropins {
			unit.DropIns = append(unit.DropIns, DropIn{
				Name:     di.Name,
				Contents: derefString(di.Contents),
			})
		}
		out.Units = append(out.Units, unit)
	}

	// Principals (passwd.users / passwd.groups). Unlike the storage/systemd
	// sections these are carried into the IR verbatim; whether magus reconciles a
	// given principal is a policy decision (manage_users) resolved downstream, not
	// a parse-time one. An unmanaged principal (e.g. Ignition's `core`) stays
	// Ignition's concern and is simply never acted on.
	for _, u := range ign.Passwd.Users {
		out.Users = append(out.Users, User{
			Name:         u.Name,
			UID:          u.UID.v,
			PrimaryGroup: derefString(u.PrimaryGroup),
			Groups:       u.Groups,
			Shell:        derefString(u.Shell),
			HomeDir:      derefString(u.HomeDir),
			System:       u.System != nil && *u.System,
			HasPassword:  u.PasswordHash != nil && *u.PasswordHash != "",
			HasSSHKeys:   len(u.SSHAuthorizedKeys) > 0,
		})
	}
	for _, g := range ign.Passwd.Groups {
		out.Groups = append(out.Groups, Group{
			Name:   g.Name,
			GID:    g.GID.v,
			System: g.System != nil && *g.System,
		})
	}

	return out, warnings, nil
}

func collectWarnings(r report.Report) []string {
	if len(r.Entries) == 0 {
		return nil
	}
	var out []string
	for _, e := range r.Entries {
		out = append(out, e.String())
	}
	return out
}

// ignitionSubset is the slice of the Ignition spec magus consumes. Fields not
// listed here are silently ignored — that's the IR contract: anything outside
// this subset belongs to a different consumer (Ignition itself).
type ignitionSubset struct {
	Storage struct {
		Files       []ignFile      `json:"files"`
		Directories []ignDirectory `json:"directories"`
	} `json:"storage"`
	Systemd struct {
		Units []ignUnit `json:"units"`
	} `json:"systemd"`
	Passwd struct {
		Users  []ignUser  `json:"users"`
		Groups []ignGroup `json:"groups"`
	} `json:"passwd"`
}

// ignUser mirrors the Ignition passwd.users schema. Only the v1 consumed subset
// is unmarshalled; passwordHash and sshAuthorizedKeys are parsed solely so a
// managed principal declaring them can be refused at validate (deferred in v1).
type ignUser struct {
	Name              string   `json:"name"`
	UID               intPtr   `json:"uid"`
	PrimaryGroup      *string  `json:"primaryGroup"`
	Groups            []string `json:"groups"`
	Shell             *string  `json:"shell"`
	HomeDir           *string  `json:"homeDir"`
	System            *bool    `json:"system"`
	PasswordHash      *string  `json:"passwordHash"`
	SSHAuthorizedKeys []string `json:"sshAuthorizedKeys"`
}

type ignGroup struct {
	Name   string `json:"name"`
	GID    intPtr `json:"gid"`
	System *bool  `json:"system"`
}

type ignFile struct {
	Path     string       `json:"path"`
	Mode     intPtr       `json:"mode"`
	User     ignNodeOwner `json:"user"`
	Group    ignNodeOwner `json:"group"`
	Contents struct {
		Source      string `json:"source"`
		Compression string `json:"compression"`
	} `json:"contents"`
}

type ignDirectory struct {
	Path  string       `json:"path"`
	Mode  intPtr       `json:"mode"`
	User  ignNodeOwner `json:"user"`
	Group ignNodeOwner `json:"group"`
}

type ignNodeOwner struct {
	ID intPtr `json:"id"`
}

type ignUnit struct {
	Name     string      `json:"name"`
	Enabled  *bool       `json:"enabled"`
	Mask     *bool       `json:"mask"`
	Contents *string     `json:"contents"`
	Dropins  []ignDropin `json:"dropins"`
}

type ignDropin struct {
	Name     string  `json:"name"`
	Contents *string `json:"contents"`
}

// intPtr is a *int that survives JSON's null-vs-missing distinction with a
// helpful default accessor.
type intPtr struct {
	v *int
}

func (p *intPtr) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	p.v = &n
	return nil
}

func (p intPtr) value(def int) uint32 {
	if p.v == nil {
		return uint32(def)
	}
	return uint32(*p.v)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// decodeSource decodes an Ignition contents.source URL into raw bytes. v1
// supports the inline forms — data: URLs, both percent-encoded and base64.
// Remote sources (http, https, s3, etc.) are not supported in the IR; magus
// reconciles content it can resolve at parse time.
//
// compression is the Ignition contents.compression field. Butane's translator
// auto-gzips file payloads, so a missing decompress step writes gzipped bytes
// to disk. Empty and "gzip" are accepted; anything else is an error.
func decodeSource(src, compression string) ([]byte, error) {
	if src == "" {
		return nil, nil
	}
	if !strings.HasPrefix(src, "data:") {
		return nil, fmt.Errorf("contents.source: only data: URLs are supported, got %q", schemeOf(src))
	}
	body := strings.TrimPrefix(src, "data:")
	comma := strings.IndexByte(body, ',')
	if comma < 0 {
		return nil, fmt.Errorf("contents.source: malformed data URL")
	}
	meta, payload := body[:comma], body[comma+1:]
	isBase64 := false
	for _, part := range strings.Split(meta, ";") {
		if part == "base64" {
			isBase64 = true
			break
		}
	}
	var raw []byte
	if isBase64 {
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, err
		}
		raw = decoded
	} else {
		// PathUnescape, not QueryUnescape: RFC 2397 data URLs are not query
		// strings, and QueryUnescape turns a literal '+' into a space. Any
		// producer that emits a literal '+' (RFC 2397 permits it) would be
		// silently corrupted otherwise (D18).
		decoded, err := url.PathUnescape(payload)
		if err != nil {
			return nil, fmt.Errorf("contents.source: %w", err)
		}
		raw = []byte(decoded)
	}
	switch compression {
	case "":
		return raw, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("contents.compression=gzip: %w", err)
		}
		defer zr.Close()
		return io.ReadAll(zr)
	default:
		return nil, fmt.Errorf("contents.compression: unsupported %q", compression)
	}
}

func schemeOf(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}
