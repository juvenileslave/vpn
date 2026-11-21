package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Kind identifies how an upstream source locator is interpreted.
type Kind string

const (
	Subscription  Kind = "subscription"
	WireguardFile Kind = "wireguard_file"
)

// MaxDeclarationBytes is the maximum permitted size of a source declaration.
const MaxDeclarationBytes = 256 << 10

const (
	expectedSchema      = 1
	minSources          = 1
	maxSources          = 64
	minSlot             = 1
	maxSlot             = 63
	minInterval         = time.Minute
	maxInterval         = 24 * time.Hour
	maxLocatorBytes     = 4096
	maxFilterCountries  = 64
	minMaxLatency       = time.Millisecond
	maxMaxLatency       = 60 * time.Second
	minSuccessfulProbes = 1
	maxSuccessfulProbes = 16
	defaultMinProbes    = 1
)

var (
	ErrEmpty             = errors.New("empty declaration")
	ErrMultipleDocuments = errors.New("multiple YAML documents")

	idPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
)

// Problem describes a single validation failure at a field path.
type Problem struct {
	Path    string
	Message string
}

func (p Problem) String() string { return p.Path + ": " + p.Message }

// ValidationError collects all validation problems found in a declaration.
type ValidationError struct {
	Problems []Problem
}

func (e *ValidationError) Error() string {
	lines := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		lines[i] = p.String()
	}
	return strings.Join(lines, "\n")
}

// Filter restricts candidate nodes selected from an upstream source.
type Filter struct {
	Countries           []string
	MaxLatency          time.Duration // 0 = no bound
	MinSuccessfulProbes int           // >= 1
}

// Source is a validated upstream source declaration entry.
type Source struct {
	id          string
	kind        Kind
	slot        int
	interval    time.Duration
	enabled     bool
	filter      Filter
	locator     string
	fingerprint string
}

func (s Source) ID() string              { return s.id }
func (s Source) Kind() Kind              { return s.kind }
func (s Source) Slot() int               { return s.slot }
func (s Source) Interval() time.Duration { return s.interval }
func (s Source) Enabled() bool           { return s.enabled }
func (s Source) Locator() string         { return s.locator }
func (s Source) Fingerprint() string     { return s.fingerprint }

func (s Source) Filter() Filter {
	f := s.filter
	if len(s.filter.Countries) > 0 {
		f.Countries = append([]string(nil), s.filter.Countries...)
	}
	return f
}

func (s Source) String() string {
	return fmt.Sprintf("source.Source{id=%s kind=%s slot=%d redacted}", s.id, s.kind, s.slot)
}

func (s Source) GoString() string { return s.String() }

// Declaration is a validated upstream source declaration file.
type Declaration struct {
	Schema  int
	Sources []Source
}

func (d Declaration) String() string {
	return fmt.Sprintf("source.Declaration{schema=%d sources=%d redacted}", d.Schema, len(d.Sources))
}

func (d Declaration) GoString() string { return d.String() }

type rawDeclaration struct {
	Schema  *int        `yaml:"schema"`
	Sources []rawSource `yaml:"sources"`
}

type rawSource struct {
	ID              string     `yaml:"id"`
	Kind            string     `yaml:"kind"`
	Slot            *int       `yaml:"slot"`
	Interval        string     `yaml:"interval"`
	Enabled         *bool      `yaml:"enabled"`
	SubscriptionURL *string    `yaml:"subscription_url"`
	WireguardPath   *string    `yaml:"wireguard_path"`
	Filter          *rawFilter `yaml:"filter"`
}

type rawFilter struct {
	Countries           []string `yaml:"countries"`
	MaxLatency          *string  `yaml:"max_latency"`
	MinSuccessfulProbes *int     `yaml:"min_successful_probes"`
}

// Load reads and validates a 0600 regular declaration file and its wireguard_file locators.
func Load(path string) (*Declaration, error) {
	if path == "" || hasControlChar(path) || !filepath.IsAbs(path) {
		return nil, errors.New("load declaration: path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("load declaration: %s", statErrorReason(err))
	}
	if reason := checkPrivateRegularFile(info); reason != "" {
		return nil, fmt.Errorf("load declaration: %s", reason)
	}
	if info.Size() > MaxDeclarationBytes {
		return nil, fmt.Errorf("load declaration: size exceeds %d bytes", MaxDeclarationBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("load declaration: %s", statErrorReason(err))
	}
	defer f.Close()

	finfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("load declaration: %s", statErrorReason(err))
	}
	if !os.SameFile(info, finfo) {
		return nil, errors.New("load declaration: file changed while opening")
	}
	if reason := checkPrivateRegularFile(finfo); reason != "" {
		return nil, fmt.Errorf("load declaration: %s", reason)
	}

	data, err := io.ReadAll(io.LimitReader(f, MaxDeclarationBytes+1))
	if err != nil {
		return nil, errors.New("load declaration: read failed")
	}
	if len(data) > MaxDeclarationBytes {
		return nil, fmt.Errorf("load declaration: size exceeds %d bytes", MaxDeclarationBytes)
	}

	decl, err := Parse(data)
	if err != nil {
		return nil, err
	}

	var problems []Problem
	for i, src := range decl.Sources {
		if src.kind != WireguardFile {
			continue
		}
		wPath := fmt.Sprintf("sources[%d].wireguard_path", i)
		winfo, err := os.Lstat(src.locator)
		if err != nil {
			problems = append(problems, Problem{Path: wPath, Message: statErrorReason(err)})
			continue
		}
		if reason := checkPrivateRegularFile(winfo); reason != "" {
			problems = append(problems, Problem{Path: wPath, Message: reason})
		}
	}
	if len(problems) > 0 {
		return nil, &ValidationError{Problems: problems}
	}
	return decl, nil
}

// Parse strictly decodes and validates a YAML upstream source declaration.
func Parse(data []byte) (*Declaration, error) {
	if len(data) > MaxDeclarationBytes {
		return nil, fmt.Errorf("parse declaration: input exceeds %d bytes", MaxDeclarationBytes)
	}
	raw, err := decode(data)
	if err != nil {
		return nil, err
	}
	return validate(raw)
}

func decode(data []byte) (rawDeclaration, error) {
	var raw rawDeclaration
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return rawDeclaration{}, ErrEmpty
		}
		return rawDeclaration{}, fmt.Errorf("parse declaration: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return rawDeclaration{}, ErrMultipleDocuments
	}
	return raw, nil
}

func validate(raw rawDeclaration) (*Declaration, error) {
	var problems []Problem

	if raw.Schema == nil {
		problems = append(problems, Problem{Path: "schema", Message: "required"})
	} else if *raw.Schema != expectedSchema {
		problems = append(problems, Problem{Path: "schema", Message: "must be 1"})
	}

	if len(raw.Sources) < minSources || len(raw.Sources) > maxSources {
		problems = append(problems, Problem{
			Path:    "sources",
			Message: fmt.Sprintf("must contain between %d and %d entries", minSources, maxSources),
		})
	}

	seenIDs := make(map[string]struct{}, len(raw.Sources))
	sources := make([]Source, 0, len(raw.Sources))
	for i, rs := range raw.Sources {
		prefix := fmt.Sprintf("sources[%d]", i)

		switch {
		case rs.ID == "":
			problems = append(problems, Problem{Path: prefix + ".id", Message: "required"})
		case !idPattern.MatchString(rs.ID):
			problems = append(problems, Problem{Path: prefix + ".id", Message: fmt.Sprintf("must match %s", idPattern)})
		default:
			if _, dup := seenIDs[rs.ID]; dup {
				problems = append(problems, Problem{Path: prefix + ".id", Message: "duplicate source id"})
			} else {
				seenIDs[rs.ID] = struct{}{}
			}
		}

		kind := Kind(rs.Kind)
		kindValid := false
		switch {
		case rs.Kind == "":
			problems = append(problems, Problem{Path: prefix + ".kind", Message: "required"})
		case kind != Subscription && kind != WireguardFile:
			problems = append(problems, Problem{Path: prefix + ".kind", Message: "must be subscription or wireguard_file"})
		default:
			kindValid = true
		}

		var slot int
		switch {
		case rs.Slot == nil:
			problems = append(problems, Problem{Path: prefix + ".slot", Message: "required"})
		case *rs.Slot < minSlot || *rs.Slot > maxSlot:
			problems = append(problems, Problem{Path: prefix + ".slot", Message: fmt.Sprintf("must be between %d and %d", minSlot, maxSlot)})
		default:
			slot = *rs.Slot
		}

		var interval time.Duration
		if rs.Interval == "" {
			problems = append(problems, Problem{Path: prefix + ".interval", Message: "required"})
		} else {
			d, err := time.ParseDuration(rs.Interval)
			switch {
			case err != nil:
				problems = append(problems, Problem{Path: prefix + ".interval", Message: "must be a valid Go duration"})
			case d < minInterval || d > maxInterval:
				problems = append(problems, Problem{Path: prefix + ".interval", Message: "must be between 1m and 24h"})
			default:
				interval = d
			}
		}

		enabled := true
		if rs.Enabled != nil {
			enabled = *rs.Enabled
		}

		var locator string
		if kindValid {
			switch kind {
			case Subscription:
				if rs.WireguardPath != nil {
					problems = append(problems, Problem{Path: prefix + ".wireguard_path", Message: "not allowed for subscription source"})
				}
				if rs.SubscriptionURL == nil {
					problems = append(problems, Problem{Path: prefix + ".subscription_url", Message: "required for subscription source"})
				} else {
					validateSubscriptionURL(prefix+".subscription_url", *rs.SubscriptionURL, &problems)
					locator = *rs.SubscriptionURL
				}
			case WireguardFile:
				if rs.SubscriptionURL != nil {
					problems = append(problems, Problem{Path: prefix + ".subscription_url", Message: "not allowed for wireguard_file source"})
				}
				if rs.WireguardPath == nil {
					problems = append(problems, Problem{Path: prefix + ".wireguard_path", Message: "required for wireguard_file source"})
				} else {
					validateWireguardPath(prefix+".wireguard_path", *rs.WireguardPath, &problems)
					locator = *rs.WireguardPath
				}
			}
		} else if rs.SubscriptionURL != nil && rs.WireguardPath != nil {
			problems = append(problems, Problem{Path: prefix, Message: "must specify only one locator"})
		}

		filter := validateFilter(prefix+".filter", rs.Filter, &problems)
		sources = append(sources, Source{
			id:          rs.ID,
			kind:        kind,
			slot:        slot,
			interval:    interval,
			enabled:     enabled,
			filter:      filter,
			locator:     locator,
			fingerprint: computeFingerprint(kind, locator),
		})
	}

	if len(problems) > 0 {
		return nil, &ValidationError{Problems: problems}
	}
	return &Declaration{
		Schema:  *raw.Schema,
		Sources: sources,
	}, nil
}

func validateSubscriptionURL(path, raw string, problems *[]Problem) {
	if raw == "" {
		*problems = append(*problems, Problem{Path: path, Message: "required for subscription source"})
		return
	}
	if len(raw) > maxLocatorBytes {
		*problems = append(*problems, Problem{Path: path, Message: fmt.Sprintf("must be at most %d bytes", maxLocatorBytes)})
		return
	}
	if hasControlChar(raw) {
		*problems = append(*problems, Problem{Path: path, Message: "must not contain control characters"})
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		*problems = append(*problems, Problem{Path: path, Message: "must be a valid https URL"})
		return
	}
	if !u.IsAbs() || u.Scheme != "https" || u.Opaque != "" {
		*problems = append(*problems, Problem{Path: path, Message: "must be an absolute https URL"})
	}
	if u.Hostname() == "" {
		*problems = append(*problems, Problem{Path: path, Message: "must include a non-empty host"})
	}
	if u.User != nil {
		*problems = append(*problems, Problem{Path: path, Message: "must not include userinfo"})
	}
}

func validateWireguardPath(path, raw string, problems *[]Problem) {
	if raw == "" {
		*problems = append(*problems, Problem{Path: path, Message: "required for wireguard_file source"})
		return
	}
	if len(raw) > maxLocatorBytes {
		*problems = append(*problems, Problem{Path: path, Message: fmt.Sprintf("must be at most %d bytes", maxLocatorBytes)})
	}
	if hasControlChar(raw) {
		*problems = append(*problems, Problem{Path: path, Message: "must not contain control characters"})
	}
	if !filepath.IsAbs(raw) {
		*problems = append(*problems, Problem{Path: path, Message: "must be an absolute path"})
	}
}

func validateFilter(path string, rf *rawFilter, problems *[]Problem) Filter {
	f := Filter{
		MinSuccessfulProbes: defaultMinProbes,
	}
	if rf == nil {
		return f
	}
	if len(rf.Countries) > maxFilterCountries {
		*problems = append(*problems, Problem{
			Path:    path + ".countries",
			Message: fmt.Sprintf("must contain at most %d entries", maxFilterCountries),
		})
	}
	if len(rf.Countries) > 0 {
		seen := make(map[string]struct{}, len(rf.Countries))
		countries := make([]string, 0, len(rf.Countries))
		for j, code := range rf.Countries {
			cPath := fmt.Sprintf("%s.countries[%d]", path, j)
			if !isCountryCode(code) {
				*problems = append(*problems, Problem{
					Path:    cPath,
					Message: "must be two uppercase ASCII letters",
				})
				continue
			}
			if _, dup := seen[code]; dup {
				*problems = append(*problems, Problem{
					Path:    cPath,
					Message: "duplicate country code",
				})
				continue
			}
			seen[code] = struct{}{}
			countries = append(countries, code)
		}
		if len(countries) > 0 {
			f.Countries = countries
		}
	}
	if rf.MaxLatency != nil {
		d, err := time.ParseDuration(*rf.MaxLatency)
		switch {
		case err != nil:
			*problems = append(*problems, Problem{
				Path:    path + ".max_latency",
				Message: "must be a valid Go duration",
			})
		case d < minMaxLatency || d > maxMaxLatency:
			*problems = append(*problems, Problem{
				Path:    path + ".max_latency",
				Message: "must be between 1ms and 60s",
			})
		default:
			f.MaxLatency = d
		}
	}
	if rf.MinSuccessfulProbes != nil {
		n := *rf.MinSuccessfulProbes
		if n < minSuccessfulProbes || n > maxSuccessfulProbes {
			*problems = append(*problems, Problem{
				Path:    path + ".min_successful_probes",
				Message: "must be between 1 and 16",
			})
		} else {
			f.MinSuccessfulProbes = n
		}
	}
	return f
}

func computeFingerprint(kind Kind, locator string) string {
	h := sha256.New()
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(locator))
	return hex.EncodeToString(h.Sum(nil))
}

func isCountryCode(s string) bool {
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func statErrorReason(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "file does not exist"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	default:
		return "cannot access file"
	}
}

func checkPrivateRegularFile(info fs.FileInfo) string {
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return "must not be a symlink"
	}
	if !mode.IsRegular() {
		return "must be a regular file"
	}
	if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return "must not have special mode bits"
	}
	if mode.Perm() != 0o600 {
		return fmt.Sprintf("mode must be 0600, got %04o", mode.Perm())
	}
	return ""
}
