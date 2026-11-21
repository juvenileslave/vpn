package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/store"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/source"
)

const (
	defaultUpstreamVersionLimit = 20
	maxUpstreamVersionLimit     = 1000
	minUpstreamSlot             = 1
	maxUpstreamSlot             = 63
	shortVersionIDLen           = 12
)

// Refusal messages returned before any file, database or network I/O.
const (
	refreshRefusal  = "upstream refresh refused: publishing is not authorized; no I/O performed"
	rollbackRefusal = "upstream rollback refused: store-only rollback is not a panel rollback; no I/O performed"
	slotSetRefusal  = "slot set refused: upstream publishing is not authorized; no I/O performed"
)

type upstreamSourceView struct {
	Slot          int    `json:"slot"`
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Interval      string `json:"interval"`
	Enabled       bool   `json:"enabled"`
	CountryFilter int    `json:"country_filters"`
	Mode          string `json:"mode,omitempty"`
	Active        string `json:"active,omitempty"`
	Failures      int    `json:"failures,omitempty"`
	NextRun       string `json:"next_run,omitempty"`
}

type upstreamVersionView struct {
	Slot        int    `json:"slot"`
	ID          string `json:"id"`
	Seq         int64  `json:"seq"`
	State       string `json:"state"`
	Origin      string `json:"origin"`
	CreatedAt   string `json:"created_at"`
	ActivatedAt string `json:"activated_at,omitempty"`
}

type upstreamSlotView struct {
	Slot      int    `json:"slot"`
	Mode      string `json:"mode"`
	Active    string `json:"active,omitempty"`
	Failures  int    `json:"failures"`
	NextRun   string `json:"next_run,omitempty"`
	LastError string `json:"last_error,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

func runUpstream(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "missing upstream subcommand")
	}
	switch args[0] {
	case "refresh":
		fmt.Fprintln(stderr, refreshRefusal)
		return ExitRefused
	case "rollback":
		fmt.Fprintln(stderr, rollbackRefusal)
		return ExitRefused
	case "list":
		return runUpstreamList(args[1:], stdout, stderr)
	case "versions":
		return runUpstreamVersions(args[1:], stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unknown upstream subcommand %q", args[0]))
	}
}

func runSlot(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "missing slot subcommand")
	}
	switch args[0] {
	case "set":
		fmt.Fprintln(stderr, slotSetRefusal)
		return ExitRefused
	case "show":
		return runSlotShow(args[1:], stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unknown slot subcommand %q", args[0]))
	}
}

func runUpstreamList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upstream list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sourcesPath := fs.String("sources", "", "path to the source declaration file")
	storePath := fs.String("store", "", "path to the state database")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, err.Error())
	}
	if fs.NArg() != 0 {
		return usageError(stderr, "upstream list takes no positional arguments")
	}
	if *sourcesPath == "" || *storePath == "" {
		return usageError(stderr, "upstream list requires --sources and --store")
	}
	if *format != "text" && *format != "json" {
		return usageError(stderr, fmt.Sprintf("unsupported format %q", *format))
	}

	decl, err := source.Load(*sourcesPath)
	if err != nil {
		fmt.Fprintln(stderr, "upstream list failed: source declaration rejected")
		return ExitError
	}
	ctx := context.Background()
	st, err := store.Open(ctx, *storePath)
	if err != nil {
		fmt.Fprintln(stderr, "upstream list failed: store unavailable")
		return ExitError
	}
	defer func() { _ = st.Close() }()

	views := make([]upstreamSourceView, 0, len(decl.Sources))
	for _, src := range decl.Sources {
		view := upstreamSourceView{
			Slot:          src.Slot(),
			ID:            src.ID(),
			Kind:          string(src.Kind()),
			Interval:      src.Interval().String(),
			Enabled:       src.Enabled(),
			CountryFilter: len(src.Filter().Countries),
		}
		if slot, err := st.UpstreamSlot(ctx, src.Slot()); err == nil {
			view.Mode = slot.Mode
			view.Active = shortVersionID(slot.ActiveVersionID)
			view.Failures = slot.FailureCount
			if !slot.NextRunAt.IsZero() {
				view.NextRun = slot.NextRunAt.UTC().Format(time.RFC3339)
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			fmt.Fprintln(stderr, "upstream list failed: store read failed")
			return ExitError
		}
		views = append(views, view)
	}
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].Slot != views[j].Slot {
			return views[i].Slot < views[j].Slot
		}
		return views[i].ID < views[j].ID
	})

	if *format == "json" {
		return writeJSON(stdout, stderr, struct {
			Schema  int                  `json:"schema"`
			Sources []upstreamSourceView `json:"sources"`
		}{Schema: 1, Sources: views})
	}
	fmt.Fprintln(stdout, "SLOT  ID           KIND          INTERVAL  ENABLED  COUNTRIES  MODE       ACTIVE        FAILURES  NEXT RUN")
	for _, v := range views {
		fmt.Fprintf(stdout, "%-5d %-12s %-13s %-9s %-8t %-10d %-10s %-13s %-9d %s\n",
			v.Slot, v.ID, v.Kind, v.Interval, v.Enabled, v.CountryFilter,
			dash(v.Mode), dash(v.Active), v.Failures, dash(v.NextRun))
	}
	return ExitOK
}

func runUpstreamVersions(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upstream versions", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	storePath := fs.String("store", "", "path to the state database")
	slot := fs.Int("slot", 0, "upstream slot")
	limit := fs.Int("limit", defaultUpstreamVersionLimit, "maximum versions to show")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, err.Error())
	}
	if fs.NArg() != 0 {
		return usageError(stderr, "upstream versions takes no positional arguments")
	}
	if *storePath == "" {
		return usageError(stderr, "upstream versions requires --store")
	}
	if *slot < minUpstreamSlot || *slot > maxUpstreamSlot {
		return usageError(stderr, fmt.Sprintf("--slot must be between %d and %d", minUpstreamSlot, maxUpstreamSlot))
	}
	if *limit < 1 || *limit > maxUpstreamVersionLimit {
		return usageError(stderr, fmt.Sprintf("--limit must be between 1 and %d", maxUpstreamVersionLimit))
	}
	if *format != "text" && *format != "json" {
		return usageError(stderr, fmt.Sprintf("unsupported format %q", *format))
	}

	ctx := context.Background()
	st, err := store.Open(ctx, *storePath)
	if err != nil {
		fmt.Fprintln(stderr, "upstream versions failed: store unavailable")
		return ExitError
	}
	defer func() { _ = st.Close() }()

	versions, err := st.ListUpstreamVersions(ctx, *slot, *limit)
	if err != nil {
		fmt.Fprintln(stderr, "upstream versions failed: store read failed")
		return ExitError
	}
	views := make([]upstreamVersionView, 0, len(versions))
	for _, v := range versions {
		views = append(views, upstreamVersionView{
			Slot:        v.Slot,
			ID:          shortVersionID(v.ID),
			Seq:         v.Seq,
			State:       v.State,
			Origin:      v.Origin,
			CreatedAt:   v.CreatedAt.UTC().Format(time.RFC3339),
			ActivatedAt: formatTime(v.ActivatedAt),
		})
	}
	if *format == "json" {
		return writeJSON(stdout, stderr, struct {
			Schema   int                   `json:"schema"`
			Versions []upstreamVersionView `json:"versions"`
		}{Schema: 1, Versions: views})
	}
	fmt.Fprintln(stdout, "SLOT  ID            SEQ  STATE       ORIGIN     CREATED                   ACTIVATED")
	for _, v := range views {
		fmt.Fprintf(stdout, "%-5d %-12s %-4d %-11s %-10s %-25s %s\n",
			v.Slot, v.ID, v.Seq, v.State, v.Origin, v.CreatedAt, dash(v.ActivatedAt))
	}
	return ExitOK
}

func runSlotShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("slot show", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	storePath := fs.String("store", "", "path to the state database")
	slot := fs.Int("slot", 0, "upstream slot; all slots when omitted")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, err.Error())
	}
	if fs.NArg() != 0 {
		return usageError(stderr, "slot show takes no positional arguments")
	}
	if *storePath == "" {
		return usageError(stderr, "slot show requires --store")
	}
	if *slot != 0 && (*slot < minUpstreamSlot || *slot > maxUpstreamSlot) {
		return usageError(stderr, fmt.Sprintf("--slot must be between %d and %d", minUpstreamSlot, maxUpstreamSlot))
	}
	if *format != "text" && *format != "json" {
		return usageError(stderr, fmt.Sprintf("unsupported format %q", *format))
	}

	ctx := context.Background()
	st, err := store.Open(ctx, *storePath)
	if err != nil {
		fmt.Fprintln(stderr, "slot show failed: store unavailable")
		return ExitError
	}
	defer func() { _ = st.Close() }()

	var slots []store.UpstreamSlot
	if *slot != 0 {
		one, err := st.UpstreamSlot(ctx, *slot)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				fmt.Fprintln(stderr, "slot show failed: slot not found")
			} else {
				fmt.Fprintln(stderr, "slot show failed: store read failed")
			}
			return ExitError
		}
		slots = append(slots, one)
	} else {
		slots, err = st.ListUpstreamSlots(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "slot show failed: store read failed")
			return ExitError
		}
	}

	views := make([]upstreamSlotView, 0, len(slots))
	for _, s := range slots {
		views = append(views, upstreamSlotView{
			Slot:      s.Slot,
			Mode:      s.Mode,
			Active:    shortVersionID(s.ActiveVersionID),
			Failures:  s.FailureCount,
			NextRun:   formatTime(s.NextRunAt),
			LastError: s.LastErrorCode,
			UpdatedAt: s.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	if *format == "json" {
		return writeJSON(stdout, stderr, struct {
			Schema int                `json:"schema"`
			Slots  []upstreamSlotView `json:"slots"`
		}{Schema: 1, Slots: views})
	}
	fmt.Fprintln(stdout, "SLOT  MODE       ACTIVE        FAILURES  NEXT RUN                  LAST ERROR")
	for _, v := range views {
		fmt.Fprintf(stdout, "%-5d %-10s %-13s %-9d %-25s %s\n",
			v.Slot, v.Mode, dash(v.Active), v.Failures, dash(v.NextRun), dash(v.LastError))
	}
	return ExitOK
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(stderr, "output failed: encoding error")
		return ExitError
	}
	return ExitOK
}

func shortVersionID(id string) string {
	if len(id) <= shortVersionIDLen {
		return id
	}
	return id[:shortVersionIDLen]
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
