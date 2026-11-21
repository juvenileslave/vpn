package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/store"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/candidate"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/payload"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/selector"
	"github.com/juvenileslave/vpn/vpnctl/internal/upstream/source"
)

const (
	minSlot            = 1
	maxSlot            = 63
	defaultConcurrency = 4
	maxConcurrency     = 16
	maxFailureCodeLen  = 64

	originUpstream  = "upstream"
	originBlackhole = "blackhole"
)

var (
	ErrInvalidOptions = errors.New("pipeline: invalid options")
	ErrInProgress     = errors.New("pipeline: refresh already in progress for the slot")
	ErrUnknownSlot    = errors.New("pipeline: slot is not declared")
)

// Fetcher retrieves and parses upstream candidates for a declared source.
type Fetcher interface {
	// Fetch returns candidates parsed with tag as their outbound tag.
	Fetch(ctx context.Context, src source.Source, tag string) ([]candidate.Candidate, []candidate.Reject, error)
}

// Prober probes a single upstream candidate.
type Prober interface {
	Probe(ctx context.Context, cand candidate.Candidate) ([]selector.Probe, error)
}

// Validator validates a slot outbound configuration prior to publication.
type Validator interface {
	// Validate runs the real configuration validation for the slot outbound.
	Validate(ctx context.Context, slot int, outbound json.RawMessage) error
}

// Publisher handles publishing, verifying, and restoring slot outbounds.
type Publisher interface {
	Publish(ctx context.Context, slot int, versionID string, outbound json.RawMessage) error
	ReadBack(ctx context.Context, slot int) (json.RawMessage, error)
	// Verify runs the authenticated end-to-end probe through the real slot path.
	Verify(ctx context.Context, slot int) error
	// Restore reinstalls a previous version during rollback.
	Restore(ctx context.Context, slot int, versionID string, outbound json.RawMessage) error
}

// Options configures a Pipeline instance.
type Options struct {
	Store       *store.Store
	Payloads    *payload.Store
	Fetcher     Fetcher
	Prober      Prober
	Validator   Validator
	Publisher   Publisher
	Now         func() time.Time // defaults to time.Now
	Concurrency int              // candidate probes; 0 => 4, max 16
}

// Pipeline orchestrates per-slot upstream refreshes.
//
// In-process single-flight is enforced per slot via an internal map protected
// by a mutex. Cross-process single-flight is explicitly out of scope for this
// file and must be coordinated externally when multiple processes refresh the
// same slot concurrently.
type Pipeline struct {
	store       *store.Store
	payloads    *payload.Store
	fetcher     Fetcher
	prober      Prober
	validator   Validator
	publisher   Publisher
	now         func() time.Time
	concurrency int

	mu       sync.Mutex
	inFlight map[int]struct{}
}

// New constructs a validated Pipeline.
func New(opts Options) (*Pipeline, error) {
	if opts.Store == nil ||
		opts.Payloads == nil ||
		opts.Fetcher == nil ||
		opts.Prober == nil ||
		opts.Validator == nil ||
		opts.Publisher == nil ||
		opts.Concurrency < 0 {
		return nil, ErrInvalidOptions
	}

	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = defaultConcurrency
	} else if concurrency > maxConcurrency {
		concurrency = maxConcurrency
	}

	return &Pipeline{
		store:       opts.Store,
		payloads:    opts.Payloads,
		fetcher:     opts.Fetcher,
		prober:      opts.Prober,
		validator:   opts.Validator,
		publisher:   opts.Publisher,
		now:         nowFn,
		concurrency: concurrency,
		inFlight:    make(map[int]struct{}),
	}, nil
}

// Result describes the outcome of a slot refresh.
type Result struct {
	Slot       int
	VersionID  string
	Active     bool   // false for a blackhole version
	Reason     string // selector reason or "activated" / "blackhole" / failure code
	Candidates int
	Rejects    int
	Healthy    int
	RolledBack bool
}

type sourceFetch struct {
	src        source.Source
	candidates []candidate.Candidate
}

type probeJob struct {
	sourceIdx int
	cand      candidate.Candidate
	probes    []selector.Probe
}

type blackholeOutbound struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
}

// Refresh executes a full refresh cycle for slot using the enabled sources in
// decl: fetch -> probe -> select -> persist -> validate -> create version ->
// publish -> read back -> verify -> activate.
//
// Among per-source winners, the candidate with the lowest median successful
// probe latency is selected; ties break by lexicographically smallest
// Candidate.ID. A slot with no healthy candidate activates a blackhole version
// and never falls back to direct exit.
func (p *Pipeline) Refresh(ctx context.Context, decl *source.Declaration, slot int) (Result, error) {
	res := Result{Slot: slot}
	if p == nil {
		return res, ErrInvalidOptions
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if decl == nil || slot < minSlot || slot > maxSlot {
		return res, ErrUnknownSlot
	}

	sources := enabledSourcesForSlot(decl, slot)
	if len(sources) == 0 {
		return res, ErrUnknownSlot
	}

	if !p.acquireSlot(slot) {
		return res, ErrInProgress
	}
	defer p.releaseSlot(slot)

	tag := fmt.Sprintf("upstream-slot-%d", slot)

	// Fetch every declared enabled source for the slot; a single source error
	// must not discard candidates from other sources.
	fetched := make([]sourceFetch, 0, len(sources))
	var fetchErrs int
	var lastFetchErr error
	for _, src := range sources {
		cands, rejects, err := p.fetcher.Fetch(ctx, src, tag)
		res.Rejects += len(rejects)
		if err != nil {
			fetchErrs++
			lastFetchErr = err
			continue
		}
		res.Candidates += len(cands)
		fetched = append(fetched, sourceFetch{
			src:        src,
			candidates: cands,
		})
	}

	if len(fetched) == 0 && fetchErrs > 0 {
		return p.recordPreActivationFailure(ctx, res, "fetch_failed", lastFetchErr)
	}

	// Probe all candidates with bounded concurrency, reusing each candidate's
	// own probe slice returned by Prober.
	jobs := make([]probeJob, 0, res.Candidates)
	for sIdx, sf := range fetched {
		for _, cand := range sf.candidates {
			jobs = append(jobs, probeJob{
				sourceIdx: sIdx,
				cand:      cand,
			})
		}
	}

	if len(jobs) > 0 {
		p.probeAll(ctx, jobs)
		if err := ctx.Err(); err != nil {
			return p.recordPreActivationFailure(ctx, res, "probe_canceled", err)
		}
	}

	inputsBySource := make([][]selector.Input, len(fetched))
	for _, job := range jobs {
		inputsBySource[job.sourceIdx] = append(inputsBySource[job.sourceIdx], selector.Input{
			Candidate: job.cand,
			Probes:    job.probes,
		})
	}

	// Select deterministically per source using that source's filter.
	winners := make([]selector.Input, 0, len(fetched))
	var selectorReason string
	for sIdx, sf := range fetched {
		selFilter := toSelectorFilter(sf.src.Filter())
		inputs := inputsBySource[sIdx]

		for _, in := range inputs {
			single := selector.Select([]selector.Input{in}, selFilter)
			if !single.Blackhole && single.Candidate != nil {
				res.Healthy++
			}
		}

		dec := selector.Select(inputs, selFilter)
		if !dec.Blackhole && dec.Candidate != nil {
			winners = append(winners, matchWinnerInput(inputs, *dec.Candidate))
			continue
		}
		if selectorReason == "" && strings.TrimSpace(dec.Reason) != "" {
			selectorReason = dec.Reason
		}
	}

	if len(winners) == 0 {
		if selectorReason == "" {
			selectorReason = originBlackhole
		}
		return p.activateBlackhole(ctx, res, tag, selectorReason)
	}

	winner := selectBestWinner(winners)
	return p.activateUpstream(ctx, res, tag, winner.Candidate)
}

func (p *Pipeline) acquireSlot(slot int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, busy := p.inFlight[slot]; busy {
		return false
	}
	p.inFlight[slot] = struct{}{}
	return true
}

func (p *Pipeline) releaseSlot(slot int) {
	p.mu.Lock()
	delete(p.inFlight, slot)
	p.mu.Unlock()
}

func (p *Pipeline) probeAll(ctx context.Context, jobs []probeJob) {
	workers := p.concurrency
	if workers > len(jobs) {
		workers = len(jobs)
	}

	jobCh := make(chan int, len(jobs))
	for i := range jobs {
		jobCh <- i
	}
	close(jobCh)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for idx := range jobCh {
				if ctx.Err() != nil {
					continue
				}
				probes, err := p.prober.Probe(ctx, jobs[idx].cand)
				if err != nil {
					continue
				}
				jobs[idx].probes = probes
			}
		}()
	}
	wg.Wait()
}

func (p *Pipeline) activateUpstream(ctx context.Context, res Result, tag string, cand candidate.Candidate) (Result, error) {
	outboundBytes, err := marshalCandidateOutbound(cand.Outbound)
	if err != nil {
		return p.recordPreActivationFailure(ctx, res, "invalid_outbound", err)
	}
	return p.publishAndActivate(ctx, res, tag, originUpstream, outboundBytes, "activated")
}

func (p *Pipeline) activateBlackhole(ctx context.Context, res Result, tag, reason string) (Result, error) {
	outboundBytes, err := marshalBlackholeOutbound(tag)
	if err != nil {
		return p.recordPreActivationFailure(ctx, res, "invalid_outbound", err)
	}
	return p.publishAndActivate(ctx, res, tag, originBlackhole, outboundBytes, reason)
}

func (p *Pipeline) publishAndActivate(
	ctx context.Context,
	res Result,
	tag string,
	origin string,
	outboundBytes []byte,
	successReason string,
) (Result, error) {
	fingerprint := sha256Hex(outboundBytes)

	ref, err := p.payloads.Put(ctx, outboundBytes)
	if err != nil {
		return p.recordPreActivationFailure(ctx, res, "payload_put_failed", err)
	}

	if err := p.validator.Validate(ctx, res.Slot, json.RawMessage(outboundBytes)); err != nil {
		return p.recordPreActivationFailure(ctx, res, "validate_failed", err)
	}

	created, err := p.store.CreateUpstreamVersion(ctx, store.UpstreamVersion{
		Slot:                res.Slot,
		Origin:              origin,
		PayloadRef:          ref.ID,
		PayloadSHA256:       ref.SHA256,
		OutboundFingerprint: fingerprint,
	}, p.now())
	if err != nil {
		return p.recordPreActivationFailure(ctx, res, "create_version_failed", err)
	}
	res.VersionID = created.ID

	prev, prevErr := p.store.ActiveUpstreamVersion(ctx, res.Slot)
	hasPrev := prevErr == nil
	if prevErr != nil && !errors.Is(prevErr, store.ErrNotFound) {
		return p.failVersion(ctx, res, created.ID, tag, false, false, store.UpstreamVersion{}, "active_lookup_failed", prevErr)
	}

	if err := p.publisher.Publish(ctx, res.Slot, created.ID, json.RawMessage(outboundBytes)); err != nil {
		// The publish attempt may have partially applied before failing, so
		// restore the previous outbound (or fail-closed blackhole) rather than
		// assuming the slot is untouched.
		return p.failVersion(ctx, res, created.ID, tag, true, hasPrev, prev, "publish_failed", err)
	}

	readBackBytes, err := p.publisher.ReadBack(ctx, res.Slot)
	if err != nil {
		return p.failVersion(ctx, res, created.ID, tag, true, hasPrev, prev, "readback_failed", err)
	}
	if sha256Hex(readBackBytes) != fingerprint {
		return p.failVersion(ctx, res, created.ID, tag, true, hasPrev, prev, "readback_mismatch", nil)
	}

	if origin == originUpstream {
		if err := p.publisher.Verify(ctx, res.Slot); err != nil {
			return p.failVersion(ctx, res, created.ID, tag, true, hasPrev, prev, "verify_failed", err)
		}
	}

	if _, _, err := p.store.ActivateUpstreamVersion(ctx, created.ID, p.now()); err != nil {
		return p.failVersion(ctx, res, created.ID, tag, true, hasPrev, prev, "activate_failed", err)
	}

	res.Active = origin == originUpstream
	res.Reason = successReason
	return res, nil
}

func (p *Pipeline) failVersion(
	ctx context.Context,
	res Result,
	versionID string,
	tag string,
	published bool,
	hasPrev bool,
	prev store.UpstreamVersion,
	code string,
	cause error,
) (Result, error) {
	code = sanitizeFailureCode(code)
	cctx := cleanupContext(ctx)

	_ = p.store.FailUpstreamVersion(cctx, versionID, code, p.now())

	if published {
		res.RolledBack = p.restorePrevious(cctx, res.Slot, versionID, tag, hasPrev, prev)
	}

	return p.recordPreActivationFailure(cctx, res, code, cause)
}

func (p *Pipeline) restorePrevious(
	ctx context.Context,
	slot int,
	failedVersionID string,
	tag string,
	hasPrev bool,
	prev store.UpstreamVersion,
) bool {
	if !hasPrev {
		// No previous active version exists in the store, and Activate never
		// ran so nothing is active in the store. Restore the static blackhole
		// outbound on the publisher so the failed candidate does not remain
		// live; never call RollbackUpstreamSlot for blackhole restore.
		bhBytes, err := marshalBlackholeOutbound(tag)
		if err != nil {
			return false
		}
		return p.publisher.Restore(ctx, slot, "", json.RawMessage(bhBytes)) == nil
	}

	if prev.Origin == originBlackhole {
		// Blackhole outbound is static; never call RollbackUpstreamSlot for
		// blackhole restore so a revoked or retired version is never
		// resurrected.
		bhBytes, err := marshalBlackholeOutbound(tag)
		if err != nil {
			return false
		}
		return p.publisher.Restore(ctx, slot, prev.ID, json.RawMessage(bhBytes)) == nil
	}

	prevBytes, err := p.payloads.Get(ctx, payload.Ref{
		ID:     prev.PayloadRef,
		SHA256: prev.PayloadSHA256,
	})
	if err != nil {
		return false
	}

	if err := p.publisher.Restore(ctx, slot, prev.ID, json.RawMessage(prevBytes)); err != nil {
		return false
	}

	// Only roll back the store slot if the failed version actually became
	// active; otherwise prev is already active and RollbackUpstreamSlot would
	// demote prev to an older version.
	if cur, err := p.store.ActiveUpstreamVersion(ctx, slot); err == nil && cur.ID == failedVersionID {
		if _, _, err := p.store.RollbackUpstreamSlot(ctx, slot, p.now()); err != nil {
			return false
		}
	}

	return true
}

func (p *Pipeline) recordPreActivationFailure(ctx context.Context, res Result, code string, cause error) (Result, error) {
	code = sanitizeFailureCode(code)
	cctx := cleanupContext(ctx)
	_, _ = p.store.RecordUpstreamFailure(cctx, res.Slot, code, time.Time{}, p.now())
	res.Active = false
	res.Reason = code
	return res, boundedError(res.Slot, code, cause)
}

func enabledSourcesForSlot(decl *source.Declaration, slot int) []source.Source {
	var matched []source.Source
	for _, src := range decl.Sources {
		if src.Enabled() && src.Slot() == slot {
			matched = append(matched, src)
		}
	}
	return matched
}

func toSelectorFilter(f source.Filter) selector.Filter {
	var countries []string
	if len(f.Countries) > 0 {
		countries = make([]string, len(f.Countries))
		copy(countries, f.Countries)
	}
	return selector.Filter{
		Countries:           countries,
		MaxLatency:          f.MaxLatency,
		MinSuccessfulProbes: f.MinSuccessfulProbes,
	}
}

func matchWinnerInput(inputs []selector.Input, winner candidate.Candidate) selector.Input {
	for _, in := range inputs {
		if in.Candidate.ID == winner.ID {
			return selector.Input{
				Candidate: winner,
				Probes:    in.Probes,
			}
		}
	}
	return selector.Input{Candidate: winner}
}

// selectBestWinner chooses the fastest per-source winner by median successful
// probe latency, breaking ties by lexicographically smallest Candidate.ID.
func selectBestWinner(winners []selector.Input) selector.Input {
	best := winners[0]
	bestLat := effectiveLatency(best.Probes)
	for _, cand := range winners[1:] {
		lat := effectiveLatency(cand.Probes)
		if lat < bestLat || (lat == bestLat && cand.Candidate.ID < best.Candidate.ID) {
			best = cand
			bestLat = lat
		}
	}
	return best
}

func effectiveLatency(probes []selector.Probe) time.Duration {
	if len(probes) == 0 {
		return time.Duration(math.MaxInt64)
	}
	latencies := make([]time.Duration, 0, len(probes))
	for _, pr := range probes {
		if isSuccessOutcome(pr.Outcome) && pr.Latency >= 0 {
			latencies = append(latencies, pr.Latency)
		}
	}
	if len(latencies) == 0 {
		for _, pr := range probes {
			if pr.Latency > 0 {
				latencies = append(latencies, pr.Latency)
			}
		}
	}
	if len(latencies) == 0 {
		return time.Duration(math.MaxInt64)
	}
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})
	mid := len(latencies) / 2
	if len(latencies)%2 == 1 {
		return latencies[mid]
	}
	return latencies[mid-1] + (latencies[mid]-latencies[mid-1])/2
}

func isSuccessOutcome(outcome string) bool {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "ok", "success", "succeeded", "pass", "passed", "healthy":
		return true
	default:
		return false
	}
}

func marshalCandidateOutbound(raw json.RawMessage) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("empty outbound")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil, errors.New("null outbound")
	}
	return b, nil
}

func marshalBlackholeOutbound(tag string) ([]byte, error) {
	return json.Marshal(blackholeOutbound{
		Protocol: originBlackhole,
		Tag:      tag,
	})
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func cleanupContext(ctx context.Context) context.Context {
	if ctx.Err() == nil {
		return ctx
	}
	return context.WithoutCancel(ctx)
}

func isValidFailureCode(code string) bool {
	if len(code) == 0 || len(code) > maxFailureCodeLen {
		return false
	}
	if code[0] < 'a' || code[0] > 'z' {
		return false
	}
	for i := 1; i < len(code); i++ {
		c := code[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isLower && !isDigit && c != '_' {
			return false
		}
	}
	return true
}

func sanitizeFailureCode(code string) string {
	if isValidFailureCode(code) {
		return code
	}
	return "internal_error"
}

func boundedError(slot int, code string, cause error) error {
	code = sanitizeFailureCode(code)
	if errors.Is(cause, context.Canceled) {
		return fmt.Errorf("pipeline: slot %d refresh failed (%s): %w", slot, code, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return fmt.Errorf("pipeline: slot %d refresh failed (%s): %w", slot, code, context.DeadlineExceeded)
	}
	return fmt.Errorf("pipeline: slot %d refresh failed (%s)", slot, code)
}
