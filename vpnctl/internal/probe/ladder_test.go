package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLadderStageOutcomesNeverAcceptSizeOrIntegrityFailure(t *testing.T) {
	endpoint := &Endpoint{Bytes: SmallBytes, SHA256: strings.Repeat("a", 64)}
	for _, test := range []struct {
		name        string
		observation Observation
		stage       Stage
		outcome     Outcome
		code        string
	}{
		{name: "exact verified transfer", stage: StageTransferSmall, observation: Observation{Outcome: OutcomeSuccess, BytesRead: SmallBytes, SHA256: endpoint.SHA256}, outcome: OutcomeSuccess},
		{name: "short declared body", stage: StageTransferSmall, observation: Observation{Outcome: OutcomeSuccess, BytesRead: SmallBytes - 1, SHA256: endpoint.SHA256}, outcome: OutcomeSizeMismatch, code: "size_mismatch"},
		{name: "oversized or unconfirmed body", stage: StageTransferSmall, observation: Observation{Outcome: OutcomeSuccess, BytesRead: SmallBytes, SHA256: endpoint.SHA256, LimitReached: true}, outcome: OutcomeSizeMismatch, code: "size_mismatch"},
		{name: "wrong payload", stage: StageTransferSmall, observation: Observation{Outcome: OutcomeSuccess, BytesRead: SmallBytes, SHA256: strings.Repeat("b", 64)}, outcome: OutcomeIntegrityMismatch, code: "integrity_mismatch"},
		{name: "authorized request timeout", stage: StageAuth, observation: Observation{Outcome: OutcomeTimeout}, outcome: OutcomeTimeout, code: "auth_timeout"},
		{name: "wrong credentials protocol failure", stage: StageAuth, observation: Observation{Outcome: OutcomeHTTPProtocol, Error: "secret-canary"}, outcome: OutcomeHTTPProtocol, code: "auth_failed"},
		{name: "cancel is not tcp block", stage: StageAuth, observation: Observation{Outcome: OutcomeCanceled}, outcome: OutcomeCanceled, code: "canceled"},
		{name: "measured early eof", stage: StageThroughput, observation: Observation{Outcome: OutcomeEarlyEOF, BytesRead: 17 << 10}, outcome: OutcomeEarlyEOF, code: "early_eof"},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := finishEvent(Event{Stage: test.stage, ErrorCode: "stage_not_run"}, test.observation, endpoint)
			if event.Outcome != test.outcome || event.ErrorCode != test.code || event.Integrity != (test.outcome == OutcomeSuccess) {
				t.Fatalf("event = %+v; want %s/%s", event, test.outcome, test.code)
			}
			if strings.Contains(fmt.Sprint(event), "secret-canary") {
				t.Fatal("raw primitive error leaked")
			}
		})
	}
}

func pipeTransfer(t *testing.T, ctx context.Context, size, sent int64, hold bool) Observation {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	written := make(chan struct{})
	go func() {
		defer close(written)
		defer server.Close()
		buf := make([]byte, 1024)
		var request strings.Builder
		for !strings.Contains(request.String(), "\r\n\r\n") {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			request.Write(buf[:n])
		}
		if _, err := fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size); err != nil {
			return
		}
		if _, err := io.CopyN(server, strings.NewReader(strings.Repeat("x", int(sent))), sent); err != nil {
			return
		}
		if hold {
			<-ctx.Done()
		}
	}()
	stop := watch(ctx, client)
	defer stop()
	endpoint, err := url.Parse("http://payload.example.test/fixture")
	if err != nil {
		t.Fatal(err)
	}
	observation := transfer(ctx, client, endpoint, HTTPRequest{MaxBytes: size, HashBody: true}, Observation{})
	client.Close()
	<-written
	return observation
}

func TestHashedBoundedTransferOnPipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observation := pipeTransfer(t, ctx, 256, 256, false)
	digest := sha256.Sum256([]byte(strings.Repeat("x", 256)))
	if observation.Outcome != OutcomeSuccess || observation.BytesRead != 256 || observation.LimitReached || observation.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("bounded integrity measurement = %+v", observation)
	}
}

func TestHashedTransferRecordsActual17KiBInterruption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observation := pipeTransfer(t, ctx, LargeBytes, 17<<10, false)
	digest := sha256.Sum256([]byte(strings.Repeat("x", 17<<10)))
	if observation.Outcome != OutcomeEarlyEOF || observation.BytesRead != 17<<10 || observation.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("interruption = %+v", observation)
	}
}

func TestHashedTransferDeadlineAndCancel(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancelEarly), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if cancelEarly {
				cancel()
			}
			observation := pipeTransfer(t, ctx, LargeBytes, 17<<10, true)
			want := OutcomeTimeout
			if cancelEarly {
				want = OutcomeCanceled
			}
			if observation.Outcome != want || observation.BytesRead >= LargeBytes {
				t.Fatalf("bounded transfer = %+v; want %s", observation, want)
			}
		})
	}
}

func TestLadderFamilyAndBudgetsCannotFallback(t *testing.T) {
	budgets := Budgets{Overall: time.Second, Setup: time.Second, TCP: time.Second, TLS: time.Second,
		Auth: time.Second, Small: time.Second, Large: time.Second, Control: time.Second}
	if err := budgets.validate(); err != nil {
		t.Fatal(err)
	}
	budgets.TCP = 2 * time.Second
	if err := budgets.validate(); err == nil {
		t.Fatal("stage budget escaped overall deadline")
	}
}
