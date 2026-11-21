package payload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
)

func mustGenerateIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	return id
}

func newTestStoreDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "payloads")
	if err := os.Mkdir(dir, mode); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatalf("Chmod dir: %v", err)
	}
	return dir
}

func writeIdentityFile(t *testing.T, id *age.X25519Identity, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.age")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), mode); err != nil {
		t.Fatalf("WriteFile identity: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod identity: %v", err)
	}
	return path
}

func TestRoundTripPayloads(t *testing.T) {
	id := mustGenerateIdentity(t)
	dir := newTestStoreDir(t, 0o700)
	idFile := writeIdentityFile(t, id, 0o600)

	store, err := Open(Options{
		Dir:          dir,
		Recipient:    id.Recipient().String(),
		IdentityFile: idFile,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	binaryData := make([]byte, 1024)
	for i := range binaryData {
		binaryData[i] = byte(i % 256)
	}

	oneMiB := make([]byte, 1<<20)
	for i := range oneMiB {
		oneMiB[i] = byte((i*31 + 17) % 256)
	}

	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "single_byte", payload: []byte{0x2a}},
		{name: "json_credentials", payload: []byte("{\"type\":\"vless\",\"uuid\":\"secret-uuid-1234\"}")},
		{name: "binary_bytes", payload: binaryData},
		{name: "one_mib", payload: oneMiB},
	}

	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := store.Put(ctx, tc.payload)
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			if !isLowerHex(ref.ID, 32) {
				t.Fatalf("invalid Ref.ID format: %q", ref.ID)
			}
			if !isLowerHex(ref.SHA256, 64) {
				t.Fatalf("invalid Ref.SHA256 format: %q", ref.SHA256)
			}

			got, err := store.Get(ctx, ref)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(tc.payload))
			}
		})
	}
}

func TestCiphertextAtRestAndPermissions(t *testing.T) {
	id := mustGenerateIdentity(t)
	dir := newTestStoreDir(t, 0o700)
	idFile := writeIdentityFile(t, id, 0o600)

	store, err := Open(Options{
		Dir:          dir,
		Recipient:    id.Recipient().String(),
		IdentityFile: idFile,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const secretMarker = "PROXY_SECRET_MARKER_9a8b7c6d"
	plaintext := []byte("{\"proxy\":\"socks5://user:" + secretMarker + "@10.0.0.1:1080\"}")

	ref, err := store.Put(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	blobPath := filepath.Join(dir, ref.ID+".age")
	info, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("Stat blob: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("blob mode = %04o, want 0600", got)
	}

	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("ReadFile blob: %v", err)
	}
	if bytes.Equal(raw, plaintext) {
		t.Fatalf("ciphertext on disk equals plaintext")
	}
	if bytes.Contains(raw, []byte(secretMarker)) {
		t.Fatalf("ciphertext on disk contains secret marker")
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != ref.SHA256 {
		t.Fatalf("Ref.SHA256 = %q, want %q", ref.SHA256, got)
	}
}

func TestWrongIdentityReturnsError(t *testing.T) {
	id1 := mustGenerateIdentity(t)
	id2 := mustGenerateIdentity(t)
	dir := newTestStoreDir(t, 0o700)
	idFile1 := writeIdentityFile(t, id1, 0o600)
	idFile2 := writeIdentityFile(t, id2, 0o600)

	writerStore, err := Open(Options{
		Dir:          dir,
		Recipient:    id1.Recipient().String(),
		IdentityFile: idFile1,
	})
	if err != nil {
		t.Fatalf("Open writerStore: %v", err)
	}

	const secret = "WRONG_IDENTITY_SECRET_MARKER"
	ref, err := writerStore.Put(context.Background(), []byte(secret))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	wrongStore, err := Open(Options{
		Dir:          dir,
		Recipient:    id2.Recipient().String(),
		IdentityFile: idFile2,
	})
	if err != nil {
		t.Fatalf("Open wrongStore: %v", err)
	}

	got, err := wrongStore.Get(context.Background(), ref)
	if err == nil {
		t.Fatalf("Get with wrong identity succeeded, got %d bytes", len(got))
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get error = %v, want ErrCorrupt", err)
	}
	msg := err.Error()
	if strings.Contains(msg, secret) || strings.Contains(msg, dir) || strings.Contains(msg, id2.String()) {
		t.Fatalf("error message leaked sensitive details: %q", msg)
	}
}

func TestTamperedCiphertextAndWrongSHA256(t *testing.T) {
	id := mustGenerateIdentity(t)
	dir := newTestStoreDir(t, 0o700)
	idFile := writeIdentityFile(t, id, 0o600)

	store, err := Open(Options{
		Dir:          dir,
		Recipient:    id.Recipient().String(),
		IdentityFile: idFile,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	ref, err := store.Put(ctx, []byte("sensitive-outbound-payload"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	t.Run("wrong_ref_sha256", func(t *testing.T) {
		badRef := ref
		if badRef.SHA256[0] == '0' {
			badRef.SHA256 = "1" + badRef.SHA256[1:]
		} else {
			badRef.SHA256 = "0" + badRef.SHA256[1:]
		}
		if _, err := store.Get(ctx, badRef); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Get with wrong SHA256 error = %v, want ErrCorrupt", err)
		}
	})

	blobPath := filepath.Join(dir, ref.ID+".age")
	raw, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := os.WriteFile(blobPath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile tampered: %v", err)
	}

	t.Run("tampered_ciphertext_original_ref", func(t *testing.T) {
		if _, err := store.Get(ctx, ref); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Get tampered ciphertext error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("tampered_ciphertext_matching_sha256", func(t *testing.T) {
		sum := sha256.Sum256(raw)
		tamperedRef := Ref{
			ID:     ref.ID,
			SHA256: hex.EncodeToString(sum[:]),
		}
		if _, err := store.Get(ctx, tamperedRef); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Get tampered ciphertext with updated SHA256 error = %v, want ErrCorrupt", err)
		}
	})
}

func TestNoIdentityAndMissingPayload(t *testing.T) {
	id := mustGenerateIdentity(t)
	dir := newTestStoreDir(t, 0o700)
	idFile := writeIdentityFile(t, id, 0o600)

	writeOnly, err := Open(Options{
		Dir:       dir,
		Recipient: id.Recipient().String(),
	})
	if err != nil {
		t.Fatalf("Open writeOnly: %v", err)
	}

	ctx := context.Background()
	ref, err := writeOnly.Put(ctx, []byte("write-only-payload"))
	if err != nil {
		t.Fatalf("Put without identity: %v", err)
	}
	if _, err := writeOnly.Get(ctx, ref); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Get without identity error = %v, want ErrNoIdentity", err)
	}

	missingRef := Ref{
		ID:     strings.Repeat("a", 32),
		SHA256: strings.Repeat("b", 64),
	}
	if _, err := writeOnly.Get(ctx, missingRef); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Get missing ref without identity error = %v, want ErrNoIdentity", err)
	}

	readWrite, err := Open(Options{
		Dir:          dir,
		Recipient:    id.Recipient().String(),
		IdentityFile: idFile,
	})
	if err != nil {
		t.Fatalf("Open readWrite: %v", err)
	}
	if _, err := readWrite.Get(ctx, missingRef); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing ref error = %v, want ErrNotFound", err)
	}
}

func TestPutValidationAndCancelledContext(t *testing.T) {
	id := mustGenerateIdentity(t)
	dir := newTestStoreDir(t, 0o700)

	store, err := Open(Options{
		Dir:       dir,
		Recipient: id.Recipient().String(),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	if _, err := store.Put(ctx, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Put(nil) error = %v, want ErrInvalidInput", err)
	}
	if _, err := store.Put(ctx, []byte{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Put(empty) error = %v, want ErrInvalidInput", err)
	}
	if _, err := store.Put(ctx, make([]byte, (1<<20)+1)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Put(oversized) error = %v, want ErrInvalidInput", err)
	}

	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Put(cancelledCtx, []byte("abc")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put(cancelled) error = %v, want context.Canceled", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty store dir after rejected puts, found %d entries", len(entries))
	}
}

func TestOpenAndRefValidation(t *testing.T) {
	id := mustGenerateIdentity(t)
	validDir := newTestStoreDir(t, 0o700)
	validRecipient := id.Recipient().String()
	validIDFile := writeIdentityFile(t, id, 0o600)

	dir0755 := newTestStoreDir(t, 0o755)

	symlinkDir := filepath.Join(t.TempDir(), "linkdir")
	if err := os.Symlink(validDir, symlinkDir); err != nil {
		t.Fatalf("Symlink dir: %v", err)
	}

	idFile0644 := writeIdentityFile(t, id, 0o644)

	symlinkIDFile := filepath.Join(t.TempDir(), "linkid")
	if err := os.Symlink(validIDFile, symlinkIDFile); err != nil {
		t.Fatalf("Symlink id file: %v", err)
	}

	cases := []struct {
		name   string
		opts   Options
		secret string
	}{
		{
			name:   "invalid_recipient",
			opts:   Options{Dir: validDir, Recipient: "not-a-valid-recipient"},
			secret: "not-a-valid-recipient",
		},
		{
			name:   "plugin_recipient_rejected",
			opts:   Options{Dir: validDir, Recipient: "age1plugin-example1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"},
			secret: "age1plugin-example",
		},
		{
			name:   "dir_mode_0755",
			opts:   Options{Dir: dir0755, Recipient: validRecipient},
			secret: dir0755,
		},
		{
			name:   "symlinked_dir",
			opts:   Options{Dir: symlinkDir, Recipient: validRecipient},
			secret: symlinkDir,
		},
		{
			name:   "relative_dir",
			opts:   Options{Dir: "relative/path", Recipient: validRecipient},
			secret: "relative/path",
		},
		{
			name:   "nul_in_dir",
			opts:   Options{Dir: validDir + "\x00bad", Recipient: validRecipient},
			secret: validDir,
		},
		{
			name:   "identity_mode_0644",
			opts:   Options{Dir: validDir, Recipient: validRecipient, IdentityFile: idFile0644},
			secret: idFile0644,
		},
		{
			name:   "symlinked_identity_file",
			opts:   Options{Dir: validDir, Recipient: validRecipient, IdentityFile: symlinkIDFile},
			secret: symlinkIDFile,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(tc.opts)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Open error = %v, want ErrInvalidInput", err)
			}
			if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("Open error leaked sensitive input: %q", err.Error())
			}
		})
	}

	store, err := Open(Options{
		Dir:          validDir,
		Recipient:    validRecipient,
		IdentityFile: validIDFile,
	})
	if err != nil {
		t.Fatalf("Open valid store: %v", err)
	}

	badRefs := []Ref{
		{ID: "", SHA256: strings.Repeat("a", 64)},
		{ID: strings.Repeat("A", 32), SHA256: strings.Repeat("a", 64)},
		{ID: "../" + strings.Repeat("a", 29), SHA256: strings.Repeat("a", 64)},
		{ID: strings.Repeat("a", 32), SHA256: strings.Repeat("A", 64)},
		{ID: strings.Repeat("a", 32), SHA256: "short"},
	}
	for i, ref := range badRefs {
		if _, err := store.Get(context.Background(), ref); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("badRefs[%d]: Get error = %v, want ErrInvalidInput", i, err)
		}
	}
}

func TestConcurrentPut(t *testing.T) {
	id := mustGenerateIdentity(t)
	dir := newTestStoreDir(t, 0o700)
	idFile := writeIdentityFile(t, id, 0o600)

	store, err := Open(Options{
		Dir:          dir,
		Recipient:    id.Recipient().String(),
		IdentityFile: idFile,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	payloads := [][]byte{
		[]byte("concurrent-payload-alpha"),
		[]byte("concurrent-payload-beta"),
	}
	refs := make([]Ref, len(payloads))
	errs := make([]error, len(payloads))

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range payloads {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			refs[idx], errs[idx] = store.Put(context.Background(), payloads[idx])
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Put[%d]: %v", i, err)
		}
	}
	if refs[0].ID == refs[1].ID {
		t.Fatalf("concurrent Put calls produced duplicate ID %q", refs[0].ID)
	}

	for i, ref := range refs {
		got, err := store.Get(context.Background(), ref)
		if err != nil {
			t.Fatalf("Get[%d]: %v", i, err)
		}
		if !bytes.Equal(got, payloads[i]) {
			t.Fatalf("Get[%d] mismatch: got %q, want %q", i, got, payloads[i])
		}
	}
}
