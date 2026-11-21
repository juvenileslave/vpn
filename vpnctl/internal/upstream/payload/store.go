package payload

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

const (
	maxPlaintextSize    = 1 << 20
	maxCiphertextSize   = maxPlaintextSize + 4096
	maxIdentityFileSize = 1 << 20
	idBytes             = 16
	idHexLen            = idBytes * 2
	sha256HexLen        = sha256.Size * 2
)

var (
	ErrInvalidInput = errors.New("payload: invalid input")
	ErrNotFound     = errors.New("payload: payload not found")
	ErrCorrupt      = errors.New("payload: payload integrity check failed")
	ErrNoIdentity   = errors.New("payload: decryption identity is not configured")
)

// Ref identifies one stored encrypted payload.
type Ref struct {
	ID     string // 32 lowercase hex
	SHA256 string // 64 lowercase hex over the ciphertext file bytes
}

// Options configures an encrypted payload Store.
type Options struct {
	Dir          string // absolute existing directory, mode 0700, no symlink
	Recipient    string // age X25519 recipient, e.g. "age1..."
	IdentityFile string // optional absolute 0600 file with age identities
}

// Store persists age-encrypted payload blobs on disk.
// A Store is safe for concurrent use by multiple goroutines.
type Store struct {
	dir        string
	recipient  *age.X25519Recipient
	identities []age.Identity
}

// Open validates options and returns a Store backed by opts.Dir.
func Open(opts Options) (*Store, error) {
	if err := validatePathInput(opts.Dir); err != nil {
		return nil, fmt.Errorf("%w: directory must be a non-empty absolute path", ErrInvalidInput)
	}
	cleanDir := filepath.Clean(opts.Dir)
	dirInfo, err := os.Lstat(cleanDir)
	if err != nil {
		return nil, fmt.Errorf("%w: directory does not exist or is inaccessible", ErrInvalidInput)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return nil, fmt.Errorf("%w: directory must be an existing non-symlink directory", ErrInvalidInput)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("%w: directory permissions must be 0700", ErrInvalidInput)
	}

	if opts.Recipient == "" || strings.IndexByte(opts.Recipient, 0) >= 0 {
		return nil, fmt.Errorf("%w: recipient is required", ErrInvalidInput)
	}
	recipient, err := age.ParseX25519Recipient(opts.Recipient)
	if err != nil || recipient == nil {
		return nil, fmt.Errorf("%w: invalid x25519 recipient", ErrInvalidInput)
	}

	var identities []age.Identity
	if opts.IdentityFile != "" {
		parsed, err := loadIdentities(opts.IdentityFile)
		if err != nil {
			return nil, err
		}
		identities = parsed
	}

	return &Store{
		dir:        cleanDir,
		recipient:  recipient,
		identities: identities,
	}, nil
}

// Put encrypts plaintext with the configured recipient, writes it to a new
// 0600 file in the store directory, and returns its content reference.
func (s *Store) Put(ctx context.Context, plaintext []byte) (Ref, error) {
	if s == nil {
		return Ref{}, fmt.Errorf("%w: store is nil", ErrInvalidInput)
	}
	if ctx == nil {
		return Ref{}, fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return Ref{}, err
	}
	if len(plaintext) == 0 || len(plaintext) > maxPlaintextSize {
		return Ref{}, fmt.Errorf("%w: plaintext length must be between 1 and %d bytes", ErrInvalidInput, maxPlaintextSize)
	}

	var rawID [idBytes]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		return Ref{}, errors.New("payload: failed to generate payload id")
	}
	id := hex.EncodeToString(rawID[:])
	path := filepath.Join(s.dir, id+".age")

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Ref{}, errors.New("payload: failed to create payload file")
	}

	committed := false
	defer func() {
		if f != nil {
			_ = f.Close()
		}
		if !committed {
			_ = os.Remove(path)
		}
	}()

	if err := f.Chmod(0o600); err != nil {
		return Ref{}, errors.New("payload: failed to set payload file permissions")
	}

	hasher := sha256.New()
	encWriter, err := age.Encrypt(io.MultiWriter(f, hasher), s.recipient)
	if err != nil {
		return Ref{}, errors.New("payload: failed to initialize encryption")
	}
	if _, err := encWriter.Write(plaintext); err != nil {
		_ = encWriter.Close()
		return Ref{}, errors.New("payload: failed to encrypt payload")
	}
	if err := encWriter.Close(); err != nil {
		return Ref{}, errors.New("payload: failed to finalize encryption")
	}
	if err := f.Sync(); err != nil {
		return Ref{}, errors.New("payload: failed to sync payload file")
	}
	if err := f.Close(); err != nil {
		f = nil
		return Ref{}, errors.New("payload: failed to close payload file")
	}
	f = nil

	if err := ctx.Err(); err != nil {
		return Ref{}, err
	}

	committed = true
	return Ref{
		ID:     id,
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

// Get verifies ref integrity and decrypts the referenced payload using the
// configured identity file.
func (s *Store) Get(ctx context.Context, ref Ref) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: store is nil", ErrInvalidInput)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isLowerHex(ref.ID, idHexLen) || !isLowerHex(ref.SHA256, sha256HexLen) {
		return nil, fmt.Errorf("%w: invalid payload reference", ErrInvalidInput)
	}
	if len(s.identities) == 0 {
		return nil, ErrNoIdentity
	}

	path := filepath.Join(s.dir, ref.ID+".age")
	linfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, errors.New("payload: failed to inspect payload file")
	}
	if linfo.Mode()&os.ModeSymlink != 0 || !linfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: payload file must be a regular non-symlink file", ErrCorrupt)
	}
	if linfo.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%w: payload file permissions must be 0600", ErrCorrupt)
	}
	if linfo.Size() <= 0 || linfo.Size() > maxCiphertextSize {
		return nil, fmt.Errorf("%w: payload file size out of bounds", ErrCorrupt)
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, errors.New("payload: failed to open payload file")
	}
	defer f.Close()

	finfo, err := f.Stat()
	if err != nil {
		return nil, errors.New("payload: failed to stat payload file")
	}
	if !os.SameFile(linfo, finfo) || !finfo.Mode().IsRegular() || finfo.Mode().Perm() != 0o600 || finfo.Size() <= 0 || finfo.Size() > maxCiphertextSize {
		return nil, fmt.Errorf("%w: payload file metadata invalid", ErrCorrupt)
	}

	ciphertext, err := io.ReadAll(io.LimitReader(f, maxCiphertextSize+1))
	if err != nil {
		return nil, errors.New("payload: failed to read payload file")
	}
	if len(ciphertext) == 0 || len(ciphertext) > maxCiphertextSize {
		return nil, fmt.Errorf("%w: ciphertext size out of bounds", ErrCorrupt)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sum := sha256.Sum256(ciphertext)
	gotSHA := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(gotSHA), []byte(ref.SHA256)) != 1 {
		return nil, fmt.Errorf("%w: sha256 mismatch", ErrCorrupt)
	}

	decReader, err := age.Decrypt(bytes.NewReader(ciphertext), s.identities...)
	if err != nil {
		return nil, fmt.Errorf("%w: decryption failed", ErrCorrupt)
	}

	plaintext, err := io.ReadAll(io.LimitReader(decReader, maxPlaintextSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: decryption stream failed", ErrCorrupt)
	}
	if len(plaintext) == 0 || len(plaintext) > maxPlaintextSize {
		return nil, fmt.Errorf("%w: plaintext size out of bounds", ErrCorrupt)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return plaintext, nil
}

func loadIdentities(path string) ([]age.Identity, error) {
	if err := validatePathInput(path); err != nil {
		return nil, fmt.Errorf("%w: identity file must be an absolute path", ErrInvalidInput)
	}
	cleanPath := filepath.Clean(path)
	linfo, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("%w: identity file does not exist or is inaccessible", ErrInvalidInput)
	}
	if linfo.Mode()&os.ModeSymlink != 0 || !linfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: identity file must be a regular non-symlink file", ErrInvalidInput)
	}
	if linfo.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%w: identity file permissions must be 0600", ErrInvalidInput)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("%w: identity file could not be opened", ErrInvalidInput)
	}
	defer f.Close()

	finfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: identity file could not be inspected", ErrInvalidInput)
	}
	if !os.SameFile(linfo, finfo) || !finfo.Mode().IsRegular() || finfo.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%w: identity file must be a regular 0600 file", ErrInvalidInput)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxIdentityFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: identity file could not be read", ErrInvalidInput)
	}
	defer clear(data)
	if len(data) == 0 || len(data) > maxIdentityFileSize {
		return nil, fmt.Errorf("%w: identity file size out of bounds", ErrInvalidInput)
	}

	identities, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil || len(identities) == 0 {
		return nil, fmt.Errorf("%w: invalid age identity file", ErrInvalidInput)
	}
	return identities, nil
}

func validatePathInput(p string) error {
	if p == "" || strings.IndexByte(p, 0) >= 0 || !filepath.IsAbs(p) {
		return ErrInvalidInput
	}
	return nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
