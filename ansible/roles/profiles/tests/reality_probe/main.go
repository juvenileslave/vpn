// Command reality-probe authenticates real TLS, but never sends VLESS/application data.
// Token derivation follows the pinned Xray 26.11.9 REALITY client.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

type options struct {
	Address       string `json:"address"`
	SNI           string `json:"sni"`
	PublicKey     string `json:"public_key"`
	ShortID       string `json:"short_id"`
	OffsetSeconds int64  `json:"offset_seconds"`
	Capture       string `json:"capture"`
	State         string `json:"state"`
	ReplayState   string `json:"replay_state"`
	Trust         string `json:"trust"`
	Fragment      int    `json:"fragment"`
}

// Only serializable, documented key material is retained: never a copied UConn,
// mutex, transcript, cipher state, reflection or unsafe pointer.
type replayState struct {
	Hello        []byte `json:"hello"`
	Record       []byte `json:"record"`
	Ecdhe        []byte `json:"ecdhe"`
	HybridEcdhe  []byte `json:"hybrid_ecdhe"`
	MLKEMSeed    []byte `json:"mlkem_seed"`
	SNI          string `json:"sni"`
	PublicKey    string `json:"public_key"`
	RecordedUnix int64  `json:"recorded_unix"`
}

type verdict struct {
	Authenticated        bool    `json:"reality_authenticated"`
	OriginVerified       bool    `json:"origin_chain_verified"`
	HandshakeComplete    bool    `json:"tls_handshake_complete"`
	HelloSHA256          string  `json:"hello_sha256"`
	RecordSHA256         string  `json:"record_sha256"`
	RecordedUnix         int64   `json:"recorded_unix"`
	FirstResponseSeconds float64 `json:"first_response_seconds"`
	HandshakeSeconds     float64 `json:"handshake_seconds"`
	ServerResponseBytes  int     `json:"server_response_bytes"`
}

func privatePath(path string, existing bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("probe: absolute private path required")
	}
	directory := filepath.Dir(path)
	isLabTemporary := filepath.Dir(directory) == "/var/tmp" && strings.HasPrefix(filepath.Base(directory), "vpn-profiles-")
	if !isLabTemporary {
		return errors.New("probe: guarded profile temporary directory required")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("stat private parent: %w", err)
	}
	if !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return errors.New("probe: private parent must be a real 0700 directory")
	}
	if !existing {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat private file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("probe: private file must be a real 0600 file")
	}
	return nil
}

func writePrivate(path string, data []byte) (err error) {
	if err := privatePath(path, false); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create private probe file: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write private probe file: %w", err)
	}
	return nil
}

type tapConn struct {
	net.Conn
	fragment        int
	state           *replayState
	capture         string
	statePath       string
	isReplay        bool
	hasCaptured     bool
	firstWriteAt    time.Time
	firstResponseAt time.Time
	responseBytes   int
}

func (c *tapConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		if c.firstResponseAt.IsZero() {
			c.firstResponseAt = time.Now()
		}
		c.responseBytes += n
	}
	// Preserve net.Conn read errors for the TLS library's own handling.
	return n, err
}

func (c *tapConn) Write(data []byte) (int, error) {
	if !c.hasCaptured {
		// TLS record header is not part of the ClientHello transcript. Require
		// the exact complete recorded first write, not only a length/digest claim.
		validRecord := len(data) >= 5 && data[0] == 22
		if !validRecord || int(binary.BigEndian.Uint16(data[3:5])) != len(data)-5 {
			return 0, errors.New("probe: unexpected first tls record")
		}
		if !bytes.Equal(data[5:], c.state.Hello) {
			return 0, errors.New("probe: client hello changed before transmission")
		}
		if c.isReplay {
			if !bytes.Equal(data, c.state.Record) {
				return 0, errors.New("probe: replay record is not byte identical")
			}
		} else {
			c.state.Record = bytes.Clone(data)
			serialized, err := json.Marshal(c.state)
			if err != nil {
				return 0, fmt.Errorf("encode private replay state: %w", err)
			}
			if err := writePrivate(c.capture, data); err != nil {
				return 0, err
			}
			if err := writePrivate(c.statePath, serialized); err != nil {
				return 0, err
			}
		}
		c.hasCaptured = true
	}
	if c.firstWriteAt.IsZero() {
		c.firstWriteAt = time.Now()
	}
	if c.fragment == 0 {
		return c.Conn.Write(data)
	}
	total := 0
	for len(data) > 0 {
		n := min(c.fragment, len(data))
		written, err := c.Conn.Write(data[:n])
		total += written
		if err != nil {
			return total, fmt.Errorf("fragment hello: %w", err)
		}
		if written == 0 {
			return total, errors.New("probe: zero length fragment write")
		}
		data = data[written:]
		time.Sleep(time.Millisecond)
	}
	return total, nil
}

func retainedKeys(keys *utls.KeySharePrivateKeys, state *replayState) error {
	if keys == nil {
		return errors.New("probe: missing key shares")
	}
	if keys.Ecdhe != nil {
		state.Ecdhe = keys.Ecdhe.Bytes()
	}
	if keys.MlkemEcdhe != nil {
		state.HybridEcdhe = keys.MlkemEcdhe.Bytes()
	}
	if keys.Mlkem != nil {
		key, ok := keys.Mlkem.(*mlkem.DecapsulationKey768)
		if !ok {
			return errors.New("probe: unsupported fingerprint kem key")
		}
		state.MLKEMSeed = key.Bytes()
	}
	return nil
}

func restoredKeys(state *replayState) (*utls.KeySharePrivateKeys, error) {
	keys := &utls.KeySharePrivateKeys{}
	var err error
	if len(state.Ecdhe) > 0 {
		keys.Ecdhe, err = ecdh.X25519().NewPrivateKey(state.Ecdhe)
		if err != nil {
			return nil, fmt.Errorf("restore replay x25519 key: %w", err)
		}
	}
	if len(state.HybridEcdhe) > 0 {
		keys.MlkemEcdhe, err = ecdh.X25519().NewPrivateKey(state.HybridEcdhe)
		if err != nil {
			return nil, fmt.Errorf("restore replay hybrid key: %w", err)
		}
	}
	if len(state.MLKEMSeed) > 0 {
		keys.Mlkem, err = mlkem.NewDecapsulationKey768(state.MLKEMSeed)
		if err != nil {
			return nil, fmt.Errorf("restore replay kem seed: %w", err)
		}
	}
	return keys, nil
}

func authenticationKey(hello *utls.PubClientHelloMsg, keys *utls.KeySharePrivateKeys, public string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(public)
	if err != nil {
		return nil, fmt.Errorf("decode probe public key: %w", err)
	}
	key, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("probe public key: %w", err)
	}
	ephemeral := keys.Ecdhe
	if ephemeral == nil {
		ephemeral = keys.MlkemEcdhe
	}
	if ephemeral == nil || len(hello.Random) != 32 {
		return nil, errors.New("probe: missing x25519 key or random")
	}
	shared, err := ephemeral.ECDH(key)
	if err != nil {
		return nil, fmt.Errorf("probe shared key: %w", err)
	}
	derived, err := hkdf.Key(
		sha256.New,
		shared,
		hello.Random[:20],
		"REALITY",
		32,
	)
	if err != nil {
		return nil, fmt.Errorf("derive probe authentication key: %w", err)
	}
	return derived, nil
}

func probe(ctx context.Context, opt options) (result verdict, probeErr error) {
	state := &replayState{SNI: opt.SNI, PublicKey: opt.PublicKey, RecordedUnix: time.Now().Unix()}
	if opt.ReplayState != "" {
		if err := privatePath(opt.ReplayState, true); err != nil {
			return result, err
		}
		data, err := os.ReadFile(opt.ReplayState)
		if err != nil {
			return result, fmt.Errorf("read replay state: %w", err)
		}
		if err := json.Unmarshal(data, state); err != nil {
			return result, fmt.Errorf("decode replay state: %w", err)
		}
		if state.SNI != opt.SNI || state.PublicKey != opt.PublicKey {
			return result, errors.New("probe: replay authority mismatch")
		}
	}
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(opt.Trust)
	if err != nil {
		return result, fmt.Errorf("read disposable origin trust: %w", err)
	}
	if !roots.AppendCertsFromPEM(pem) {
		return result, errors.New("probe: no disposable trust anchor")
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", opt.Address)
	if err != nil {
		return result, fmt.Errorf("dial probe: %w", err)
	}
	defer func() { probeErr = errors.Join(probeErr, conn.Close()) }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return result, fmt.Errorf("probe deadline: %w", err)
	}
	authKey := []byte{}
	verify := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("probe: no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse probe certificate: %w", err)
		}
		if key, ok := cert.PublicKey.(ed25519.PublicKey); ok {
			mac := hmac.New(sha512.New, authKey)
			if _, err := mac.Write(key); err != nil {
				return fmt.Errorf("probe certificate mac: %w", err)
			}
			result.Authenticated = hmac.Equal(mac.Sum(nil), cert.Signature)
			if result.Authenticated {
				return nil
			}
		}
		intermediates := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			intermediate, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("parse origin chain: %w", err)
			}
			intermediates.AddCert(intermediate)
		}
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: opt.SNI, Roots: roots, Intermediates: intermediates}); err != nil {
			return fmt.Errorf("verify actual origin certificate: %w", err)
		}
		result.OriginVerified = true
		return nil
	}
	tap := &tapConn{Conn: conn, fragment: opt.Fragment, state: state, capture: opt.Capture, statePath: opt.State, isReplay: opt.ReplayState != ""}
	config := &utls.Config{
		ServerName: opt.SNI,
		// REALITY replaces PKIX authentication with its HMAC certificate. The
		// callback enforces that HMAC OR real origin chain/SAN/expiry, never nil
		// verification. TLS CertificateVerify and Finished remain library-owned.
		InsecureSkipVerify:     true,
		VerifyPeerCertificate:  verify,
		SessionTicketsDisabled: true,
		MinVersion:             utls.VersionTLS13,
		MaxVersion:             utls.VersionTLS13,
	}
	fingerprint := utls.HelloFirefox_Auto
	if tap.isReplay {
		// The documented HelloGolang build-once path lets the public parsed
		// Firefox hello replace generated fields WITHOUT a later remarshal.
		// No completed TLS state is copied; the handshake/transcript are fresh.
		fingerprint = utls.HelloGolang
		hello := utls.UnmarshalClientHello(state.Hello)
		if hello == nil {
			return result, errors.New("probe: recorded client hello cannot be parsed")
		}
		config.NextProtos = hello.AlpnProtocols
	}
	client := utls.UClient(tap, config, fingerprint)
	if err := client.BuildHandshakeState(); err != nil {
		return result, fmt.Errorf("build probe hello: %w", err)
	}
	if tap.isReplay {
		client.HandshakeState.Hello = utls.UnmarshalClientHello(state.Hello)
		keys, err := restoredKeys(state)
		if err != nil {
			return result, err
		}
		client.HandshakeState.State13.KeyShareKeys = keys
		specification, err := (&utls.Fingerprinter{}).FingerprintClientHello(state.Record)
		if err != nil {
			return result, fmt.Errorf("parse recorded handshake extensions: %w", err)
		}
		// Retain handlers such as certificate compression from the exact
		// recorded hello. HelloGolang will not reapply/remarshal extensions.
		client.Extensions = specification.Extensions
	}
	hello := client.HandshakeState.Hello
	if len(hello.Raw) < 71 {
		return result, errors.New("probe: short hello")
	}
	authKey, err = authenticationKey(hello, client.HandshakeState.State13.KeyShareKeys, opt.PublicKey)
	if err != nil {
		return result, err
	}
	if !tap.isReplay {
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId)
		hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 26, 11, 9
		binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(state.RecordedUnix+opt.OffsetSeconds))
		shortID, err := hex.DecodeString(opt.ShortID)
		if err != nil || len(shortID) != 8 {
			return result, errors.New("probe: invalid short id")
		}
		copy(hello.SessionId[8:], shortID)
		block, err := aes.NewCipher(authKey)
		if err != nil {
			return result, fmt.Errorf("probe cipher: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return result, fmt.Errorf("probe gcm: %w", err)
		}
		aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
		state.Hello = bytes.Clone(hello.Raw)
		if err := retainedKeys(client.HandshakeState.State13.KeyShareKeys, state); err != nil {
			return result, err
		}
	}
	handshakeStarted := time.Now()
	if err := client.HandshakeContext(ctx); err != nil {
		return result, fmt.Errorf("probe handshake: %w", err)
	}
	result.HandshakeComplete = client.ConnectionState().HandshakeComplete
	result.HandshakeSeconds = time.Since(handshakeStarted).Seconds()
	if !result.HandshakeComplete || (!result.Authenticated && !result.OriginVerified) || !tap.hasCaptured {
		return result, errors.New("probe: no verified authentication verdict")
	}
	hasResponseTiming := !tap.firstWriteAt.IsZero() && !tap.firstResponseAt.IsZero()
	if !hasResponseTiming || tap.responseBytes == 0 {
		return result, errors.New("probe: no actual server response timing")
	}
	result.FirstResponseSeconds = tap.firstResponseAt.Sub(tap.firstWriteAt).Seconds()
	result.ServerResponseBytes = tap.responseBytes
	helloDigest, recordDigest := sha256.Sum256(state.Hello), sha256.Sum256(state.Record)
	result.HelloSHA256 = hex.EncodeToString(helloDigest[:])
	result.RecordSHA256 = hex.EncodeToString(recordDigest[:])
	result.RecordedUnix = state.RecordedUnix
	return result, nil
}

func run() error {
	isDisposable := runtime.GOOS == "linux" && os.Geteuid() == 0
	isHosted := os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted"
	if !isDisposable || !isHosted || os.Getenv("VPN_PROFILES_DISPOSABLE_GUEST") != "yes" {
		return errors.New("probe: guarded disposable guest required")
	}
	if len(os.Args) != 2 {
		return errors.New("probe: private input file required")
	}
	if err := privatePath(os.Args[1], true); err != nil {
		return err
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return fmt.Errorf("read probe input: %w", err)
	}
	var opt options
	if err := json.Unmarshal(data, &opt); err != nil {
		return fmt.Errorf("decode probe input: %w", err)
	}
	if opt.Fragment < 0 || opt.Fragment > 65535 {
		return errors.New("probe: invalid fragment size")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := probe(ctx, opt)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(); err != nil {
		// Input-dependent details stay private; no tokens or ephemeral keys out.
		fmt.Fprintln(os.Stderr, "disposable reality probe failed")
		os.Exit(1)
	}
}
