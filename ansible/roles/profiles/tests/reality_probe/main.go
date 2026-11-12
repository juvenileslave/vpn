// Command reality-probe exercises timestamped REALITY TLS, never VLESS/tunnel access.
// Token derivation follows Xray 26.11.9 transport/internet/reality/reality.go.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
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
	"time"

	utls "github.com/refraction-networking/utls"
)

type options struct {
	Address string `json:"address"`
	SNI string `json:"sni"`
	PublicKey string `json:"public_key"`
	ShortID string `json:"short_id"`
	OffsetSeconds int64 `json:"offset_seconds"`
	Capture string `json:"capture"`
	Fragment int `json:"fragment"`
}

type tapConn struct {
	net.Conn
	capture string
	fragment int
	hasCaptured bool
}

func (c *tapConn) Write(data []byte) (int, error) {
	if !c.hasCaptured {
		if err := os.WriteFile(c.capture, data, 0600); err != nil {
			return 0, fmt.Errorf("capture hello: %w", err)
		}
		c.hasCaptured = true
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
		data = data[written:]
		time.Sleep(time.Millisecond)
	}
	return total, nil
}

func probe(ctx context.Context, opt options) (authenticated bool, probeErr error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", opt.Address)
	if err != nil {
		return false, fmt.Errorf("dial probe: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			probeErr = errors.Join(probeErr, fmt.Errorf("close probe: %w", err))
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return false, fmt.Errorf("probe deadline: %w", err)
	}
	var isAuthenticated bool
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
			isAuthenticated = hmac.Equal(mac.Sum(nil), cert.Signature)
		}
		// A normal origin certificate is an observed negative-auth outcome only.
		// This probe never sends application data or asserts certificate trust.
		return nil
	}
	tap := &tapConn{Conn: conn, capture: opt.Capture, fragment: opt.Fragment}
	client := utls.UClient(tap, &utls.Config{
		ServerName: opt.SNI,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: verify,
		SessionTicketsDisabled: true,
	}, utls.HelloFirefox_Auto)
	if err := client.BuildHandshakeState(); err != nil {
		return false, fmt.Errorf("build probe hello: %w", err)
	}
	hello := client.HandshakeState.Hello
	if len(hello.Raw) < 71 {
		return false, errors.New("probe: short hello")
	}
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 26, 11, 9
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()+opt.OffsetSeconds))
	shortID, err := hex.DecodeString(opt.ShortID)
	if err != nil {
		return false, fmt.Errorf("decode probe short id: %w", err)
	}
	copy(hello.SessionId[8:], shortID)
	public, err := base64.RawURLEncoding.DecodeString(opt.PublicKey)
	if err != nil {
		return false, fmt.Errorf("decode probe public key: %w", err)
	}
	key, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return false, fmt.Errorf("probe public key: %w", err)
	}
	ephemeral := client.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ephemeral == nil {
		ephemeral = client.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ephemeral == nil {
		return false, errors.New("probe: fingerprint has no x25519 key")
	}
	shared, err := ephemeral.ECDH(key)
	if err != nil {
		return false, fmt.Errorf("probe shared key: %w", err)
	}
	authKey, err = hkdf.Key(
		sha256.New,
		shared,
		hello.Random[:20],
		"REALITY",
		32,
	)
	if err != nil {
		return false, fmt.Errorf("derive probe key: %w", err)
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return false, fmt.Errorf("probe cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return false, fmt.Errorf("probe gcm: %w", err)
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if err := client.HandshakeContext(ctx); err != nil {
		return false, fmt.Errorf("probe handshake: %w", err)
	}
	return isAuthenticated, nil
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("probe: private input file required")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return fmt.Errorf("read probe input: %w", err)
	}
	var opt options
	if err := json.Unmarshal(data, &opt); err != nil {
		return fmt.Errorf("decode probe input: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	authenticated, err := probe(ctx, opt)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]bool{"reality_authenticated": authenticated})
}

func main() {
	if err := run(); err != nil {
		// Never print detailed input-dependent errors or token material.
		fmt.Fprintln(os.Stderr, "disposable reality probe failed")
		os.Exit(1)
	}
}
