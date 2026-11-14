package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func TestTLSFactsTrackVerifiedAndWrongSNI(t *testing.T) {
	for _, wrongName := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "wrong sni"}[wrongName], func(t *testing.T) {
			pki := newPKI(t)
			leaf := pki.leaf(t, time.Now().Add(time.Hour), "cover.example.test")
			certificate, err := x509.ParseCertificate(leaf.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			server := newRawServer(t, "tcp4", "127.0.0.1:0", func(conn net.Conn, _ <-chan struct{}) {
				tlsConn := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{leaf}, NextProtos: []string{"http/1.1"},
				})
				_ = tlsConn.Handshake()
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			name := "cover.example.test"
			if wrongName {
				name = "wrong.example.test"
			}
			observation := TLS(ctx, TLSRequest{
				Target: target(server.addr, IPv4), ServerName: name, RootCAs: pki.pool,
			}).Last()
			facts := observation.Certificate
			issuer := sha256.Sum256(certificate.RawIssuer)
			if facts == nil || facts.IssuerSHA256 != hex.EncodeToString(issuer[:]) || facts.NotBefore != certificate.NotBefore || facts.NotAfter != certificate.NotAfter {
				t.Fatalf("certificate facts do not match observed peer: %+v", facts)
			}
			if wrongName {
				if observation.Outcome != OutcomeHostnameMismatch || facts.Verified || facts.SANMatch {
					t.Fatalf("wrong SNI was verified or hidden: %+v", observation)
				}
			} else if observation.Outcome != OutcomeSuccess || !facts.Verified || !facts.SANMatch || facts.ALPN != "http/1.1" {
				t.Fatalf("verified TLS facts missing: %+v", observation)
			}
		})
	}
}

func TestPinnedVersionRejectsStaleAndPrefixLookalikes(t *testing.T) {
	for _, test := range []struct {
		output             string
		overflow, accepted bool
	}{
		{output: "Xray 26.11.9 (Xray, Penetrates Everything.)\n", accepted: true},
		{output: "Xray 26.11.8 (Xray)\n"},
		{output: "Xray 26.11.90 (Xray)\n"},
		{output: "Xray 26.11.9-stale (Xray)\n"},
		{output: "not Xray 26.11.9 (Xray)\n"},
		{output: "Xray 26.11.9 (Xray)\n", overflow: true},
	} {
		if got := pinnedVersion([]byte(test.output), test.overflow); got != test.accepted {
			t.Fatalf("version gate accepted=%t; want %t", got, test.accepted)
		}
	}
}
