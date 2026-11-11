package vless

import "strings"

// Outbound is an Xray v26.11.9 outbound object for one link. It marshals to
// the JSON accepted under "outbounds" in an Xray configuration.
type Outbound struct {
	Tag            string           `json:"tag,omitempty"`
	Protocol       string           `json:"protocol"`
	Settings       OutboundSettings `json:"settings"`
	StreamSettings StreamSettings   `json:"streamSettings"`
}

// OutboundSettings is the VLESS outbound "settings" object.
type OutboundSettings struct {
	Vnext []Server `json:"vnext"`
}

// Server is one VLESS server endpoint.
type Server struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Users   []User `json:"users"`
}

// User is a VLESS user. ID is a credential.
type User struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

// StreamSettings is the outbound "streamSettings" object.
type StreamSettings struct {
	Network         string           `json:"network"`
	Security        string           `json:"security"`
	TLSSettings     *TLSSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *RealitySettings `json:"realitySettings,omitempty"`
	XHTTPSettings   *XHTTPSettings   `json:"xhttpSettings,omitempty"`
}

// TLSSettings is the client "tlsSettings" object.
type TLSSettings struct {
	ServerName           string   `json:"serverName,omitempty"`
	Fingerprint          string   `json:"fingerprint"`
	ALPN                 []string `json:"alpn,omitempty"`
	PinnedPeerCertSHA256 string   `json:"pinnedPeerCertSha256,omitempty"`
	VerifyPeerCertByName string   `json:"verifyPeerCertByName,omitempty"`
}

// RealitySettings is the client "realitySettings" object.
type RealitySettings struct {
	ServerName    string `json:"serverName"`
	Fingerprint   string `json:"fingerprint"`
	Password      string `json:"password"`
	ShortID       string `json:"shortId,omitempty"`
	SpiderX       string `json:"spiderX,omitempty"`
	MLDSA65Verify string `json:"mldsa65Verify,omitempty"`
}

// XHTTPSettings is the "xhttpSettings" object; supported extra options are
// emitted inline, which Xray treats the same as a nested "extra".
type XHTTPSettings struct {
	Host string `json:"host,omitempty"`
	Path string `json:"path"`
	Mode string `json:"mode"`
	*XHTTPExtra
}

// Outbound builds the Xray outbound for l. The tag is chosen by the caller;
// the display label is deliberately not used.
func (l *Link) Outbound(tag string) Outbound {
	o := Outbound{
		Tag:      tag,
		Protocol: "vless",
		Settings: OutboundSettings{Vnext: []Server{{
			Address: l.Address,
			Port:    l.Port,
			Users:   []User{{ID: l.ID, Encryption: l.Encryption, Flow: l.Flow}},
		}}},
		StreamSettings: StreamSettings{Network: string(l.Transport), Security: string(l.Security)},
	}
	if t := l.TLS; t != nil {
		o.StreamSettings.TLSSettings = &TLSSettings{
			ServerName:           t.ServerName,
			Fingerprint:          t.Fingerprint,
			ALPN:                 append([]string(nil), t.ALPN...),
			PinnedPeerCertSHA256: strings.Join(t.PinnedPeerCertSHA256, ","),
			VerifyPeerCertByName: strings.Join(t.VerifyPeerCertByName, ","),
		}
	}
	if r := l.Reality; r != nil {
		o.StreamSettings.RealitySettings = &RealitySettings{
			ServerName:    r.ServerName,
			Fingerprint:   r.Fingerprint,
			Password:      r.PublicKey,
			ShortID:       r.ShortID,
			SpiderX:       r.SpiderX,
			MLDSA65Verify: r.MLDSA65Verify,
		}
	}
	if x := l.XHTTP; x != nil {
		o.StreamSettings.XHTTPSettings = &XHTTPSettings{Host: x.Host, Path: x.Path, Mode: x.Mode, XHTTPExtra: x.Extra}
	}
	return o
}
