package trojan

// Outbound is an Xray v26.11.9 outbound object for one link. It marshals to
// the JSON accepted under "outbounds" in an Xray configuration.
type Outbound struct {
	Tag            string           `json:"tag,omitempty"`
	Protocol       string           `json:"protocol"`
	Settings       OutboundSettings `json:"settings"`
	StreamSettings StreamSettings   `json:"streamSettings"`
}

// OutboundSettings is the trojan outbound "settings" object.
type OutboundSettings struct {
	Servers []Server `json:"servers"`
}

// Server is one trojan server endpoint. Password is a credential.
type Server struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Password string `json:"password"`
}

// StreamSettings is the outbound "streamSettings" object.
type StreamSettings struct {
	Network     string       `json:"network"`
	Security    string       `json:"security"`
	TLSSettings *TLSSettings `json:"tlsSettings,omitempty"`
}

// TLSSettings is the client "tlsSettings" object.
type TLSSettings struct {
	ServerName string   `json:"serverName,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
}

// Outbound builds the Xray outbound for l. The tag is chosen by the caller;
// the display label is deliberately not used.
func (l *Link) Outbound(tag string) Outbound {
	o := Outbound{
		Tag:      tag,
		Protocol: "trojan",
		Settings: OutboundSettings{Servers: []Server{{
			Address:  l.Address,
			Port:     l.Port,
			Password: l.Password,
		}}},
		StreamSettings: StreamSettings{Network: string(l.Transport), Security: "tls"},
	}
	if l.TLS.ServerName != "" || len(l.TLS.ALPN) > 0 {
		o.StreamSettings.TLSSettings = &TLSSettings{
			ServerName: l.TLS.ServerName,
			ALPN:       append([]string(nil), l.TLS.ALPN...),
		}
	}
	return o
}
