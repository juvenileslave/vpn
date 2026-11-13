package shadowsocks

// Outbound is an Xray v26.11.9 outbound object for one link. It marshals to
// the JSON accepted under "outbounds" in an Xray configuration. Shadowsocks
// runs over a plain TCP connection; no stream settings are emitted.
type Outbound struct {
	Tag      string           `json:"tag,omitempty"`
	Protocol string           `json:"protocol"`
	Settings OutboundSettings `json:"settings"`
}

// OutboundSettings is the shadowsocks outbound "settings" object.
type OutboundSettings struct {
	Servers []Server `json:"servers"`
}

// Server is one shadowsocks server endpoint. Password is a credential.
type Server struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

// Outbound builds the Xray outbound for l. The tag is chosen by the caller;
// the display label is deliberately not used.
func (l *Link) Outbound(tag string) Outbound {
	return Outbound{
		Tag:      tag,
		Protocol: "shadowsocks",
		Settings: OutboundSettings{Servers: []Server{{
			Address:  l.Address,
			Port:     l.Port,
			Method:   l.Method,
			Password: l.Password,
		}}},
	}
}
