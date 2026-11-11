package wireguard

// XrayOutbound is an Xray outbound object using the wireguard protocol. Field
// names follow infra/conf/wireguard.go of the pinned Xray-core v26.11.9.
//
// The value contains the private and preshared keys in clear text: treat the
// marshalled JSON as a secret.
type XrayOutbound struct {
	Tag      string       `json:"tag,omitempty"`
	Protocol string       `json:"protocol"`
	Settings XraySettings `json:"settings"`
}

// XraySettings is the wireguard outbound "settings" object.
type XraySettings struct {
	SecretKey string     `json:"secretKey"`
	Address   []string   `json:"address"`
	Peers     []XrayPeer `json:"peers"`
	// MTU is omitted when the config does not set it; Xray then uses 1420.
	MTU int `json:"mtu,omitempty"`
	// RemoteDNS is omitted without DNS; Xray then uses its built-in resolvers.
	RemoteDNS []string `json:"remoteDNS,omitempty"`
	// NoKernelTun is always true: each outbound uses the userspace stack, so
	// several Xray instances never contend for kernel TUN devices and routes.
	NoKernelTun bool `json:"noKernelTun"`
}

// XrayPeer is one entry of XraySettings.Peers.
type XrayPeer struct {
	PublicKey    string `json:"publicKey"`
	PreSharedKey string `json:"preSharedKey,omitempty"`
	Endpoint     string `json:"endpoint"`
	KeepAlive    uint16 `json:"keepAlive,omitempty"`
	// AllowedIPs is always emitted: an empty list would make Xray fall back
	// to routing everything through the peer.
	AllowedIPs []string `json:"allowedIPs"`
}

// XrayOutbound converts the config to an Xray wireguard outbound with the
// given tag. It does not validate the result against a running Xray.
func (c *Config) XrayOutbound(tag string) XrayOutbound {
	s := XraySettings{
		SecretKey:   c.Interface.PrivateKey.Base64(),
		Address:     make([]string, len(c.Interface.Addresses)),
		Peers:       make([]XrayPeer, len(c.Peers)),
		MTU:         c.Interface.MTU,
		NoKernelTun: true,
	}
	for i, a := range c.Interface.Addresses {
		s.Address[i] = a.String()
	}
	for _, d := range c.Interface.DNS {
		s.RemoteDNS = append(s.RemoteDNS, d.String())
	}
	for i, p := range c.Peers {
		xp := XrayPeer{
			PublicKey:  p.PublicKey.Base64(),
			Endpoint:   p.Endpoint.String(),
			KeepAlive:  p.PersistentKeepalive,
			AllowedIPs: make([]string, len(p.AllowedIPs)),
		}
		if p.PresharedKey != nil {
			xp.PreSharedKey = p.PresharedKey.Base64()
		}
		for j, a := range p.AllowedIPs {
			xp.AllowedIPs[j] = a.String()
		}
		s.Peers[i] = xp
	}
	return XrayOutbound{Tag: tag, Protocol: "wireguard", Settings: s}
}
