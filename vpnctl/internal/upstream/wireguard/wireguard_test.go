package wireguard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// synthKey returns a valid, obviously synthetic key filled with b.
func synthKey(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, KeyLen))
}

var (
	privKey = synthKey(0x01)
	pubKey1 = synthKey(0x02)
	pubKey2 = synthKey(0x03)
	psk     = synthKey(0x04)
)

func dualStackConfig() string {
	return "# synthetic client config\n" +
		"[Interface]\n" +
		"PrivateKey = " + privKey + "\n" +
		"Address = 10.8.0.2/24, fd00:8::2/64\n" +
		"DNS = 192.0.2.53, 2001:db8::53\n" +
		"MTU = 1380\n" +
		"\n" +
		"[Peer]\n" +
		"PublicKey = " + pubKey1 + "\n" +
		"PresharedKey = " + psk + "\n" +
		"Endpoint = [2001:db8::10]:51820 # IPv6 endpoint\n" +
		"AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n" +
		"AllowedIPs = ::/0\n" +
		"PersistentKeepalive = 25\n" +
		"\n" +
		"[Peer]\n" +
		"PublicKey = " + pubKey2 + "\n" +
		"Endpoint = vpn.example.com:443\n" +
		"AllowedIPs = 10.9.0.0/16\n"
}

func TestParseDualStackMultiplePeers(t *testing.T) {
	cfg, err := Parse([]byte(dualStackConfig()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ifc := cfg.Interface
	if ifc.PrivateKey.Base64() != privKey {
		t.Error("private key not preserved")
	}
	wantAddr := []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24"), netip.MustParsePrefix("fd00:8::2/64")}
	if !reflect.DeepEqual(ifc.Addresses, wantAddr) {
		t.Errorf("Addresses = %v, want %v", ifc.Addresses, wantAddr)
	}
	wantDNS := []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")}
	if !reflect.DeepEqual(ifc.DNS, wantDNS) {
		t.Errorf("DNS = %v, want %v", ifc.DNS, wantDNS)
	}
	if ifc.MTU != 1380 {
		t.Errorf("MTU = %d", ifc.MTU)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("got %d peers", len(cfg.Peers))
	}

	p1 := cfg.Peers[0]
	if p1.PublicKey.Base64() != pubKey1 || p1.PresharedKey == nil || p1.PresharedKey.Base64() != psk {
		t.Error("peer 1 keys not preserved")
	}
	if p1.Endpoint != (Endpoint{Host: "2001:db8::10", Port: 51820}) || !p1.Endpoint.IsIP() {
		t.Errorf("peer 1 endpoint = %+v", p1.Endpoint)
	}
	if got := p1.Endpoint.String(); got != "[2001:db8::10]:51820" {
		t.Errorf("peer 1 endpoint string = %q", got)
	}
	wantAllowed := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"), netip.MustParsePrefix("::/0"),
	}
	if !reflect.DeepEqual(p1.AllowedIPs, wantAllowed) {
		t.Errorf("peer 1 AllowedIPs = %v", p1.AllowedIPs)
	}
	if p1.PersistentKeepalive != 25 {
		t.Errorf("peer 1 keepalive = %d", p1.PersistentKeepalive)
	}

	p2 := cfg.Peers[1]
	if p2.PresharedKey != nil || p2.PersistentKeepalive != 0 {
		t.Error("peer 2 must have no preshared key and no keepalive")
	}
	if p2.Endpoint != (Endpoint{Host: "vpn.example.com", Port: 443}) || p2.Endpoint.IsIP() {
		t.Errorf("peer 2 endpoint = %+v", p2.Endpoint)
	}
}

func TestParseNormalisation(t *testing.T) {
	src := "\xef\xbb\xbf[interface]\r\n" +
		"privatekey=" + privKey + "\r\n" +
		"Address = 10.8.0.2\r\n" +
		"Address = fd00::2\r\n" +
		"[PEER]\r\n" +
		"PublicKey = " + pubKey1 + "\r\n" +
		"Endpoint = 192.0.2.1:51820\r\n" +
		"AllowedIPs = 192.0.2.128\r\n" +
		"PersistentKeepalive = off\r\n"
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32"), netip.MustParsePrefix("fd00::2/128")}
	if !reflect.DeepEqual(cfg.Interface.Addresses, want) {
		t.Errorf("Addresses = %v", cfg.Interface.Addresses)
	}
	if got := cfg.Peers[0].AllowedIPs; len(got) != 1 || got[0] != netip.MustParsePrefix("192.0.2.128/32") {
		t.Errorf("AllowedIPs = %v", got)
	}
	if cfg.Peers[0].PersistentKeepalive != 0 || cfg.Interface.MTU != 0 || cfg.Interface.DNS != nil {
		t.Error("unset optional fields must stay zero")
	}
}

func TestXrayOutboundMapping(t *testing.T) {
	cfg, err := Parse([]byte(dualStackConfig()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := cfg.XrayOutbound("wg-test")
	want := XrayOutbound{
		Tag:      "wg-test",
		Protocol: "wireguard",
		Settings: XraySettings{
			SecretKey: privKey,
			Address:   []string{"10.8.0.2/24", "fd00:8::2/64"},
			Peers: []XrayPeer{
				{
					PublicKey:    pubKey1,
					PreSharedKey: psk,
					Endpoint:     "[2001:db8::10]:51820",
					KeepAlive:    25,
					AllowedIPs:   []string{"0.0.0.0/1", "128.0.0.0/1", "::/0"},
				},
				{
					PublicKey:  pubKey2,
					Endpoint:   "vpn.example.com:443",
					AllowedIPs: []string{"10.9.0.0/16"},
				},
			},
			MTU:         1380,
			RemoteDNS:   []string{"192.0.2.53", "2001:db8::53"},
			NoKernelTun: true,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("XrayOutbound mismatch\n got: %+v\nwant: %+v", got, want)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	settings := generic["settings"].(map[string]any)
	for _, k := range []string{"secretKey", "address", "peers", "mtu", "remoteDNS", "noKernelTun"} {
		if _, ok := settings[k]; !ok {
			t.Errorf("settings JSON lacks %q", k)
		}
	}
	peer := settings["peers"].([]any)[0].(map[string]any)
	for _, k := range []string{"publicKey", "preSharedKey", "endpoint", "keepAlive", "allowedIPs"} {
		if _, ok := peer[k]; !ok {
			t.Errorf("peer JSON lacks %q", k)
		}
	}
}

func TestXrayOutboundOmitsUnsetOptionals(t *testing.T) {
	src := "[Interface]\nPrivateKey = " + privKey + "\nAddress = 10.8.0.2/32\n" +
		"[Peer]\nPublicKey = " + pubKey1 + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	raw, err := json.Marshal(cfg.XrayOutbound(""))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"mtu"`, `"remoteDNS"`, `"preSharedKey"`, `"keepAlive"`, `"tag"`} {
		if bytes.Contains(raw, []byte(k)) {
			t.Errorf("JSON unexpectedly contains %s", k)
		}
	}
	if !bytes.Contains(raw, []byte(`"noKernelTun":true`)) {
		t.Error("noKernelTun must be true")
	}
}

func TestEndpoints(t *testing.T) {
	tests := []struct {
		in   string
		want Endpoint
		ok   bool
	}{
		{"192.0.2.1:51820", Endpoint{"192.0.2.1", 51820}, true},
		{"[2001:db8::1]:1", Endpoint{"2001:db8::1", 1}, true},
		{"[2001:DB8:0::1]:65535", Endpoint{"2001:db8::1", 65535}, true},
		{"vpn-1.example.com:51820", Endpoint{"vpn-1.example.com", 51820}, true},
		{"2001:db8::1:51820", Endpoint{}, false},
		{"[2001:db8::1]", Endpoint{}, false},
		{"[192.0.2.1]:51820", Endpoint{}, false},
		{"[vpn.example.com]:51820", Endpoint{}, false},
		{"[fe80::1%eth0]:51820", Endpoint{}, false},
		{"0.0.0.0:51820", Endpoint{}, false},
		{"192.0.2.1:0", Endpoint{}, false},
		{"192.0.2.1:65536", Endpoint{}, false},
		{"192.0.2.1:-1", Endpoint{}, false},
		{"192.0.2.1:+80", Endpoint{}, false},
		{"192.0.2.1:", Endpoint{}, false},
		{"192.0.2.1", Endpoint{}, false},
		{"300.0.2.1:51820", Endpoint{}, false},
		{"-bad.example.com:51820", Endpoint{}, false},
		{"bad_host.example.com:51820", Endpoint{}, false},
		{":51820", Endpoint{}, false},
	}
	for _, tt := range tests {
		got, reason := parseEndpoint(tt.in)
		if ok := reason == ""; ok != tt.ok || got != tt.want {
			t.Errorf("parseEndpoint(%q) = %+v, %q; want %+v ok=%v", tt.in, got, reason, tt.want, tt.ok)
		}
	}
}

// build replaces one line of a minimal valid config and returns it.
func build(ifaceExtra, peerExtra string) string {
	return "[Interface]\nPrivateKey = " + privKey + "\nAddress = 10.8.0.2/32, fd00::2/128\n" + ifaceExtra +
		"[Peer]\nPublicKey = " + pubKey1 + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n" + peerExtra
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		kind    error
		line    int
		section string
		key     string
	}{
		{"short private key", strings.Replace(build("", ""), privKey, privKey[:43], 1), ErrInvalid, 2, "Interface", "PrivateKey"},
		{"private key wrong length decoded", strings.Replace(build("", ""), privKey, base64.StdEncoding.EncodeToString(make([]byte, 33))[:44], 1), ErrInvalid, 2, "Interface", "PrivateKey"},
		{"non-canonical base64", strings.Replace(build("", ""), privKey, privKey[:42]+"F=", 1), ErrInvalid, 2, "Interface", "PrivateKey"},
		{"public key not base64", strings.Replace(build("", ""), pubKey1, strings.Repeat("!", 44), 1), ErrInvalid, 5, "Peer 1", "PublicKey"},
		{"bad preshared key", build("", "PresharedKey = abc\n"), ErrInvalid, 8, "Peer 1", "PresharedKey"},
		{"bad address", build("Address = 10.8.0.300/32\n", ""), ErrInvalid, 4, "Interface", "Address"},
		{"bad address prefix", build("Address = 10.8.0.3/33\n", ""), ErrInvalid, 4, "Interface", "Address"},
		{"duplicate address", build("Address = 10.8.0.2/24\n", ""), ErrDuplicate, 4, "Interface", "Address"},
		{"bad allowed ip", build("", "AllowedIPs = 2001:db8::/129\n"), ErrInvalid, 8, "Peer 1", "AllowedIPs"},
		{"allowed ip garbage", build("", "AllowedIPs = 10.0.0.0/8, nope\n"), ErrInvalid, 8, "Peer 1", "AllowedIPs"},
		{"empty list item", build("DNS = 192.0.2.53,,192.0.2.54\n", ""), ErrSyntax, 4, "Interface", "DNS"},
		{"empty value", build("", "AllowedIPs =\n"), ErrInvalid, 8, "Peer 1", "AllowedIPs"},
		{"dns search domain", build("DNS = 192.0.2.53, corp.example\n", ""), ErrUnsupported, 4, "Interface", "DNS"},
		{"mtu too small", build("MTU = 100\n", ""), ErrInvalid, 4, "Interface", "MTU"},
		{"mtu not int", build("MTU = auto\n", ""), ErrInvalid, 4, "Interface", "MTU"},
		{"mtu below ipv6 minimum", build("MTU = 1200\n", ""), ErrInvalid, 4, "Interface", "MTU"},
		{"bad endpoint port", strings.Replace(build("", ""), "192.0.2.1:51820", "192.0.2.1:70000", 1), ErrInvalid, 6, "Peer 1", "Endpoint"},
		{"unbracketed ipv6 endpoint", strings.Replace(build("", ""), "192.0.2.1:51820", "2001:db8::1:51820", 1), ErrInvalid, 6, "Peer 1", "Endpoint"},
		{"keepalive out of range", build("", "PersistentKeepalive = 70000\n"), ErrInvalid, 8, "Peer 1", "PersistentKeepalive"},
		{"keepalive negative", build("", "PersistentKeepalive = -1\n"), ErrInvalid, 8, "Peer 1", "PersistentKeepalive"},
		{"duplicate single key", build("MTU = 1400\nMTU = 1420\n", ""), ErrDuplicate, 5, "Interface", "MTU"},
		{"duplicate allowed ip across peers", build("", "[Peer]\nPublicKey = "+pubKey2+"\nEndpoint = 192.0.2.2:51820\nAllowedIPs = 0.0.0.0/0\n"), ErrDuplicate, 11, "Peer 2", "AllowedIPs"},
		{"duplicate peer key", build("", "[Peer]\nPublicKey = "+pubKey1+"\nEndpoint = 192.0.2.2:51820\nAllowedIPs = 10.0.0.0/8\n"), ErrDuplicate, 8, "Peer 2", "PublicKey"},
		{"missing private key", strings.Replace(build("", ""), "PrivateKey = "+privKey+"\n", "", 1), ErrMissing, 1, "Interface", "PrivateKey"},
		{"missing address", strings.Replace(build("", ""), "Address = 10.8.0.2/32, fd00::2/128\n", "", 1), ErrMissing, 1, "Interface", "Address"},
		{"missing public key", strings.Replace(build("", ""), "PublicKey = "+pubKey1+"\n", "", 1), ErrMissing, 4, "Peer 1", "PublicKey"},
		{"missing endpoint", strings.Replace(build("", ""), "Endpoint = 192.0.2.1:51820\n", "", 1), ErrMissing, 4, "Peer 1", "Endpoint"},
		{"missing allowed ips", strings.Replace(build("", ""), "AllowedIPs = 0.0.0.0/0\n", "", 1), ErrMissing, 4, "Peer 1", "AllowedIPs"},
		{"missing interface", "[Peer]\nPublicKey = " + pubKey1 + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n", ErrMissing, 0, "Interface", ""},
		{"missing peer", "[Interface]\nPrivateKey = " + privKey + "\nAddress = 10.8.0.2/32\n", ErrMissing, 0, "Peer", ""},
		{"second interface", build("", "[Interface]\n"), ErrDuplicate, 8, "Interface", ""},
		{"unknown section", build("", "[Proxy]\n"), ErrUnsupported, 8, "", ""},
		{"malformed header", build("", "[Peer\n"), ErrSyntax, 8, "", ""},
		{"key outside section", "PrivateKey = " + privKey + "\n" + build("", ""), ErrSyntax, 1, "", "PrivateKey"},
		{"line without equals", build("", "AllowedIPs\n"), ErrSyntax, 8, "Peer 1", ""},
		{"unknown key", build("Jc = 4\n", ""), ErrUnsupported, 4, "Interface", ""},
		{"interface key in peer", build("", "MTU = 1400\n"), ErrUnsupported, 8, "Peer 1", "MTU"},
		{"peer key in interface", build("Endpoint = 192.0.2.1:51820\n", ""), ErrUnsupported, 4, "Interface", "Endpoint"},
		{"table", build("Table = off\n", ""), ErrUnsupported, 4, "Interface", "Table"},
		{"fwmark", build("FwMark = 0x1234\n", ""), ErrUnsupported, 4, "Interface", "FwMark"},
		{"listen port", build("ListenPort = 51820\n", ""), ErrUnsupported, 4, "Interface", "ListenPort"},
		{"save config", build("SaveConfig = true\n", ""), ErrUnsupported, 4, "Interface", "SaveConfig"},
		{"too large", strings.Repeat("#", MaxConfigSize+1), ErrInvalid, 0, "", ""},
		{"nul byte", build("\x00\n", ""), ErrSyntax, 0, "", ""},
		{"invalid utf8", build("\xff\n", ""), ErrSyntax, 0, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.src))
			if err == nil {
				t.Fatalf("Parse succeeded: %+v", cfg)
			}
			if cfg != nil {
				t.Error("config must be nil on error")
			}
			if !errors.Is(err, tt.kind) {
				t.Fatalf("error %q is not %v", err, tt.kind)
			}
			if !hasError(err, tt.kind, tt.line, tt.section, tt.key) {
				t.Errorf("no error with line=%d section=%q key=%q in:\n%v", tt.line, tt.section, tt.key, err)
			}
		})
	}
}

func hasError(err error, kind error, line int, section, key string) bool {
	var list ErrorList
	if !errors.As(err, &list) {
		return false
	}
	for _, e := range list {
		if e.Kind == kind && e.Line == line && e.Section == section && e.Key == key {
			return true
		}
	}
	return false
}

func TestHooksRejected(t *testing.T) {
	marker := "touch /tmp/wireguard-parser-must-not-run"
	for _, key := range []string{"PreUp", "PostUp", "PreDown", "PostDown", "postup", "POSTDOWN"} {
		t.Run(key, func(t *testing.T) {
			for _, src := range []string{
				build(key+" = "+marker+"\n", ""),
				build("", key+" = "+marker+"\n"),
				key + " = " + marker + "\n" + build("", ""),
				build(key+" =\n", ""),
			} {
				_, err := Parse([]byte(src))
				if !errors.Is(err, ErrHook) {
					t.Fatalf("hook not rejected: %v", err)
				}
				if strings.Contains(err.Error(), marker) {
					t.Fatal("error echoes hook command")
				}
				var list ErrorList
				errors.As(err, &list)
				canonical := map[string]string{"postup": "PostUp", "POSTDOWN": "PostDown"}[key]
				if canonical == "" {
					canonical = key
				}
				if !hasErrorKey(list, ErrHook, canonical) {
					t.Errorf("hook error lacks key %q: %v", canonical, err)
				}
			}
		})
	}
}

func hasErrorKey(list ErrorList, kind error, key string) bool {
	for _, e := range list {
		if e.Kind == kind && e.Key == key {
			return true
		}
	}
	return false
}

func TestErrorsDoNotLeakSecrets(t *testing.T) {
	secretish := synthKey(0x5a)
	src := "[Interface]\n" +
		"PrivateKey = " + secretish[:43] + "\n" + // malformed key
		secretish + "\n" + // pasted key without key name
		secretish + " = x\n" + // pasted key used as a key name
		"Address = " + secretish + "\n" +
		"[Peer]\n" +
		"PublicKey = " + pubKey1 + "\n" +
		"PresharedKey = " + secretish + "x\n" +
		"Endpoint = " + secretish + ":51820\n" +
		"AllowedIPs = " + secretish + "\n" +
		"PersistentKeepalive = " + secretish + "\n" +
		"PostUp = " + secretish + "\n"
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("Parse succeeded")
	}
	msg := err.Error()
	for _, frag := range []string{secretish, secretish[:20], secretish[10:30], "x\n"} {
		if strings.Contains(msg, frag) {
			t.Fatalf("error leaks config content %q:\n%s", frag, msg)
		}
	}
	var list ErrorList
	if !errors.As(err, &list) {
		t.Fatalf("unexpected error type: %T", err)
	}
	var lines []int
	for _, e := range list {
		lines = append(lines, e.Line)
	}
	// Every bad line is reported; a pasted padded key on line 3 ends in "="
	// and therefore surfaces as an unnamed unknown key.
	if want := []int{2, 3, 4, 5, 8, 9, 10, 11, 12}; !reflect.DeepEqual(lines, want) {
		t.Fatalf("error lines = %v, want %v", lines, want)
	}
}

func TestKeyRedaction(t *testing.T) {
	k, err := ParseKey(privKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Interface: Interface{PrivateKey: k}, Peers: []Peer{{PresharedKey: &k}}}
	text, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{
		fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s %x %q", k, k, k, k, k, k),
		fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg), string(text),
	}
	raw := string(k[:])
	for _, out := range outputs {
		if strings.Contains(out, privKey) || strings.Contains(out, fmt.Sprintf("%x", raw)) || strings.Contains(out, "1 1 1 1") {
			t.Errorf("key leaked in %q", out)
		}
	}
	if k.Base64() != privKey {
		t.Error("Base64 must return the key")
	}
}

func ExampleConfig_XrayOutbound() {
	src := `[Interface]
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Address = 10.8.0.2/24, fd00:8::2/64
DNS = 192.0.2.53, 2001:db8::53
MTU = 1380

[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
PresharedKey = BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=
Endpoint = [2001:db8::10]:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		fmt.Println(err)
		return
	}
	out, _ := json.MarshalIndent(cfg.XrayOutbound("wg-example"), "", "  ")
	fmt.Println(string(out))
	// Output:
	// {
	//   "tag": "wg-example",
	//   "protocol": "wireguard",
	//   "settings": {
	//     "secretKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	//     "address": [
	//       "10.8.0.2/24",
	//       "fd00:8::2/64"
	//     ],
	//     "peers": [
	//       {
	//         "publicKey": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
	//         "preSharedKey": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=",
	//         "endpoint": "[2001:db8::10]:51820",
	//         "keepAlive": 25,
	//         "allowedIPs": [
	//           "0.0.0.0/0",
	//           "::/0"
	//         ]
	//       }
	//     ],
	//     "mtu": 1380,
	//     "remoteDNS": [
	//       "192.0.2.53",
	//       "2001:db8::53"
	//     ],
	//     "noKernelTun": true
	//   }
	// }
}
