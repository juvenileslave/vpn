package panel

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var (
	bundleDNSPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	shortIDPattern   = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// The renderer remains the authority for routes and credentials. These checks
// enforce the pinned publication policy and reject malformed/tampered inputs;
// they do not reproduce rendering or substitute for Xray/runtime validation.
func validateBundlePolicy(bundle Bundle) error {
	var commonPath string
	for _, role := range []string{"exit", "relay"} {
		host := bundle.Hosts[role]
		if len(host.SNI) > 253 || !bundleDNSPattern.MatchString(host.SNI) {
			return ErrInvalidInput
		}
		for index, text := range []string{host.IPv4, host.IPv6} {
			address, err := netip.ParseAddr(text)
			if err != nil || address.Is4() != (index == 0) || address.Is4In6() || address.Zone() != "" {
				return ErrInvalidInput
			}
			unsafeAddress := address.IsLoopback() || address.IsMulticast() || address.IsUnspecified()
			if unsafeAddress || address.IsLinkLocalUnicast() {
				return ErrInvalidInput
			}
		}
		originAddress, originPort, err := net.SplitHostPort(host.Origin)
		listener, parseErr := strconv.Atoi(originPort)
		if err != nil || parseErr != nil || originAddress != "127.0.0.1" || listener < 1 || listener > 65535 {
			return ErrInvalidInput
		}
		config, err := decodeObject(bundle.Configs[role])
		if err != nil {
			return err
		}
		for key := range config {
			known := key == "log" || key == "inbounds" || key == "outbounds" || key == "routing"
			if !known && !(role == "relay" && key == "observatory") {
				return ErrInvalidInput
			}
		}
		var inbounds []map[string]json.RawMessage
		if json.Unmarshal(config["inbounds"], &inbounds) != nil || len(inbounds) == 0 {
			return ErrInvalidInput
		}
		seen := make(map[string]bool, len(inbounds))
		for _, inbound := range inbounds {
			tag := stringField(inbound, "tag")
			if seen[tag] || !bundleInbound(role, tag) || stringField(inbound, "protocol") != "vless" {
				return ErrInvalidInput
			}
			seen[tag] = true
			port, ok := integerField(inbound, "port")
			if !ok || port < 1 || port > 65535 || port == int64(listener) {
				return ErrInvalidInput
			}
			listen := "0.0.0.0"
			if strings.HasSuffix(tag, "-v6") {
				listen = "::"
			}
			if stringField(inbound, "listen") != listen {
				return ErrInvalidInput
			}
			path, err := validateInboundPolicy(inbound, host)
			if err != nil {
				return err
			}
			if commonPath == "" {
				commonPath = path
			}
			if commonPath != path {
				return ErrInvalidInput
			}
		}
		if role == "exit" && len(seen) != 4 {
			return ErrInvalidInput
		}
		var outbounds []map[string]json.RawMessage
		if json.Unmarshal(config["outbounds"], &outbounds) != nil || len(outbounds) == 0 {
			return ErrInvalidInput
		}
		for _, outbound := range outbounds {
			if stringField(outbound, "tag") == "" || stringField(outbound, "protocol") == "" {
				return ErrInvalidInput
			}
			if role == "relay" && stringField(outbound, "protocol") == "freedom" {
				return ErrInvalidInput
			}
		}
		if _, err := decodeObject(config["routing"]); err != nil {
			return err
		}
	}
	return nil
}

func bundleInbound(role, tag string) bool {
	if role == "exit" {
		return tag == "direct-v4" || tag == "direct-v6" || tag == "transit-v4" || tag == "transit-v6"
	}
	return len(tag) == len("slot-0-v4") && strings.HasPrefix(tag, "slot-") &&
		tag[5] >= '0' && tag[5] <= '5' && (tag[6:] == "-v4" || tag[6:] == "-v6")
}

func validateInboundPolicy(inbound map[string]json.RawMessage, host BundleHost) (string, error) {
	settings, err := decodeObject(inbound["settings"])
	if err != nil || stringField(settings, "decryption") != "none" {
		return "", ErrInvalidInput
	}
	var clients []map[string]json.RawMessage
	if json.Unmarshal(settings["clients"], &clients) != nil || clients == nil {
		return "", ErrInvalidInput
	}
	seen := make(map[string]bool, len(clients))
	for _, client := range clients {
		id := stringField(client, "id")
		if !objectUUID(id) || seen[id] || len(client["flow"]) != 0 {
			return "", ErrInvalidInput
		}
		seen[id] = true
	}
	stream, err := decodeObject(inbound["streamSettings"])
	if err != nil || stringField(stream, "network") != "xhttp" || stringField(stream, "security") != "reality" {
		return "", ErrInvalidInput
	}
	xhttp, err := decodeObject(stream["xhttpSettings"])
	if err != nil || stringField(xhttp, "mode") != "stream-one" || stringField(xhttp, "xPaddingBytes") != "100-1000" {
		return "", ErrInvalidInput
	}
	path := stringField(xhttp, "path")
	if !strings.HasPrefix(path, "/") || len(path) > 4096 {
		return "", ErrInvalidInput
	}
	reality, err := decodeObject(stream["realitySettings"])
	if err != nil || stringField(reality, "dest") != host.Origin || !hasJSONValue(reality["serverNames"], []string{host.SNI}) {
		return "", ErrInvalidInput
	}
	if !hasJSONValue(reality["xver"], 0) || !hasJSONValue(reality["show"], false) {
		return "", ErrInvalidInput
	}
	budget, ok := integerField(reality, "maxTimeDiff")
	if !ok || budget <= 0 {
		return "", ErrInvalidInput
	}
	private := stringField(reality, "privateKey")
	decoded, err := base64.RawURLEncoding.DecodeString(private)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != private {
		return "", ErrInvalidInput
	}
	var shortIDs []string
	if json.Unmarshal(reality["shortIds"], &shortIDs) != nil || len(shortIDs) == 0 {
		return "", ErrInvalidInput
	}
	seenShort := make(map[string]bool, len(shortIDs))
	for _, id := range shortIDs {
		if !shortIDPattern.MatchString(id) || seenShort[id] {
			return "", ErrInvalidInput
		}
		seenShort[id] = true
	}
	return path, nil
}
