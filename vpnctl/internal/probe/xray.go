package probe

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// These types decode the accepted renderer's client, not an alternative renderer.
// DisallowUnknownFields rejects DNS, observatory, mux, API, freedom and log paths.
type clientProfile struct {
	Log struct {
		Level string `json:"loglevel"`
	} `json:"log"`
	Inbounds  []clientInbound  `json:"inbounds"`
	Outbounds []clientOutbound `json:"outbounds"`
	Routing   struct {
		Rules []clientRule `json:"rules"`
	} `json:"routing"`
}

type clientInbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Settings struct {
		UDP bool `json:"udp"`
	} `json:"settings"`
}

type clientRule struct {
	Type        string `json:"type"`
	Network     string `json:"network"`
	OutboundTag string `json:"outboundTag"`
}

type clientOutbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings *clientSettings `json:"settings,omitempty"`
	Stream   *clientStream   `json:"streamSettings,omitempty"`
}

type clientSettings struct {
	Servers []clientServer `json:"vnext"`
}
type clientServer struct {
	Address string       `json:"address"`
	Port    uint16       `json:"port"`
	Users   []clientUser `json:"users"`
}
type clientUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
}
type clientStream struct {
	Network  string `json:"network"`
	Security string `json:"security"`
	XHTTP    struct {
		Path    string `json:"path"`
		Mode    string `json:"mode"`
		Padding string `json:"xPaddingBytes"`
	} `json:"xhttpSettings"`
	Reality struct {
		Show        bool   `json:"show"`
		ServerName  string `json:"serverName"`
		Fingerprint string `json:"fingerprint"`
		Password    string `json:"password"`
		ShortID     string `json:"shortId"`
	} `json:"realitySettings"`
}

var (
	uuidPattern    = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	shortIDPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)
)

func loadProfile(request *LadderRequest) (*clientProfile, error) {
	var profile clientProfile
	if err := readJSON(request.ProfileFile, 256<<10, &profile); err != nil {
		return nil, shortError("profile_unavailable")
	}
	if len(profile.Inbounds) != 1 || len(profile.Outbounds) != 2 || len(profile.Routing.Rules) != 1 {
		return nil, shortError("profile_not_accepted")
	}
	inbound, proxy, block, rule := profile.Inbounds[0], profile.Outbounds[0], profile.Outbounds[1], profile.Routing.Rules[0]
	validInbound := inbound.Tag == "local" && inbound.Listen == "127.0.0.1" && inbound.Port != 0 &&
		inbound.Protocol == "socks" && !inbound.Settings.UDP
	validRouting := rule.Type == "field" && rule.Network == "tcp,udp" && rule.OutboundTag == "proxy"
	validBlock := block.Tag == "block" && block.Protocol == "blackhole" && block.Settings == nil && block.Stream == nil
	if !validInbound || !validRouting || !validBlock || proxy.Tag != "proxy" || proxy.Protocol != "vless" ||
		proxy.Settings == nil || proxy.Stream == nil || len(proxy.Settings.Servers) != 1 {
		return nil, shortError("profile_not_accepted")
	}
	server, stream := &proxy.Settings.Servers[0], proxy.Stream
	if len(server.Users) != 1 || !uuidPattern.MatchString(server.Users[0].ID) || server.Users[0].Encryption != "none" ||
		server.Port != request.Target.Port {
		return nil, shortError("profile_not_accepted")
	}
	address, err := netip.ParseAddr(server.Address)
	allowedAddress := address == request.Target.Address || (request.ProfileAddress.IsValid() && address == request.ProfileAddress)
	if err != nil || !allowedAddress || address.Is4In6() || address.Zone() != "" {
		return nil, shortError("profile_target_mismatch")
	}
	key, err := base64.RawURLEncoding.DecodeString(stream.Reality.Password)
	validKey := err == nil && len(key) == 32 && base64.RawURLEncoding.EncodeToString(key) == stream.Reality.Password
	validXHTTP := stream.Network == "xhttp" && stream.Security == "reality" && stream.XHTTP.Mode == "stream-one" &&
		stream.XHTTP.Padding == "100-1000" && strings.HasPrefix(stream.XHTTP.Path, "/") && len(stream.XHTTP.Path) <= 256
	validReality := !stream.Reality.Show && stream.Reality.Fingerprint == "firefox" && validKey &&
		shortIDPattern.MatchString(stream.Reality.ShortID) && stream.Reality.ServerName == request.ServerName
	if !validXHTTP || !validReality {
		return nil, shortError("profile_not_accepted")
	}
	return &profile, nil
}

func coreEnvironment() []string {
	out := make([]string, 0, 5)
	// No owner tokens, proxy variables, XRAY_LOCATION_CONFIG or extra config dirs.
	for _, name := range []string{"PATH", "HOME", "SYSTEMROOT", "LANG", "XRAY_LOCATION_ASSET"} {
		if value, ok := os.LookupEnv(name); ok {
			out = append(out, name+"="+value)
		}
	}
	return out
}

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	length := len(p)
	if b.Len()+length > 4096 {
		b.overflow = true
		p = p[:max(0, 4096-b.Len())]
	}
	_, err := b.Buffer.Write(p)
	return length, err
}

func checkCore(ctx context.Context, path string) error {
	if !filepath.IsAbs(path) {
		return shortError("explicit_xray_path_required")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return shortError("xray_unavailable")
	}
	command := exec.CommandContext(ctx, path, "version")
	command.WaitDelay = time.Second
	command.Env = coreEnvironment()
	output := &boundedOutput{}
	command.Stdout, command.Stderr = output, io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return shortError("xray_version_failed")
	}
	if !pinnedVersion(output.Bytes(), output.overflow) {
		return shortError("xray_version_mismatch")
	}
	return nil
}

func pinnedVersion(output []byte, overflow bool) bool {
	return !overflow && bytes.HasPrefix(output, []byte("Xray "+PinnedCoreVersion+" "))
}

// readyOutput discards every log; only the pinned core's started marker is kept
// as a boolean. Startup readiness never opens a second remote probe connection.
type readyOutput struct {
	mu      sync.Mutex
	line    []byte
	ready   chan struct{}
	started bool
}

func (r *readyOutput) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, value := range p {
		if value == '\n' {
			if !r.started && bytes.Contains(r.line, []byte("core: Xray "+PinnedCoreVersion+" started")) {
				close(r.ready)
				r.started = true
			}
			r.line = r.line[:0]
		} else if len(r.line) < 4096 {
			r.line = append(r.line, value)
		}
	}
	return len(p), nil
}

type coreProcess struct {
	command   *exec.Cmd
	done      chan error
	directory string
	port      uint16
}

func startCore(
	ctx context.Context,
	request *LadderRequest,
	profile *clientProfile,
	startupContext context.Context,
) (process *coreProcess, resultErr error) {
	directory, err := os.MkdirTemp("", "vpnctl-probe-")
	if err != nil {
		return nil, shortError("private_config_failed")
	}
	core := &coreProcess{directory: directory, done: make(chan error, 1)}
	failed := true
	defer func() {
		if failed {
			if err := core.close(); err != nil {
				process, resultErr = nil, err
			}
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, shortError("private_config_failed")
	}
	path := filepath.Join(directory, "client.json")
	if _, err := externalPath(path); err != nil {
		return nil, shortError("private_config_failed")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, shortError("local_listener_failed")
	}
	core.port = addrPort(listener.Addr()).Port()
	profile.Inbounds[0].Port = core.port
	profile.Outbounds[0].Settings.Servers[0].Address = request.Target.Address.String()
	profile.Log.Level = "warning"
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		listener.Close()
		return nil, shortError("private_config_failed")
	}
	encodeErr := json.NewEncoder(file).Encode(profile)
	closeErr := file.Close()
	if err := listener.Close(); err != nil || encodeErr != nil || closeErr != nil {
		return nil, shortError("private_config_failed")
	}
	output := &readyOutput{line: make([]byte, 0, 256), ready: make(chan struct{})}
	core.command = exec.CommandContext(ctx, request.XrayPath, "run", "-config", path)
	core.command.WaitDelay = time.Second
	core.command.Env = coreEnvironment()
	core.command.Stdout, core.command.Stderr = output, output
	if err := core.command.Start(); err != nil {
		core.command = nil
		return nil, shortError("xray_start_failed")
	}
	go func() { core.done <- core.command.Wait() }()
	startup, cancel := context.WithTimeout(startupContext, request.Budgets.Setup)
	defer cancel()
	select {
	case <-output.ready:
		failed = false
		return core, nil
	case err := <-core.done:
		core.command = nil
		if err == nil {
			return nil, shortError("xray_exited")
		}
		return nil, shortError("xray_start_failed")
	case <-startup.Done():
		return nil, startup.Err()
	}
}

func (c *coreProcess) close() error {
	var cleanupErr error
	if c.command != nil {
		// Kill only our child; no PID lookup, daemon, service or host changes.
		if err := c.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			cleanupErr = shortError("xray_cleanup_failed")
		}
		select {
		case <-c.done:
		case <-time.After(3 * time.Second):
			cleanupErr = shortError("xray_cleanup_failed")
		}
		c.command = nil
	}
	if err := os.RemoveAll(c.directory); err != nil {
		cleanupErr = shortError("private_cleanup_failed")
	}
	if _, err := os.Lstat(c.directory); !os.IsNotExist(err) {
		cleanupErr = shortError("private_cleanup_failed")
	}
	return cleanupErr
}

func (c *coreProcess) request(ctx context.Context, endpoint Endpoint, roots *x509.CertPool) (obs Observation) {
	start := time.Now()
	defer func() { obs.Start, obs.End = start, time.Now() }()
	conn, obs := dial(ctx, Target{Address: netip.MustParseAddr("127.0.0.1"), Port: c.port, Family: IPv4})
	if conn == nil {
		return obs
	}
	defer conn.Close()
	stop := watch(ctx, conn)
	defer stop()
	if err := socksConnect(conn, endpoint); err != nil {
		obs.Outcome = classifyHTTP(ctx, err)
		return obs
	}
	u, err := url.Parse(endpoint.URL)
	if err != nil {
		obs.Outcome = OutcomeInvalidRequest
		return obs
	}
	request := HTTPRequest{URL: endpoint.URL, MaxBytes: endpoint.Bytes, HashBody: true}
	rw := conn
	if u.Scheme == "https" {
		tlsConn, tlsObs := handshake(ctx, conn, u.Hostname(), roots, obs)
		if tlsConn == nil {
			return tlsObs
		}
		rw = tlsConn
	}
	return transfer(ctx, rw, u, request, obs)
}

func socksConnect(conn net.Conn, endpoint Endpoint) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	if greeting != [2]byte{5, 0} {
		return shortError("socks_protocol_error")
	}
	request := []byte{5, 1, 0, 1}
	if endpoint.Address.Is6() {
		request[3] = 4
	}
	request = append(request, endpoint.Address.AsSlice()...)
	request = binary.BigEndian.AppendUint16(request, endpoint.Port)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return shortError("socks_path_failed")
	}
	var remaining int64
	switch header[3] {
	case 1:
		remaining = 6
	case 4:
		remaining = 18
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return err
		}
		remaining = int64(size[0]) + 2
	default:
		return shortError("socks_protocol_error")
	}
	_, err := io.CopyN(io.Discard, conn, remaining)
	return err
}
