// Package validate runs the real pinned `xray -test` against a slot outbound
// before publication. It validates configuration syntax only; a passing test
// is not proof that a tunnel works.
package validate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultTimeout = 15 * time.Second
	versionTimeout = 5 * time.Second
	maxOutbound    = 256 << 10
)

var (
	ErrInvalidOptions = errors.New("validate: invalid options")
	ErrConfig         = errors.New("validate: outbound config rejected")
	ErrCore           = errors.New("validate: pinned xray is unusable")
	ErrRejected       = errors.New("validate: xray -test rejected the config")
)

// Options configures the Xray validator.
type Options struct {
	XrayPath      string
	VersionPrefix string
	Timeout       time.Duration // 0 => 15s
}

// Xray implements pipeline.Validator with `xray -test`.
type Xray struct {
	xrayPath string
	version  string
	timeout  time.Duration
}

// New validates options without executing Xray.
func New(opts Options) (*Xray, error) {
	if opts.XrayPath == "" || !filepath.IsAbs(opts.XrayPath) {
		return nil, fmt.Errorf("%w: xray path must be absolute", ErrInvalidOptions)
	}
	info, err := os.Lstat(opts.XrayPath)
	if err != nil {
		return nil, fmt.Errorf("%w: xray path is inaccessible", ErrInvalidOptions)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("%w: xray path must be an executable regular file", ErrInvalidOptions)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Xray{xrayPath: opts.XrayPath, version: opts.VersionPrefix, timeout: timeout}, nil
}

// Validate writes the outbound to a 0600 temporary config and runs
// `xray -test -c <config>`. Errors never include the config or its path.
func (v *Xray) Validate(ctx context.Context, slot int, outbound json.RawMessage) error {
	if v == nil {
		return ErrInvalidOptions
	}
	if ctx == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if slot < 1 || slot > 63 {
		return fmt.Errorf("%w: slot must be between 1 and 63", ErrConfig)
	}
	if len(outbound) == 0 || len(outbound) > maxOutbound {
		return fmt.Errorf("%w: outbound is empty or too large", ErrConfig)
	}
	var object map[string]any
	if err := json.Unmarshal(outbound, &object); err != nil || object == nil {
		return fmt.Errorf("%w: outbound is not a JSON object", ErrConfig)
	}
	cfg, err := json.Marshal(map[string]any{
		"log":       map[string]string{"loglevel": "none"},
		"outbounds": []json.RawMessage{outbound},
	})
	if err != nil {
		return fmt.Errorf("%w: config encoding failed", ErrConfig)
	}

	if err := v.checkVersion(ctx); err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "vpnctl-upstream-validate-")
	if err != nil {
		return fmt.Errorf("%w: temporary directory failed", ErrConfig)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("%w: temporary directory permissions", ErrConfig)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		return fmt.Errorf("%w: temporary config failed", ErrConfig)
	}

	testCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	if err := exec.CommandContext(testCtx, v.xrayPath, "-test", "-c", path).Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(testCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%w: xray -test timed out", ErrRejected)
		}
		return fmt.Errorf("%w", ErrRejected)
	}
	return nil
}

func (v *Xray) checkVersion(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	out, err := exec.CommandContext(checkCtx, v.xrayPath, "-version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: version check failed", ErrCore)
	}
	if v.version != "" && !strings.HasPrefix(strings.TrimSpace(string(out)), v.version) {
		return fmt.Errorf("%w: version does not match the pinned prefix", ErrCore)
	}
	return nil
}
