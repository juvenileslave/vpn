package remnawave

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	configProfileNamePattern = regexp.MustCompile(`^[A-Za-z0-9_ -]+$`)
	snippetNamePattern       = regexp.MustCompile(`^[A-Za-z0-9_ -]+(/[A-Za-z0-9_ -]+)*$`)
)

// CreateConfigProfileInput holds the validated fields for POST /api/config-profiles.
// Config may contain secrets; formatting the struct redacts its contents.
type CreateConfigProfileInput struct {
	Name   string
	Config json.RawMessage
}

func (i CreateConfigProfileInput) String() string {
	return "remnawave.CreateConfigProfileInput{redacted}"
}
func (i CreateConfigProfileInput) GoString() string { return i.String() }
func (i CreateConfigProfileInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

// UpdateConfigProfileInput holds the fields for PATCH /api/config-profiles.
// Supplying Config replaces the entire panel config object.
type UpdateConfigProfileInput struct {
	UUID   string
	Name   *string
	Config json.RawMessage
}

func (i UpdateConfigProfileInput) String() string {
	return "remnawave.UpdateConfigProfileInput{redacted}"
}
func (i UpdateConfigProfileInput) GoString() string { return i.String() }
func (i UpdateConfigProfileInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

// WriteSnippetInput holds the fields for POST and PATCH /api/snippets.
type WriteSnippetInput struct {
	Name    string
	Snippet json.RawMessage
}

func (i WriteSnippetInput) String() string   { return "remnawave.WriteSnippetInput{redacted}" }
func (i WriteSnippetInput) GoString() string { return i.String() }
func (i WriteSnippetInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

// InboundRef identifies a config profile and one of its inbounds.
type InboundRef struct {
	ConfigProfileUUID        string
	ConfigProfileInboundUUID string
}

func (r InboundRef) String() string   { return "remnawave.InboundRef{redacted}" }
func (r InboundRef) GoString() string { return r.String() }
func (r InboundRef) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

// WriteHost holds the fields for POST /api/hosts. Nil optional pointer fields
// are omitted; non-nil pointers (including empty strings) are serialized
// explicitly.
type WriteHost struct {
	HostName               string
	Address                string
	Port                   int
	Path                   *string
	SNI                    *string
	Host                   *string
	Fingerprint            *string
	Inbound                InboundRef
	OverrideSNIFromAddress *bool
	KeepSNIBlank           *bool
	ShuffleHost            *bool
}

func (h WriteHost) String() string   { return "remnawave.WriteHost{redacted}" }
func (h WriteHost) GoString() string { return h.String() }
func (h WriteHost) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

// UpdateHostInput holds the fields for PATCH /api/hosts. Nil optional pointer
// fields are omitted so panel-side settings are preserved; non-nil pointers
// (including empty strings) are serialized explicitly and overwrite the field.
type UpdateHostInput struct {
	UUID                   string
	HostName               *string
	Address                *string
	Port                   *int
	Path                   *string
	SNI                    *string
	Host                   *string
	Fingerprint            *string
	Inbound                *InboundRef
	OverrideSNIFromAddress *bool
	KeepSNIBlank           *bool
	ShuffleHost            *bool
}

func (h UpdateHostInput) String() string   { return "remnawave.UpdateHostInput{redacted}" }
func (h UpdateHostInput) GoString() string { return h.String() }
func (h UpdateHostInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

type createConfigProfileRequest struct {
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

type updateConfigProfileRequest struct {
	UUID   string          `json:"uuid"`
	Name   *string         `json:"name,omitempty"`
	Config json.RawMessage `json:"config,omitempty"`
}

type writeSnippetRequest struct {
	Name    string          `json:"name"`
	Snippet json.RawMessage `json:"snippet"`
}

type snippetNameRequest struct {
	Name string `json:"name"`
}

type inboundRefRequest struct {
	ConfigProfileUUID        string `json:"configProfileUuid"`
	ConfigProfileInboundUUID string `json:"configProfileInboundUuid"`
}

type createHostRequest struct {
	Remark                 string            `json:"remark"`
	Address                string            `json:"address"`
	Port                   int               `json:"port"`
	Path                   *string           `json:"path,omitempty"`
	SNI                    *string           `json:"sni,omitempty"`
	Host                   *string           `json:"host,omitempty"`
	Fingerprint            *string           `json:"fingerprint,omitempty"`
	Inbound                inboundRefRequest `json:"inbound"`
	OverrideSNIFromAddress *bool             `json:"overrideSniFromAddress,omitempty"`
	KeepSNIBlank           *bool             `json:"keepSniBlank,omitempty"`
	ShuffleHost            *bool             `json:"shuffleHost,omitempty"`
}

type updateHostRequest struct {
	UUID                   string             `json:"uuid"`
	Remark                 *string            `json:"remark,omitempty"`
	Address                *string            `json:"address,omitempty"`
	Port                   *int               `json:"port,omitempty"`
	Path                   *string            `json:"path,omitempty"`
	SNI                    *string            `json:"sni,omitempty"`
	Host                   *string            `json:"host,omitempty"`
	Fingerprint            *string            `json:"fingerprint,omitempty"`
	Inbound                *inboundRefRequest `json:"inbound,omitempty"`
	OverrideSNIFromAddress *bool              `json:"overrideSniFromAddress,omitempty"`
	KeepSNIBlank           *bool              `json:"keepSniBlank,omitempty"`
	ShuffleHost            *bool              `json:"shuffleHost,omitempty"`
}

// CreateConfigProfile creates a config profile via POST /api/config-profiles.
func (c *Client) CreateConfigProfile(ctx context.Context, in CreateConfigProfileInput) (ConfigProfile, error) {
	const op = "create config profile"
	if !validConfigProfileName(in.Name) {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w: invalid profile name", op, ErrInvalidArgument)
	}
	cfg, err := validateConfigObject(in.Config)
	if err != nil {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	body, err := c.doJSON(ctx, op, http.MethodPost, http.StatusCreated, createConfigProfileRequest{
		Name:   in.Name,
		Config: cfg,
	}, "api", "config-profiles")
	if err != nil {
		return ConfigProfile{}, err
	}
	raw, err := planningEnvelope(body)
	if err != nil {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: err})
	}
	profile, err := decodeConfigProfile(raw)
	if err == nil && profile.Name != in.Name {
		err = malformed("profile: requested name does not match response")
	}
	if err != nil {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: err})
	}
	return profile, nil
}

// UpdateConfigProfile updates a config profile via PATCH /api/config-profiles.
// Supplying Config replaces the entire config object on the panel.
func (c *Client) UpdateConfigProfile(ctx context.Context, in UpdateConfigProfileInput) (ConfigProfile, error) {
	const op = "update config profile"
	if !validUUID(in.UUID) {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w: invalid uuid", op, ErrInvalidArgument)
	}
	if in.Name == nil && in.Config == nil {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w: name or config is required", op, ErrInvalidArgument)
	}
	if in.Name != nil && !validConfigProfileName(*in.Name) {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w: invalid profile name", op, ErrInvalidArgument)
	}
	var cfg json.RawMessage
	if in.Config != nil {
		var err error
		cfg, err = validateConfigObject(in.Config)
		if err != nil {
			return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w", op, err)
		}
	}
	body, err := c.doJSON(ctx, op, http.MethodPatch, http.StatusOK, updateConfigProfileRequest{
		UUID:   in.UUID,
		Name:   in.Name,
		Config: cfg,
	}, "api", "config-profiles")
	if err != nil {
		return ConfigProfile{}, err
	}
	raw, err := planningEnvelope(body)
	if err != nil {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: err})
	}
	profile, err := decodeConfigProfile(raw)
	if err == nil && !sameUUID(profile.UUID, in.UUID) {
		err = malformed("profile: requested identity does not match response")
	}
	if err == nil && in.Name != nil && profile.Name != *in.Name {
		err = malformed("profile: requested name does not match response")
	}
	if err != nil {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: err})
	}
	return profile, nil
}

// DeleteConfigProfile deletes a config profile via DELETE /api/config-profiles/{uuid}.
func (c *Client) DeleteConfigProfile(ctx context.Context, uuid string) error {
	const op = "delete config profile"
	if !validUUID(uuid) {
		return fmt.Errorf("remnawave: %s: %w: invalid uuid", op, ErrInvalidArgument)
	}
	_, err := c.doJSON(ctx, op, http.MethodDelete, http.StatusNoContent, nil, "api", "config-profiles", uuid)
	return err
}

// CreateSnippet creates a named snippet via POST /api/snippets and returns the
// complete decoded snippet collection.
func (c *Client) CreateSnippet(ctx context.Context, in WriteSnippetInput) ([]Snippet, error) {
	return c.writeSnippet(ctx, "create snippet", http.MethodPost, http.StatusCreated, in)
}

// UpdateSnippet updates a named snippet via PATCH /api/snippets and returns the
// complete decoded snippet collection.
func (c *Client) UpdateSnippet(ctx context.Context, in WriteSnippetInput) ([]Snippet, error) {
	return c.writeSnippet(ctx, "update snippet", http.MethodPatch, http.StatusOK, in)
}

func (c *Client) writeSnippet(ctx context.Context, op, method string, expectedStatus int, in WriteSnippetInput) ([]Snippet, error) {
	if !validSnippetName(in.Name) {
		return nil, fmt.Errorf("remnawave: %s: %w: invalid snippet name", op, ErrInvalidArgument)
	}
	snippet, err := validateSnippetArray(in.Snippet)
	if err != nil {
		return nil, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	body, err := c.doJSON(ctx, op, method, expectedStatus, writeSnippetRequest{
		Name:    in.Name,
		Snippet: snippet,
	}, "api", "snippets")
	if err != nil {
		return nil, err
	}
	snippets, err := decodeSnippets(body)
	if err != nil {
		return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: err})
	}
	matches := 0
	for _, item := range snippets {
		if item.Name == in.Name {
			matches++
		}
	}
	if matches != 1 {
		return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: malformed("snippet: requested identity missing from response")})
	}
	return snippets, nil
}

// DeleteSnippet deletes a named snippet via DELETE /api/snippets. HTTP 204 is
// the only confirmation; the endpoint returns no body.
func (c *Client) DeleteSnippet(ctx context.Context, name string) error {
	const op = "delete snippet"
	if !validSnippetName(name) {
		return fmt.Errorf("remnawave: %s: %w: invalid snippet name", op, ErrInvalidArgument)
	}
	_, err := c.doJSON(ctx, op, http.MethodDelete, http.StatusNoContent, snippetNameRequest{Name: name}, "api", "snippets")
	return err
}

// SyncSnippet requests snippet synchronization via POST /api/snippets/actions/sync.
func (c *Client) SyncSnippet(ctx context.Context, name string) error {
	const op = "sync snippet"
	if !validSnippetName(name) {
		return fmt.Errorf("remnawave: %s: %w: invalid snippet name", op, ErrInvalidArgument)
	}
	_, err := c.doJSON(ctx, op, http.MethodPost, http.StatusAccepted, snippetNameRequest{Name: name}, "api", "snippets", "actions", "sync")
	return err
}

// CreateHost creates a host via POST /api/hosts.
func (c *Client) CreateHost(ctx context.Context, in WriteHost) (Host, error) {
	const op = "create host"
	if !validHostRemark(in.HostName) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid host name", op, ErrInvalidArgument)
	}
	if !validHostAddress(in.Address) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid address", op, ErrInvalidArgument)
	}
	if !validPort(in.Port) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid port", op, ErrInvalidArgument)
	}
	if !validInboundRef(in.Inbound) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid inbound reference", op, ErrInvalidArgument)
	}
	if !validOptionalHostString(in.Path) || !validOptionalHostString(in.SNI) ||
		!validOptionalHostString(in.Host) || !validOptionalHostString(in.Fingerprint) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid optional host field", op, ErrInvalidArgument)
	}
	body, err := c.doJSON(ctx, op, http.MethodPost, http.StatusCreated, createHostRequest{
		Remark:      in.HostName,
		Address:     in.Address,
		Port:        in.Port,
		Path:        in.Path,
		SNI:         in.SNI,
		Host:        in.Host,
		Fingerprint: in.Fingerprint,
		Inbound: inboundRefRequest{
			ConfigProfileUUID:        in.Inbound.ConfigProfileUUID,
			ConfigProfileInboundUUID: in.Inbound.ConfigProfileInboundUUID,
		},
		OverrideSNIFromAddress: in.OverrideSNIFromAddress,
		KeepSNIBlank:           in.KeepSNIBlank,
		ShuffleHost:            in.ShuffleHost,
	}, "api", "hosts")
	if err != nil {
		return Host{}, err
	}
	raw, err := planningEnvelope(body)
	if err != nil {
		return Host{}, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: err})
	}
	host, err := decodeHost(raw)
	if err == nil && host.Remark != in.HostName {
		err = malformed("host: requested remark does not match response")
	}
	if err == nil && (!sameUUID(host.Inbound.ConfigProfileUUID, in.Inbound.ConfigProfileUUID) ||
		!sameUUID(host.Inbound.ConfigProfileInboundUUID, in.Inbound.ConfigProfileInboundUUID)) {
		err = malformed("host: requested inbound does not match response")
	}
	if err != nil {
		return Host{}, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: err})
	}
	return host, nil
}

// UpdateHost partially updates a host via PATCH /api/hosts. Omitted optional
// fields are not serialized and are preserved by the panel.
func (c *Client) UpdateHost(ctx context.Context, in UpdateHostInput) (Host, error) {
	const op = "update host"
	if !validUUID(in.UUID) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid uuid", op, ErrInvalidArgument)
	}
	if in.HostName == nil && in.Address == nil && in.Port == nil &&
		in.Path == nil && in.SNI == nil && in.Host == nil &&
		in.Fingerprint == nil && in.Inbound == nil &&
		in.OverrideSNIFromAddress == nil && in.KeepSNIBlank == nil &&
		in.ShuffleHost == nil {
		return Host{}, fmt.Errorf("remnawave: %s: %w: at least one field is required", op, ErrInvalidArgument)
	}
	if in.HostName != nil && !validHostRemark(*in.HostName) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid host name", op, ErrInvalidArgument)
	}
	if in.Address != nil && !validHostAddress(*in.Address) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid address", op, ErrInvalidArgument)
	}
	if in.Port != nil && !validPort(*in.Port) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid port", op, ErrInvalidArgument)
	}
	var inbound *inboundRefRequest
	if in.Inbound != nil {
		if !validInboundRef(*in.Inbound) {
			return Host{}, fmt.Errorf("remnawave: %s: %w: invalid inbound reference", op, ErrInvalidArgument)
		}
		inbound = &inboundRefRequest{
			ConfigProfileUUID:        in.Inbound.ConfigProfileUUID,
			ConfigProfileInboundUUID: in.Inbound.ConfigProfileInboundUUID,
		}
	}
	if !validOptionalHostString(in.Path) || !validOptionalHostString(in.SNI) ||
		!validOptionalHostString(in.Host) || !validOptionalHostString(in.Fingerprint) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid optional host field", op, ErrInvalidArgument)
	}
	body, err := c.doJSON(ctx, op, http.MethodPatch, http.StatusOK, updateHostRequest{
		UUID:                   in.UUID,
		Remark:                 in.HostName,
		Address:                in.Address,
		Port:                   in.Port,
		Path:                   in.Path,
		SNI:                    in.SNI,
		Host:                   in.Host,
		Fingerprint:            in.Fingerprint,
		Inbound:                inbound,
		OverrideSNIFromAddress: in.OverrideSNIFromAddress,
		KeepSNIBlank:           in.KeepSNIBlank,
		ShuffleHost:            in.ShuffleHost,
	}, "api", "hosts")
	if err != nil {
		return Host{}, err
	}
	raw, err := planningEnvelope(body)
	if err != nil {
		return Host{}, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: err})
	}
	host, err := decodeHost(raw)
	if err == nil && !sameUUID(host.UUID, in.UUID) {
		err = malformed("host: requested identity does not match response")
	}
	if err == nil && in.HostName != nil && host.Remark != *in.HostName {
		err = malformed("host: requested remark does not match response")
	}
	if err == nil && in.Inbound != nil &&
		(!sameUUID(host.Inbound.ConfigProfileUUID, in.Inbound.ConfigProfileUUID) ||
			!sameUUID(host.Inbound.ConfigProfileInboundUUID, in.Inbound.ConfigProfileInboundUUID)) {
		err = malformed("host: requested inbound does not match response")
	}
	if err != nil {
		return Host{}, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: err})
	}
	return host, nil
}

// DeleteHost deletes a host via DELETE /api/hosts/{uuid}.
func (c *Client) DeleteHost(ctx context.Context, uuid string) error {
	const op = "delete host"
	if !validUUID(uuid) {
		return fmt.Errorf("remnawave: %s: %w: invalid uuid", op, ErrInvalidArgument)
	}
	_, err := c.doJSON(ctx, op, http.MethodDelete, http.StatusNoContent, nil, "api", "hosts", uuid)
	return err
}

func (c *Client) doJSON(ctx context.Context, op, method string, expectedStatus int, payload any, elem ...string) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("remnawave: %s: %w: context is required", op, ErrInvalidArgument)
	}

	var reqBody []byte
	if payload != nil {
		var err error
		reqBody, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("remnawave: %s: %w: encode request body", op, ErrInvalidArgument)
		}
		limit := c.maxReqBytes
		if limit <= 0 {
			limit = DefaultMaxRequestBytes
		}
		if int64(len(reqBody)) > limit {
			return nil, fmt.Errorf("remnawave: %s: %w (limit %d bytes)", op, ErrRequestTooLarge, limit)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("remnawave: %s: %w", op, err)
	}

	u := c.base.JoinPath(elem...)
	var bodyReader io.Reader
	if reqBody != nil {
		bodyReader = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("remnawave: %s: build request: %w", op, safeCause{err})
	}
	// Disallow any transport-level body replay for mutating requests.
	req.GetBody = nil
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error repeats the request URL; keep only the cause.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			return nil, fmt.Errorf("remnawave: %s: %w", op, err)
		}
		cause := error(safeCause{err})
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(cause, ctxErr) {
			cause = fmt.Errorf("%w (%w)", ctxErr, cause)
		}
		return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: cause})
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := newAPIError(resp)
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: apiErr})
		}
		return nil, fmt.Errorf("remnawave: %s: %w", op, apiErr)
	}
	if resp.StatusCode != expectedStatus {
		cause := fmt.Errorf("%w: HTTP %d", ErrUnexpectedStatus, resp.StatusCode)
		return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: cause})
	}
	if expectedStatus == http.StatusNoContent || expectedStatus == http.StatusAccepted {
		if resp.ContentLength > 0 {
			cause := fmt.Errorf("%w: expected empty body", ErrMalformedResponse)
			return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: cause})
		}
		extra, err := io.ReadAll(io.LimitReader(resp.Body, 1))
		if err != nil {
			cause := error(safeCause{err})
			if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(cause, ctxErr) {
				cause = fmt.Errorf("%w (%w)", ctxErr, cause)
			}
			return nil, fmt.Errorf("remnawave: %s: read body: %w", op, &WriteOutcomeUnknownError{cause: cause})
		}
		if len(extra) != 0 {
			cause := fmt.Errorf("%w: expected empty body", ErrMalformedResponse)
			return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: cause})
		}
		return nil, nil
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		cause := fmt.Errorf("%w: content type is not application/json", ErrMalformedResponse)
		return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: cause})
	}
	if resp.ContentLength > c.maxBytes {
		cause := fmt.Errorf("%w (limit %d bytes)", ErrResponseTooLarge, c.maxBytes)
		return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: cause})
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		cause := error(safeCause{err})
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(cause, ctxErr) {
			cause = fmt.Errorf("%w (%w)", ctxErr, cause)
		}
		return nil, fmt.Errorf("remnawave: %s: read body: %w", op, &WriteOutcomeUnknownError{cause: cause})
	}
	if int64(len(body)) > c.maxBytes {
		cause := fmt.Errorf("%w (limit %d bytes)", ErrResponseTooLarge, c.maxBytes)
		return nil, fmt.Errorf("remnawave: %s: %w", op, &WriteOutcomeUnknownError{cause: cause})
	}
	return body, nil
}

func validConfigProfileName(name string) bool {
	return len(name) >= 2 && len(name) <= 30 &&
		strings.TrimSpace(name) != "" &&
		configProfileNamePattern.MatchString(name)
}

func validSnippetName(name string) bool {
	if len(name) < 2 || len(name) > 255 || !snippetNamePattern.MatchString(name) {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if strings.TrimSpace(seg) == "" {
			return false
		}
	}
	return true
}

func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func validHostRemark(s string) bool {
	if !utf8.ValidString(s) || hasControlChar(s) || strings.TrimSpace(s) == "" {
		return false
	}
	n := utf8.RuneCountInString(s)
	return n >= 1 && n <= 100
}

func validHostAddress(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Zone() == ""
	}
	return validHostname(s)
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for idx, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if !isASCIIAlphaNum(label[0]) || !isASCIIAlphaNum(label[len(label)-1]) {
			return false
		}
		allDigits := true
		for i := 0; i < len(label); i++ {
			b := label[i]
			if !isASCIIAlphaNum(b) && b != '-' {
				return false
			}
			if b < '0' || b > '9' {
				allDigits = false
			}
		}
		if idx == len(labels)-1 && allDigits {
			return false
		}
	}
	return true
}

func isASCIIAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func validOptionalHostString(s *string) bool {
	if s == nil {
		return true
	}
	return utf8.ValidString(*s) && !hasControlChar(*s)
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}

func validInboundRef(ref InboundRef) bool {
	return validUUID(ref.ConfigProfileUUID) && validUUID(ref.ConfigProfileInboundUUID)
}

func validateJSONTree(raw json.RawMessage) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("%w: empty json value", ErrInvalidArgument)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("%w: invalid utf8", ErrInvalidArgument)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := uniqueJSONValue(dec, 0); err != nil {
		return fmt.Errorf("%w: invalid or duplicate-key json", ErrInvalidArgument)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: unexpected trailing json data", ErrInvalidArgument)
	}
	return nil
}

func compactJSON(raw json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, fmt.Errorf("%w: invalid json", ErrInvalidArgument)
	}
	return json.RawMessage(buf.Bytes()), nil
}

func validateConfigObject(raw json.RawMessage) (json.RawMessage, error) {
	if err := validateJSONTree(raw); err != nil {
		return nil, err
	}
	fields, err := objectFields(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: config must be a json object", ErrInvalidArgument)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("%w: config object must not be empty", ErrInvalidArgument)
	}
	return compactJSON(raw)
}

func validateSnippetArray(raw json.RawMessage) (json.RawMessage, error) {
	if err := validateJSONTree(raw); err != nil {
		return nil, err
	}
	parts, err := arrayValues(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: snippet must be a json array", ErrInvalidArgument)
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: snippet array must not be empty", ErrInvalidArgument)
	}
	for _, part := range parts {
		obj, err := objectFields(part)
		if err != nil {
			return nil, fmt.Errorf("%w: snippet element must be a json object", ErrInvalidArgument)
		}
		if len(obj) == 0 {
			return nil, fmt.Errorf("%w: snippet object must not be empty", ErrInvalidArgument)
		}
	}
	return compactJSON(raw)
}
