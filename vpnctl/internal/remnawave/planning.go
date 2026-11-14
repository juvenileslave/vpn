package remnawave

import (
	"context"
	"fmt"
)

// ListConfigProfiles returns the complete raw profile collection, not node configs.
func (c *Client) ListConfigProfiles(ctx context.Context) ([]ConfigProfile, error) {
	const op = "list config profiles"
	body, err := c.get(ctx, op, nil, "api", "config-profiles")
	if err != nil {
		return nil, err
	}
	profiles, err := decodeConfigProfiles(body)
	if err != nil {
		return nil, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	return profiles, nil
}

// ConfigProfile returns the raw profile with the given UUID.
func (c *Client) ConfigProfile(ctx context.Context, uuid string) (ConfigProfile, error) {
	return c.readConfigProfile(ctx, uuid, false)
}

// ComputedConfigProfile returns the panel-expanded profile envelope. Its Config
// is not the separate node configuration with panel user injection.
func (c *Client) ComputedConfigProfile(ctx context.Context, uuid string) (ConfigProfile, error) {
	return c.readConfigProfile(ctx, uuid, true)
}

func (c *Client) readConfigProfile(ctx context.Context, uuid string, computed bool) (ConfigProfile, error) {
	op := "get config profile"
	path := []string{"api", "config-profiles", uuid}
	if computed {
		op = "get computed config profile"
		path = append(path, "computed-config")
	}
	if !validUUID(uuid) {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w: invalid uuid", op, ErrInvalidArgument)
	}
	body, err := c.get(ctx, op, nil, path...)
	if err != nil {
		return ConfigProfile{}, err
	}
	raw, err := planningEnvelope(body)
	if err != nil {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	profile, err := decodeConfigProfile(raw)
	if err == nil && !sameUUID(profile.UUID, uuid) {
		err = malformed("profile: requested identity does not match response")
	}
	if err != nil {
		return ConfigProfile{}, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	return profile, nil
}

// ListSnippets returns named snippet arrays. The API has no snippet UUID or revision.
func (c *Client) ListSnippets(ctx context.Context) ([]Snippet, error) {
	const op = "list snippets"
	body, err := c.get(ctx, op, nil, "api", "snippets")
	if err != nil {
		return nil, err
	}
	snippets, err := decodeSnippets(body)
	if err != nil {
		return nil, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	return snippets, nil
}

// ListHosts returns the complete host collection without cloning or reordering it.
func (c *Client) ListHosts(ctx context.Context) ([]Host, error) {
	const op = "list hosts"
	body, err := c.get(ctx, op, nil, "api", "hosts")
	if err != nil {
		return nil, err
	}
	hosts, err := decodeHosts(body)
	if err != nil {
		return nil, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	return hosts, nil
}

// Host returns the host with the given UUID. Null inbound references remain empty
// strings; they never become a fabricated profile or inbound identity.
func (c *Client) Host(ctx context.Context, uuid string) (Host, error) {
	const op = "get host"
	if !validUUID(uuid) {
		return Host{}, fmt.Errorf("remnawave: %s: %w: invalid uuid", op, ErrInvalidArgument)
	}
	body, err := c.get(ctx, op, nil, "api", "hosts", uuid)
	if err != nil {
		return Host{}, err
	}
	raw, err := planningEnvelope(body)
	if err != nil {
		return Host{}, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	host, err := decodeHost(raw)
	if err == nil && !sameUUID(host.UUID, uuid) {
		err = malformed("host: requested identity does not match response")
	}
	if err != nil {
		return Host{}, fmt.Errorf("remnawave: %s: %w", op, err)
	}
	return host, nil
}
