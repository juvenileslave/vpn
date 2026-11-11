package hetzner

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// Server is the subset of a Hetzner server used by vpnctl.
type Server struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"`
	Status    string            `json:"status"`
	PublicNet PublicNet         `json:"public_net"`
	Location  Location          `json:"location"`
	Labels    map[string]string `json:"labels"`
}

// PublicNet holds the server's public addresses. IPv4 or IPv6 is nil when the
// server has no such Primary IP assigned.
type PublicNet struct {
	IPv4 *PublicIP `json:"ipv4"`
	IPv6 *PublicIP `json:"ipv6"`
}

// PublicIP is a Primary IP as seen from the server. For IPv6, IP is a network
// in CIDR notation.
type PublicIP struct {
	ID      int64  `json:"id"`
	IP      string `json:"ip"`
	Blocked bool   `json:"blocked"`
}

// Location identifies a Hetzner location such as "hel1".
type Location struct {
	Name string `json:"name"`
}

// PrimaryIP is the subset of a Hetzner Primary IP used by vpnctl.
type PrimaryIP struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// IP is an address for ipv4 and a CIDR network for ipv6.
	IP           string            `json:"ip"`
	Type         string            `json:"type"` // "ipv4" or "ipv6"
	AssigneeType string            `json:"assignee_type"`
	AssigneeID   *int64            `json:"assignee_id"` // nil when unassigned
	AutoDelete   bool              `json:"auto_delete"`
	Blocked      bool              `json:"blocked"`
	Location     Location          `json:"location"`
	Labels       map[string]string `json:"labels"`
}

// ListOptions filters list calls. Empty fields are not sent.
type ListOptions struct {
	Name          string // exact name
	LabelSelector string // Hetzner label selector, e.g. "role=exit"
}

func (o ListOptions) values() url.Values {
	q := url.Values{}
	if o.Name != "" {
		q.Set("name", o.Name)
	}
	if o.LabelSelector != "" {
		q.Set("label_selector", o.LabelSelector)
	}
	return q
}

// ListServers returns all servers matching opts (GET /servers), following
// meta.pagination.next_page.
func (c *Client) ListServers(ctx context.Context, opts ListOptions) ([]Server, error) {
	const path = "/servers"
	servers := []Server{}
	err := c.listAll(ctx, path, opts.values(), func(ctx context.Context, q url.Values) (int, *listMeta, error) {
		var env struct {
			Servers *[]Server `json:"servers"`
			Meta    *listMeta `json:"meta"`
		}
		if err := c.get(ctx, path, q, &env); err != nil {
			return 0, nil, err
		}
		if env.Servers == nil {
			return 0, nil, fmt.Errorf("%w: GET %s: missing servers", ErrMalformedResponse, path)
		}
		for _, s := range *env.Servers {
			if err := checkServer(path, s); err != nil {
				return 0, nil, err
			}
		}
		servers = append(servers, *env.Servers...)
		return len(*env.Servers), env.Meta, nil
	})
	if err != nil {
		return nil, err
	}
	return servers, nil
}

// Server returns one server (GET /servers/{id}).
func (c *Client) Server(ctx context.Context, id int64) (Server, error) {
	if err := checkID("server", id); err != nil {
		return Server{}, err
	}
	const path = "/servers/{id}"
	var env struct {
		Server *Server `json:"server"`
	}
	if err := c.get(ctx, "/servers/"+strconv.FormatInt(id, 10), nil, &env); err != nil {
		return Server{}, err
	}
	if env.Server == nil {
		return Server{}, fmt.Errorf("%w: GET %s: missing server", ErrMalformedResponse, path)
	}
	if err := checkServer(path, *env.Server); err != nil {
		return Server{}, err
	}
	if env.Server.ID != id {
		return Server{}, fmt.Errorf("%w: GET %s: requested ID %d, got %d", ErrMalformedResponse, path, id, env.Server.ID)
	}
	return *env.Server, nil
}

// ListPrimaryIPs returns all Primary IPs matching opts (GET /primary_ips),
// following meta.pagination.next_page.
func (c *Client) ListPrimaryIPs(ctx context.Context, opts ListOptions) ([]PrimaryIP, error) {
	const path = "/primary_ips"
	ips := []PrimaryIP{}
	err := c.listAll(ctx, path, opts.values(), func(ctx context.Context, q url.Values) (int, *listMeta, error) {
		var env struct {
			PrimaryIPs *[]PrimaryIP `json:"primary_ips"`
			Meta       *listMeta    `json:"meta"`
		}
		if err := c.get(ctx, path, q, &env); err != nil {
			return 0, nil, err
		}
		if env.PrimaryIPs == nil {
			return 0, nil, fmt.Errorf("%w: GET %s: missing primary_ips", ErrMalformedResponse, path)
		}
		for _, ip := range *env.PrimaryIPs {
			if err := checkPrimaryIP(path, ip); err != nil {
				return 0, nil, err
			}
		}
		ips = append(ips, *env.PrimaryIPs...)
		return len(*env.PrimaryIPs), env.Meta, nil
	})
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// PrimaryIP returns one Primary IP (GET /primary_ips/{id}).
func (c *Client) PrimaryIP(ctx context.Context, id int64) (PrimaryIP, error) {
	if err := checkID("primary IP", id); err != nil {
		return PrimaryIP{}, err
	}
	const path = "/primary_ips/{id}"
	var env struct {
		PrimaryIP *PrimaryIP `json:"primary_ip"`
	}
	if err := c.get(ctx, "/primary_ips/"+strconv.FormatInt(id, 10), nil, &env); err != nil {
		return PrimaryIP{}, err
	}
	if env.PrimaryIP == nil {
		return PrimaryIP{}, fmt.Errorf("%w: GET %s: missing primary_ip", ErrMalformedResponse, path)
	}
	if err := checkPrimaryIP(path, *env.PrimaryIP); err != nil {
		return PrimaryIP{}, err
	}
	if env.PrimaryIP.ID != id {
		return PrimaryIP{}, fmt.Errorf("%w: GET %s: requested ID %d, got %d", ErrMalformedResponse, path, id, env.PrimaryIP.ID)
	}
	return *env.PrimaryIP, nil
}

func checkServer(path string, s Server) error {
	if s.ID < 1 || s.Name == "" || s.Status == "" {
		return fmt.Errorf("%w: GET %s: server without id, name or status", ErrMalformedResponse, path)
	}
	return nil
}

func checkPrimaryIP(path string, ip PrimaryIP) error {
	if ip.ID < 1 || ip.IP == "" || (ip.Type != "ipv4" && ip.Type != "ipv6") {
		return fmt.Errorf("%w: GET %s: primary IP without id, ip or valid type", ErrMalformedResponse, path)
	}
	return nil
}
