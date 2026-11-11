package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

const (
	zonesPerPage = 50  // API maximum for GET /zones.
	dnsPerPage   = 100 // API default for GET /zones/{zone_id}/dns_records.
	maxZoneIDLen = 32
)

// Zone is the subset of a Cloudflare zone used by vpnctl.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Paused bool   `json:"paused"`
}

// DNSRecord is the subset of a Cloudflare DNS record used by vpnctl.
type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	// TTL is in seconds; 1 means "automatic".
	TTL int `json:"ttl"`
}

// ZoneFilter narrows ListZones. Empty fields are not sent.
type ZoneFilter struct {
	Name      string // exact domain name
	Status    string // initializing, pending, active or moved
	AccountID string
}

// DNSRecordFilter narrows ListDNSRecords. Empty fields are not sent.
type DNSRecordFilter struct {
	Type    string // e.g. "A" or "AAAA"
	Name    string // exact FQDN
	Content string // exact content
}

// ListZones returns all zones visible to the token that match filter
// (GET /zones), following result_info pagination.
func (c *Client) ListZones(ctx context.Context, filter ZoneFilter) ([]Zone, error) {
	const label = "/zones"
	q := url.Values{}
	setIf(q, "name", filter.Name)
	setIf(q, "status", filter.Status)
	setIf(q, "account.id", filter.AccountID)
	zones := []Zone{}
	err := c.listAll(ctx, label, "/zones", q, zonesPerPage, func(raw json.RawMessage) (int, error) {
		var page []Zone
		if err := json.Unmarshal(raw, &page); err != nil {
			return 0, fmt.Errorf("%w: GET %s: result is not a zone array", ErrMalformedResponse, label)
		}
		for _, z := range page {
			if z.ID == "" || z.Name == "" {
				return 0, fmt.Errorf("%w: GET %s: zone without id or name", ErrMalformedResponse, label)
			}
		}
		zones = append(zones, page...)
		return len(page), nil
	})
	if err != nil {
		return nil, err
	}
	return zones, nil
}

// ListDNSRecords returns all DNS records of zoneID that match filter
// (GET /zones/{zone_id}/dns_records), following result_info pagination.
func (c *Client) ListDNSRecords(ctx context.Context, zoneID string, filter DNSRecordFilter) ([]DNSRecord, error) {
	if err := checkZoneID(zoneID); err != nil {
		return nil, err
	}
	const label = "/zones/{zone_id}/dns_records"
	q := url.Values{}
	setIf(q, "type", filter.Type)
	setIf(q, "name.exact", filter.Name)
	setIf(q, "content.exact", filter.Content)
	records := []DNSRecord{}
	path := "/zones/" + zoneID + "/dns_records"
	err := c.listAll(ctx, label, path, q, dnsPerPage, func(raw json.RawMessage) (int, error) {
		var page []DNSRecord
		if err := json.Unmarshal(raw, &page); err != nil {
			return 0, fmt.Errorf("%w: GET %s: result is not a DNS record array", ErrMalformedResponse, label)
		}
		for _, r := range page {
			if r.ID == "" || r.Type == "" || r.Name == "" {
				return 0, fmt.Errorf("%w: GET %s: record without id, type or name", ErrMalformedResponse, label)
			}
		}
		records = append(records, page...)
		return len(page), nil
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func setIf(q url.Values, key, value string) {
	if value != "" {
		q.Set(key, value)
	}
}

// checkZoneID accepts Cloudflare identifiers (at most 32 alphanumerics), which
// also keeps the path segment free of separators.
func checkZoneID(id string) error {
	if id == "" || len(id) > maxZoneIDLen {
		return fmt.Errorf("cloudflare: invalid zone ID (length %s)", strconv.Itoa(len(id)))
	}
	for _, r := range id {
		if !('0' <= r && r <= '9' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z') {
			return fmt.Errorf("cloudflare: invalid zone ID (non-alphanumeric character)")
		}
	}
	return nil
}
