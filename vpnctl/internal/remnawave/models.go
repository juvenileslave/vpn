package remnawave

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// UserStatus is a panel user status. Values unknown to this package are kept
// as received; use Known to detect them.
type UserStatus string

const (
	UserStatusActive   UserStatus = "ACTIVE"
	UserStatusDisabled UserStatus = "DISABLED"
	UserStatusLimited  UserStatus = "LIMITED"
	UserStatusExpired  UserStatus = "EXPIRED"
)

// Known reports whether s is one of the statuses defined by API 3.4.10.
func (s UserStatus) Known() bool {
	switch s {
	case UserStatusActive, UserStatusDisabled, UserStatusLimited, UserStatusExpired:
		return true
	}
	return false
}

// UserUsage is a user's traffic counters in bytes.
type UserUsage struct {
	UsedBytes         int64
	LifetimeUsedBytes int64
	// LimitBytes is trafficLimitBytes as reported by the panel.
	LimitBytes int64
}

// User is a panel user without credentials, subscription data or contact
// details.
type User struct {
	ID       int64
	Username string
	Status   UserStatus
	ExpireAt time.Time
	Usage    UserUsage
	// OnlineAt and FirstConnectedAt are nil when null or absent.
	OnlineAt         *time.Time
	FirstConnectedAt *time.Time
}

// UsersPage is one page of GET /api/users.
type UsersPage struct {
	Users []User
	// Total is the number of users across all pages.
	Total int64
}

// NodeStatus is derived from the node's isDisabled, isConnecting and
// isConnected flags, in that order of precedence.
type NodeStatus string

const (
	NodeStatusDisabled     NodeStatus = "disabled"
	NodeStatusConnecting   NodeStatus = "connecting"
	NodeStatusConnected    NodeStatus = "connected"
	NodeStatusDisconnected NodeStatus = "disconnected"
)

// NodeUsage is a node's traffic counters in bytes; nil means null or absent.
type NodeUsage struct {
	UsedBytes  *int64
	LimitBytes *int64
}

// Node is a panel node. Address, proxy URL and free-form status messages are
// intentionally omitted.
type Node struct {
	UUID        string
	Name        string
	CountryCode string
	Status      NodeStatus
	UsersOnline int64
	Usage       NodeUsage
	// LastStatusChange is nil when null or absent.
	LastStatusChange *time.Time
}

// Wire types decode only the fields the models need, so secret-bearing fields
// such as passwords and subscription URLs are never decoded.
type wireUser struct {
	ID                *int64     `json:"id"`
	Username          *string    `json:"username"`
	Status            *string    `json:"status"`
	ExpireAt          *time.Time `json:"expireAt"`
	TrafficLimitBytes *int64     `json:"trafficLimitBytes"`
	UserTraffic       *struct {
		UsedTrafficBytes         *int64     `json:"usedTrafficBytes"`
		LifetimeUsedTrafficBytes *int64     `json:"lifetimeUsedTrafficBytes"`
		OnlineAt                 *time.Time `json:"onlineAt"`
		FirstConnectedAt         *time.Time `json:"firstConnectedAt"`
	} `json:"userTraffic"`
}

type wireNode struct {
	UUID             *string    `json:"uuid"`
	Name             *string    `json:"name"`
	CountryCode      *string    `json:"countryCode"`
	IsConnected      *bool      `json:"isConnected"`
	IsDisabled       *bool      `json:"isDisabled"`
	IsConnecting     *bool      `json:"isConnecting"`
	UsersOnline      *int64     `json:"usersOnline"`
	TrafficUsedBytes *int64     `json:"trafficUsedBytes"`
	TrafficLimit     *int64     `json:"trafficLimitBytes"`
	LastStatusChange *time.Time `json:"lastStatusChange"`
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformedResponse}, args...)...)
}

// decodeJSON decodes exactly one JSON value. Errors describe the problem
// without quoting the response content.
func decodeJSON(data []byte, v any, what string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		var syn *json.SyntaxError
		var typ *json.UnmarshalTypeError
		switch {
		case errors.Is(err, io.EOF):
			return malformed("%s: empty body", what)
		case errors.Is(err, io.ErrUnexpectedEOF):
			return malformed("%s: truncated JSON", what)
		case errors.As(err, &syn):
			return malformed("%s: invalid JSON at offset %d", what, syn.Offset)
		case errors.As(err, &typ):
			// typ.Value may quote a number literal, so it is not included.
			if typ.Field != "" {
				return malformed("%s: field %q has an unexpected type", what, typ.Field)
			}
			return malformed("%s: unexpected JSON type", what)
		default:
			return malformed("%s: invalid value", what)
		}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return malformed("%s: unexpected data after JSON value", what)
	}
	return nil
}

func decodeEnvelope(data []byte) (json.RawMessage, error) {
	var env struct {
		Response json.RawMessage `json:"response"`
	}
	if err := decodeJSON(data, &env, "envelope"); err != nil {
		return nil, err
	}
	if len(env.Response) == 0 || string(env.Response) == "null" {
		return nil, malformed("envelope: missing response")
	}
	return env.Response, nil
}

func decodeUsersPage(data []byte) (UsersPage, error) {
	raw, err := decodeEnvelope(data)
	if err != nil {
		return UsersPage{}, err
	}
	var w struct {
		Users *[]wireUser `json:"users"`
		Total *int64      `json:"total"`
	}
	if err := decodeJSON(raw, &w, "response"); err != nil {
		return UsersPage{}, err
	}
	if w.Users == nil {
		return UsersPage{}, malformed("response: missing users")
	}
	if w.Total == nil || *w.Total < 0 {
		return UsersPage{}, malformed("response: missing or negative total")
	}
	page := UsersPage{Users: make([]User, 0, len(*w.Users)), Total: *w.Total}
	for i, wu := range *w.Users {
		u, err := wu.user()
		if err != nil {
			return UsersPage{}, malformed("users[%d]: %s", i, err)
		}
		page.Users = append(page.Users, u)
	}
	return page, nil
}

func decodeUser(data []byte) (User, error) {
	raw, err := decodeEnvelope(data)
	if err != nil {
		return User{}, err
	}
	var w wireUser
	if err := decodeJSON(raw, &w, "response"); err != nil {
		return User{}, err
	}
	u, err := w.user()
	if err != nil {
		return User{}, malformed("user: %s", err)
	}
	return u, nil
}

func decodeNodes(data []byte) ([]Node, error) {
	raw, err := decodeEnvelope(data)
	if err != nil {
		return nil, err
	}
	var ws []wireNode
	if err := decodeJSON(raw, &ws, "response"); err != nil {
		return nil, err
	}
	nodes := make([]Node, 0, len(ws))
	for i, wn := range ws {
		n, err := wn.node()
		if err != nil {
			return nil, malformed("nodes[%d]: %s", i, err)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

func (w wireUser) user() (User, error) {
	switch {
	case w.ID == nil || *w.ID <= 0:
		return User{}, errors.New("missing or invalid id")
	case w.Username == nil || *w.Username == "":
		return User{}, errors.New("missing username")
	case w.Status == nil || *w.Status == "":
		return User{}, errors.New("missing status")
	case w.ExpireAt == nil:
		return User{}, errors.New("missing expireAt")
	case w.TrafficLimitBytes == nil:
		return User{}, errors.New("missing trafficLimitBytes")
	case w.UserTraffic == nil:
		return User{}, errors.New("missing userTraffic")
	case w.UserTraffic.UsedTrafficBytes == nil:
		return User{}, errors.New("missing userTraffic.usedTrafficBytes")
	}
	u := User{
		ID:       *w.ID,
		Username: *w.Username,
		Status:   UserStatus(*w.Status),
		ExpireAt: *w.ExpireAt,
		Usage: UserUsage{
			UsedBytes:  *w.UserTraffic.UsedTrafficBytes,
			LimitBytes: *w.TrafficLimitBytes,
		},
		OnlineAt:         w.UserTraffic.OnlineAt,
		FirstConnectedAt: w.UserTraffic.FirstConnectedAt,
	}
	if w.UserTraffic.LifetimeUsedTrafficBytes != nil {
		u.Usage.LifetimeUsedBytes = *w.UserTraffic.LifetimeUsedTrafficBytes
	}
	return u, nil
}

func (w wireNode) node() (Node, error) {
	switch {
	case w.UUID == nil || *w.UUID == "":
		return Node{}, errors.New("missing uuid")
	case w.Name == nil:
		return Node{}, errors.New("missing name")
	case w.IsConnected == nil || w.IsDisabled == nil || w.IsConnecting == nil:
		return Node{}, errors.New("missing connection flags")
	}
	n := Node{
		UUID:             *w.UUID,
		Name:             *w.Name,
		Usage:            NodeUsage{UsedBytes: w.TrafficUsedBytes, LimitBytes: w.TrafficLimit},
		LastStatusChange: w.LastStatusChange,
	}
	if w.CountryCode != nil {
		n.CountryCode = *w.CountryCode
	}
	if w.UsersOnline != nil {
		n.UsersOnline = *w.UsersOnline
	}
	switch {
	case *w.IsDisabled:
		n.Status = NodeStatusDisabled
	case *w.IsConnecting:
		n.Status = NodeStatusConnecting
	case *w.IsConnected:
		n.Status = NodeStatusConnected
	default:
		n.Status = NodeStatusDisconnected
	}
	return n, nil
}
