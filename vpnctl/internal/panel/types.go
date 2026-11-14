// Package panel plans publication of an existing rendered bundle without writing to the panel.
package panel

import "encoding/json"

// Bundle is an integrity-checked candidate produced by the existing profiles renderer.
// Configs contain credentials and must never be formatted or logged.
type Bundle struct {
	ID      string
	Hosts   map[string]BundleHost
	Configs map[string]json.RawMessage
}

func (b Bundle) String() string   { return "panel.Bundle{contents: redacted}" }
func (b Bundle) GoString() string { return b.String() }

// BundleHost is the renderer's single public hostname/address authority.
type BundleHost struct {
	SNI    string
	IPv4   string
	IPv6   string
	Origin string
}

// Objects declares only the exact objects an operator intends to manage.
type Objects struct {
	Schema   int           `json:"schema"`
	Profiles []ProfileSpec `json:"profiles"`
	Snippets []SnippetSpec `json:"snippets"`
	Hosts    []HostSpec    `json:"hosts"`
}

// ProfileSpec binds one panel identity to one existing renderer output.
// An absent UUID declares creation, not adoption of an existing name.
type ProfileSpec struct {
	Name     string   `json:"name"`
	UUID     string   `json:"uuid,omitempty"`
	Role     string   `json:"role"`
	Snippets []string `json:"snippets,omitempty"`
}

// SnippetSpec selects an existing array; it does not introduce another renderer.
type SnippetSpec struct {
	Name  string `json:"name"`
	Role  string `json:"role"`
	Field string `json:"field"`
}

// HostSpec binds one declared host to a public inbound in the same bundle.
// Address, port, SNI, path and fingerprint are derived, not independently supplied.
type HostSpec struct {
	Name    string `json:"name"`
	UUID    string `json:"uuid,omitempty"`
	Profile string `json:"profile"`
	Inbound string `json:"inbound"`
	Family  string `json:"family"`
}
