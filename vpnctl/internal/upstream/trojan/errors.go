package trojan

import "github.com/juvenileslave/vpn/vpnctl/internal/upstream/sharelink"

// FieldError is a parse failure attributed to one part of a link, such as
// "password", "port" or "alpn".
//
// Reasons never contain the offending value: a link carries a password, so
// errors name the field only.
type FieldError = sharelink.FieldError

// EntryError reports why one subscription entry was rejected. Entry is the
// 1-based ordinal among non-blank, non-comment lines; Line is the 1-based line
// number in the (decoded) subscription text.
type EntryError = sharelink.EntryError

var (
	// ErrTooLarge is returned for a subscription above MaxSubscriptionBytes.
	ErrTooLarge = sharelink.ErrTooLarge
	// ErrEncoding is returned when a subscription is neither plain links nor
	// valid standard base64 of UTF-8 text.
	ErrEncoding = sharelink.ErrEncoding
	// ErrEmpty is returned when a subscription has no entries.
	ErrEmpty = sharelink.ErrEmpty
	// ErrTooManyEntries is returned for a subscription above MaxEntries.
	ErrTooManyEntries = sharelink.ErrTooManyEntries
)
