package telegram

import (
	"strings"
	"unicode/utf16"
)

// MaxMessageUnits is the Bot API limit for one message, measured in UTF-16
// code units as Telegram counts it.
const MaxMessageUnits = 4096

// TruncationMarker ends a message shortened by Truncate.
const TruncationMarker = "\n… (сокращено)"

// UTF16Length reports length in UTF-16 code units, the unit Telegram uses for
// its message limit. Invalid UTF-8 counts as replacement characters.
func UTF16Length(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// Truncate shortens s to at most limit UTF-16 code units and appends
// TruncationMarker when content was removed. It never splits a rune.
func Truncate(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if UTF16Length(s) <= limit {
		return s
	}
	marker := TruncationMarker
	markerUnits := UTF16Length(marker)
	if markerUnits > limit {
		return takeUnits(s, limit)
	}
	return takeUnits(s, limit-markerUnits) + marker
}

func takeUnits(s string, limit int) string {
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		w := utf16.RuneLen(r)
		if n+w > limit {
			break
		}
		b.WriteRune(r)
		n += w
	}
	return b.String()
}
