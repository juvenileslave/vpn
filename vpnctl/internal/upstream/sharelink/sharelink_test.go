package sharelink

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestDecodePlain(t *testing.T) {
	body := "\xef\xbb\xbf# comment\r\n\r\ntrojan://p@192.0.2.1:443\r\nssh://ignored\r\n"
	doc, err := Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Encoding != EncodingPlain || len(doc.Entries) != 2 {
		t.Fatalf("doc = %+v", doc)
	}
	if doc.Entries[0].Number != 1 || doc.Entries[0].Line != 3 || doc.Entries[0].Text != "trojan://p@192.0.2.1:443" {
		t.Errorf("entry 0 = %+v", doc.Entries[0])
	}
	if doc.Entries[1].Number != 2 || doc.Entries[1].Line != 4 {
		t.Errorf("entry 1 = %+v", doc.Entries[1])
	}
}

func TestDecodeBase64Body(t *testing.T) {
	plain := "ss://YWVzLTI1Ni1nY206cGFzcw@192.0.2.1:8388\n\n"
	std := base64.StdEncoding.EncodeToString([]byte(plain))
	wrapped := std[:len(std)/2] + "\r\n" + std[len(std)/2:]
	for name, body := range map[string]string{
		"padded":  std,
		"raw":     base64.RawStdEncoding.EncodeToString([]byte(plain)),
		"wrapped": wrapped,
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := Decode([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if doc.Encoding != EncodingBase64 || len(doc.Entries) != 1 {
				t.Fatalf("doc = %+v", doc)
			}
		})
	}
}

func TestDecodeLimit(t *testing.T) {
	line := "trojan://p@192.0.2.1:443\n"
	body := []byte(strings.Repeat(line, MaxEntries))
	doc, err := DecodeLimit(body, MaxEntries)
	if err != nil || len(doc.Entries) != MaxEntries {
		t.Fatalf("at limit: entries=%d err=%v", len(doc.Entries), err)
	}
	if _, err := DecodeLimit(body, MaxEntries-1); !errors.Is(err, ErrTooManyEntries) {
		t.Errorf("over limit err = %v", err)
	}
	// Decode keeps the accepted VLESS behaviour: no entry limit.
	doc, err = Decode([]byte(strings.Repeat(line, MaxEntries+1)))
	if err != nil || len(doc.Entries) != MaxEntries+1 {
		t.Errorf("unlimited: entries=%d err=%v", len(doc.Entries), err)
	}
}

func TestDecodeWholeBodyErrors(t *testing.T) {
	notUTF8 := base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe})
	for name, tc := range map[string]struct {
		body string
		want error
	}{
		"empty":          {"", ErrEmpty},
		"blank":          {" \r\n\t", ErrEmpty},
		"comments":       {"# a://b\n# c\n", ErrEmpty},
		"not base64":     {"plain text", ErrEncoding},
		"url-safe":       {base64.URLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xfe}), ErrEncoding},
		"bad padding":    {"AAAA=", ErrEncoding},
		"decoded binary": {notUTF8, ErrEncoding},
		"raw binary":     {"a://\xff", ErrEncoding},
		"too large":      {strings.Repeat("a", MaxSubscriptionBytes+1), ErrTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(tc.body)); !errors.Is(err, tc.want) {
				t.Errorf("err = %v; want %v", err, tc.want)
			}
		})
	}
}

func TestDecodeBase64Alphabets(t *testing.T) {
	payload := []byte("aes-256-gcm:p@ss:word")
	for name, encode := range map[string]func([]byte) string{
		"standard padded": base64.StdEncoding.EncodeToString,
		"standard raw":    base64.RawStdEncoding.EncodeToString,
		"url-safe padded": base64.URLEncoding.EncodeToString,
		"url-safe raw":    base64.RawURLEncoding.EncodeToString,
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := DecodeBase64(encode(payload))
			if !ok || got != string(payload) {
				t.Errorf("DecodeBase64 = %q, %v", got, ok)
			}
		})
	}
	for _, bad := range []string{"AAAA=", "not base64!", "%zz"} {
		if _, ok := DecodeBase64(bad); ok {
			t.Errorf("DecodeBase64(%q) accepted malformed input", bad)
		}
	}
}

func TestParseLabelLimits(t *testing.T) {
	label := strings.Repeat("a", MaxLabelRunes)
	got, err := ParseLabel(label, true)
	if err != nil || got != label {
		t.Errorf("at limit: %q, %v", got, err)
	}
	got, err = ParseLabel("%20"+label+"%20", true)
	if err != nil || got != label {
		t.Errorf("trimmed at limit: %q, %v", got, err)
	}
	_, err = ParseLabel(label+"a", true)
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "label" || !strings.Contains(fe.Reason, "longer") {
		t.Errorf("over limit err = %v", err)
	}
	if _, err := ParseLabel("a%0Ab", true); err == nil {
		t.Error("control character accepted")
	}
}
