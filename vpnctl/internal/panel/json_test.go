package panel

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCanonicalExactValues(t *testing.T) {
	for _, test := range []struct {
		name  string
		left  string
		right string
		equal bool
	}{
		{name: "object order and whitespace", left: `{"b":[1,2],"a":true}`, right: "{\n\"a\":true,\"b\":[1,2]}", equal: true},
		{name: "decimal notation", left: `{"value":1.500}`, right: `{"value":15e-1}`, equal: true},
		{name: "integer exponent", left: `{"value":1000}`, right: `{"value":1e3}`, equal: true},
		{name: "negative zero", left: `[-0.000,0e20]`, right: `[0,-0e-2]`, equal: true},
		{name: "large adjacent integers", left: `[9007199254740992]`, right: `[9007199254740993]`, equal: false},
		{name: "array order", left: `[1,2]`, right: `[2,1]`, equal: false},
		{name: "null versus missing", left: `{"field":null}`, right: `{}`, equal: false},
		{name: "escaped key", left: `{"a":1}`, right: `{"\u0061":1.0}`, equal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			left, err := Canonical([]byte(test.left))
			if err != nil {
				t.Fatal(err)
			}
			right, err := Canonical([]byte(test.right))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(left, right) != test.equal {
				t.Fatalf("canonical equality = %t; want %t", bytes.Equal(left, right), test.equal)
			}
		})
	}
}

func TestCanonicalRejectsAmbiguousJSONWithoutEchoingInput(t *testing.T) {
	const secret = "private-input-must-not-appear"
	for _, input := range []string{
		"",
		`{"name":"` + secret + `","name":"replacement"}`,
		`{"a":1,"\u0061":2}`,
		`{"nested":{"a":1,"a":2}}`,
		`{"secret":"` + secret + `"} {}`,
		`{"secret":"` + secret + `",}`,
		`{"secret":"` + secret + `"`,
		`[1e9223372036854775807,1e9223372036854775808]`,
		strings.Repeat("[", maxJSONDepth+2) + strings.Repeat("]", maxJSONDepth+2),
	} {
		_, err := Canonical([]byte(input))
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected invalid-input classification, got %v", err)
		}
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Fatal("parser error exposed credential-bearing input")
		}
	}
}
