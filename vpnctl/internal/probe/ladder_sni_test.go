package probe

import "testing"

func TestExactSNICannotBeAnIPLiteralWithSuppressedSNI(t *testing.T) {
	request := fixtureRequest(t)
	request.ServerName = "192.0.2.10"
	if err := request.validate(); err == nil {
		t.Fatal("IP literal silently suppressed the promised TLS SNI")
	}
	request.ServerName = "cover.example.test"
	request.ControlServerName = "192.0.2.10"
	if err := request.validate(); err == nil {
		t.Fatal("control IP literal silently suppressed SNI")
	}
}
