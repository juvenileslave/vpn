package panel

import "errors"

// Sentinel errors are static and safe to display. Match them with errors.Is.
var (
	ErrInvalidInput           = errors.New("panel: invalid input")
	ErrConflict               = errors.New("panel: ownership or current-state conflict")
	ErrLossyUpdate            = errors.New("panel: prospective config update would lose settings or static clients")
	ErrUnsupportedAtomicWrite = errors.New("panel: pinned api has no supported atomic write precondition")
)

// Error adds a fixed operation label without exposing a parser, URL or response body.
// Its underlying error remains available through errors.Is and errors.As.
type Error struct {
	operation string
	cause     error
}

func (e *Error) Error() string    { return "panel: " + e.operation + " failed" }
func (e *Error) Unwrap() error    { return e.cause }
func (e *Error) String() string   { return e.Error() }
func (e *Error) GoString() string { return e.Error() }
func (e *Error) MarshalJSON() ([]byte, error) {
	return []byte(`{"error":"panel operation failed"}`), nil
}

func safeError(operation string, err error) error {
	return &Error{operation: operation, cause: err}
}
