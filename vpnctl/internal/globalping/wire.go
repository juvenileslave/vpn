package globalping

import (
	"errors"
	"fmt"
	"time"
)

// Wire types mirror the API response. Fields that are not mapped (rawOutput,
// rawHeaders, rawBody, headers, resolvers, publicKey) are discarded during
// decoding.

type wireMeasurement struct {
	ID          *string       `json:"id"`
	Type        *string       `json:"type"`
	Target      *string       `json:"target"`
	Status      *string       `json:"status"`
	CreatedAt   *time.Time    `json:"createdAt"`
	UpdatedAt   *time.Time    `json:"updatedAt"`
	ProbesCount *int          `json:"probesCount"`
	Results     *[]wireResult `json:"results"`
}

type wireResult struct {
	Probe  *wireProbe      `json:"probe"`
	Result *wireHTTPResult `json:"result"`
}

type wireProbe struct {
	Continent string   `json:"continent"`
	Region    string   `json:"region"`
	Country   string   `json:"country"`
	State     *string  `json:"state"`
	City      string   `json:"city"`
	ASN       int      `json:"asn"`
	Network   string   `json:"network"`
	Latitude  float64  `json:"latitude"`
	Longitude float64  `json:"longitude"`
	Tags      []string `json:"tags"`
}

type wireHTTPResult struct {
	Status          string       `json:"status"`
	FailureSource   string       `json:"failureSource"`
	StatusCode      *int         `json:"statusCode"`
	StatusCodeName  string       `json:"statusCodeName"`
	ResolvedAddress *string      `json:"resolvedAddress"`
	Truncated       bool         `json:"truncated"`
	Timings         *wireTimings `json:"timings"`
	TLS             *wireTLS     `json:"tls"`
}

type wireTimings struct {
	Total     *int64 `json:"total"`
	DNS       *int64 `json:"dns"`
	TCP       *int64 `json:"tcp"`
	TLS       *int64 `json:"tls"`
	FirstByte *int64 `json:"firstByte"`
	Download  *int64 `json:"download"`
}

type wireTLS struct {
	Protocol   string    `json:"protocol"`
	CipherName string    `json:"cipherName"`
	Authorized bool      `json:"authorized"`
	Error      string    `json:"error"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Subject    struct {
		CN  string `json:"CN"`
		Alt string `json:"alt"`
	} `json:"subject"`
	Issuer struct {
		C  string `json:"C"`
		O  string `json:"O"`
		CN string `json:"CN"`
	} `json:"issuer"`
	KeyType        *string `json:"keyType"`
	KeyBits        *int    `json:"keyBits"`
	SerialNumber   string  `json:"serialNumber"`
	Fingerprint256 string  `json:"fingerprint256"`
}

func (w *wireMeasurement) toMeasurement(wantID string) (*Measurement, error) {
	switch {
	case w.ID == nil || *w.ID != wantID:
		return nil, errors.New("id is missing or does not match the request")
	case w.Type == nil || *w.Type != "http":
		return nil, errors.New("measurement type is not http")
	case w.Status == nil || *w.Status == "":
		return nil, errors.New("status is missing")
	case w.Target == nil:
		return nil, errors.New("target is missing")
	case w.ProbesCount == nil || *w.ProbesCount < 0:
		return nil, errors.New("probesCount is missing or negative")
	case w.Results == nil:
		return nil, errors.New("results are missing")
	}
	m := &Measurement{
		ID:          *w.ID,
		Target:      *w.Target,
		Status:      MeasurementStatus(*w.Status),
		ProbesCount: *w.ProbesCount,
		Results:     make([]Result, 0, len(*w.Results)),
	}
	if w.CreatedAt != nil {
		m.CreatedAt = *w.CreatedAt
	}
	if w.UpdatedAt != nil {
		m.UpdatedAt = *w.UpdatedAt
	}
	for i, wr := range *w.Results {
		r, err := wr.toResult()
		if err != nil {
			return nil, fmt.Errorf("results[%d]: %v", i, err)
		}
		m.Results = append(m.Results, r)
	}
	return m, nil
}

func (w wireResult) toResult() (Result, error) {
	if w.Probe == nil || w.Result == nil {
		return Result{}, errors.New("probe or result is missing")
	}
	p := w.Probe
	r := Result{Probe: Probe{
		Continent: p.Continent,
		Region:    p.Region,
		Country:   p.Country,
		City:      p.City,
		ASN:       p.ASN,
		Network:   p.Network,
		Latitude:  p.Latitude,
		Longitude: p.Longitude,
		Tags:      p.Tags,
	}}
	if p.State != nil {
		r.Probe.State = *p.State
	}

	wr := w.Result
	if wr.Status == "" {
		return Result{}, errors.New("result status is missing")
	}
	r.HTTP = HTTPResult{Status: TestStatus(wr.Status), FailureSource: wr.FailureSource}
	if r.HTTP.Status != TestFinished {
		return r, nil
	}

	if wr.StatusCode == nil {
		return Result{}, errors.New("finished result has no statusCode")
	}
	t, err := wr.Timings.toTimings()
	if err != nil {
		return Result{}, err
	}
	r.HTTP.StatusCode = *wr.StatusCode
	r.HTTP.StatusCodeName = wr.StatusCodeName
	r.HTTP.Truncated = wr.Truncated
	r.HTTP.Timings = t
	if wr.ResolvedAddress != nil {
		r.HTTP.ResolvedAddress = *wr.ResolvedAddress
	}
	if wr.TLS != nil {
		r.HTTP.TLS = wr.TLS.toTLS()
	}
	return r, nil
}

func (w *wireTimings) toTimings() (*HTTPTimings, error) {
	if w == nil || w.Total == nil || w.TCP == nil || w.FirstByte == nil || w.Download == nil {
		return nil, errors.New("finished result has incomplete timings")
	}
	ms := func(v int64) time.Duration { return time.Duration(v) * time.Millisecond }
	opt := func(v *int64) *time.Duration {
		if v == nil {
			return nil
		}
		d := ms(*v)
		return &d
	}
	return &HTTPTimings{
		Total:     ms(*w.Total),
		DNS:       opt(w.DNS),
		TCP:       ms(*w.TCP),
		TLS:       opt(w.TLS),
		FirstByte: ms(*w.FirstByte),
		Download:  ms(*w.Download),
	}, nil
}

func (w *wireTLS) toTLS() *TLSInfo {
	t := &TLSInfo{
		Protocol:       w.Protocol,
		CipherName:     w.CipherName,
		Authorized:     w.Authorized,
		Error:          w.Error,
		CreatedAt:      w.CreatedAt,
		ExpiresAt:      w.ExpiresAt,
		SubjectCN:      w.Subject.CN,
		SubjectAlt:     w.Subject.Alt,
		IssuerC:        w.Issuer.C,
		IssuerO:        w.Issuer.O,
		IssuerCN:       w.Issuer.CN,
		SerialNumber:   w.SerialNumber,
		Fingerprint256: w.Fingerprint256,
	}
	if w.KeyType != nil {
		t.KeyType = *w.KeyType
	}
	if w.KeyBits != nil {
		t.KeyBits = *w.KeyBits
	}
	return t
}
