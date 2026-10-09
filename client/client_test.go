package client

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNextTSStrictlyIncreasing(t *testing.T) {
	now := time.Unix(1700000000, 0)
	c := &Client{Now: func() time.Time { return now }}
	a, b := c.nextTS(), c.nextTS()
	if a != now.Unix() || b != a+1 {
		t.Errorf("same second: %d then %d", a, b)
	}
	now = now.Add(10 * time.Second)
	if got := c.nextTS(); got != now.Unix() {
		t.Errorf("after the clock moved on: %d, want %d", got, now.Unix())
	}
}

func resp(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		code int
		body string
		want error
	}{
		{401, `{"error":"clock_skew"}`, ErrClockSkew},
		{401, `{"error":"unauthorized"}`, ErrUnauthorized},
		{403, `{"error":"device_disabled"}`, ErrDeviceDisabled},
		{429, `{"error":"registration_limited"}`, ErrRegistrationLimited},
		{429, `{"error":"cert_rate_limited"}`, ErrCertRateLimited},
		{429, `{"error":"rate_limited"}`, ErrRateLimited},
		{404, `{"error":"not_found"}`, ErrNotFound},
		{401, `garbage`, ErrUnauthorized},
	}
	for _, c := range cases {
		if err := errorFor(resp(c.code, c.body)); !errors.Is(err, c.want) {
			t.Errorf("%d %s: err = %v, want %v", c.code, c.body, err, c.want)
		}
	}
	err := errorFor(resp(500, `{"error":"internal"}`))
	for _, sentinel := range []error{ErrClockSkew, ErrUnauthorized, ErrDeviceDisabled, ErrNotFound} {
		if errors.Is(err, sentinel) {
			t.Errorf("500 mapped to %v", sentinel)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("500: err = %v", err)
	}
}

func TestNextTSBurstBoundedLead(t *testing.T) {
	now := time.Unix(1700000000, 0)
	var slept int
	c := &Client{Now: func() time.Time { return now }}
	c.sleep = func(d time.Duration) { slept++; now = now.Add(d) }
	prev := int64(0)
	for i := 0; i < 20; i++ {
		ts := c.nextTS()
		if ts <= prev {
			t.Fatalf("call %d: ts %d not > %d", i, ts, prev)
		}
		if ts-now.Unix() > 5 {
			t.Fatalf("call %d: ts %d is %ds ahead of the clock", i, ts, ts-now.Unix())
		}
		prev = ts
	}
	if slept == 0 {
		t.Error("burst never waited for the clock")
	}
}

func TestNextTSClockStepBack(t *testing.T) {
	now := time.Unix(1700000000, 0)
	c := &Client{Now: func() time.Time { return now }}
	c.sleep = func(time.Duration) { t.Fatal("slept after a clock step back") }
	c.lastTS = now.Unix() + 3600
	if got := c.nextTS(); got != now.Unix() {
		t.Errorf("ts = %d, want %d", got, now.Unix())
	}
	if got := c.nextTS(); got != now.Unix()+1 {
		t.Errorf("next ts = %d", got)
	}
}
