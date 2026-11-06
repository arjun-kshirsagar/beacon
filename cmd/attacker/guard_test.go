package main

import (
	"testing"
)

func TestRequireTestbed(t *testing.T) {
	t.Setenv("BEACON_TESTBED", "")
	if requireTestbed() == nil {
		t.Fatal("ran without BEACON_TESTBED")
	}
	t.Setenv("BEACON_TESTBED", "yes")
	if requireTestbed() == nil {
		t.Fatal("ran with BEACON_TESTBED=yes")
	}
	t.Setenv("BEACON_TESTBED", "1")
	if err := requireTestbed(); err != nil {
		t.Fatal(err)
	}
}

func TestTarget(t *testing.T) {
	for _, tt := range []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:6881", true},
		{"10.88.1.10:6881", true},
		{"192.168.49.1:7000", true},
		{"172.16.0.5:1", true},
		{"[::1]:6881", true},
		{"[fd00::1]:6881", true},
		{"localhost:6881", true},
		{"8.8.8.8:53", false},
		{"1.1.1.1:6881", false},
		{"[2001:4860:4860::8888]:53", false},
		{"no-port", false},
	} {
		_, err := target(tt.addr)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err %v, want ok=%v", tt.addr, err, tt.ok)
		}
	}
}

func TestLabListen(t *testing.T) {
	for _, tt := range []struct {
		addr string
		ok   bool
	}{
		{":6881", true},
		{"0.0.0.0:6881", true},
		{"10.88.66.10:6881", true},
		{"8.8.8.8:6881", false},
		{"example.com:6881", false},
	} {
		if err := labListen(tt.addr); (err == nil) != tt.ok {
			t.Errorf("%s: err %v, want ok=%v", tt.addr, err, tt.ok)
		}
	}
}
