package reputation

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newBook() (*Book, *clock) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	return New(Config{Now: c.now}), c
}

func TestEvents(t *testing.T) {
	tests := []struct {
		name   string
		events []Event
		banned bool
	}{
		{"sole sender of a bad piece", []Event{BadPiece}, true},
		{"proven bad block", []Event{ProvenBad}, true},
		{"two suspect pieces", []Event{SuspectPiece, SuspectPiece}, false},
		{"three suspect pieces", []Event{SuspectPiece, SuspectPiece, SuspectPiece}, true},
		{"two violations", []Event{ProtocolViolation, ProtocolViolation}, true},
		{"flood then violation", []Event{Flood, ProtocolViolation}, true},
		{"many snubs", []Event{Snubbed, Snubbed, Snubbed, Snubbed, Snubbed, Snubbed, Snubbed}, false},
		{"eight snubs", []Event{Snubbed, Snubbed, Snubbed, Snubbed, Snubbed, Snubbed, Snubbed, Snubbed}, true},
	}
	for _, tt := range tests {
		b, _ := newBook()
		var banned bool
		for _, e := range tt.events {
			banned = b.Record("1.2.3.4", e)
		}
		if banned != tt.banned || b.Banned("1.2.3.4") != tt.banned {
			t.Errorf("%s: banned=%v, want %v (score %d)", tt.name, banned, tt.banned, b.Score("1.2.3.4"))
		}
		if b.Banned("5.6.7.8") {
			t.Errorf("%s: an unrelated peer is banned", tt.name)
		}
	}
}

func TestGoodHistoryBuysSlack(t *testing.T) {
	b, _ := newBook()
	for range 50 {
		b.Record("honest", GoodPiece)
	}
	if b.Score("honest") != maxScore {
		t.Fatalf("score %d, want cap %d", b.Score("honest"), maxScore)
	}
	// An honest peer caught in several mixed corrupt pieces survives longer.
	for i := range 6 {
		if b.Record("honest", SuspectPiece) {
			t.Fatalf("banned after %d suspect pieces despite a good history", i+1)
		}
	}
	if !b.Record("honest", SuspectPiece) {
		t.Fatal("never banned")
	}
}

func TestBanExpiryAndEscalation(t *testing.T) {
	b, c := newBook()
	b.Record("p", BadPiece)
	c.advance(59 * time.Minute)
	if !b.Banned("p") {
		t.Fatal("ban expired early")
	}
	c.advance(2 * time.Minute)
	if b.Banned("p") {
		t.Fatal("first ban did not expire after an hour")
	}
	// Released at half the ban score: one violation bans again, for longer.
	if !b.Record("p", ProtocolViolation) {
		t.Fatal("repeat offender not re-banned quickly")
	}
	c.advance(119 * time.Minute)
	if !b.Banned("p") {
		t.Fatal("second ban should last two hours")
	}
	c.advance(2 * time.Minute)
	if b.Banned("p") {
		t.Fatal("second ban did not expire")
	}
	// Doubling stops at the cap.
	for range 10 {
		b.Ban("p")
	}
	c.advance(24*time.Hour + time.Second)
	if b.Banned("p") {
		t.Fatal("ban exceeded MaxBanDuration")
	}
}

func TestPruneKeepsBans(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b := New(Config{Now: c.now, MaxPeers: 100})
	b.Record("attacker", BadPiece)
	for i := range 1000 {
		b.Record(fmt.Sprintf("10.0.%d.%d", i/250, i%250), GoodPiece)
	}
	if len(b.peers) > 100 {
		t.Fatalf("%d records kept, cap 100", len(b.peers))
	}
	if !b.Banned("attacker") {
		t.Fatal("pruning forgot a ban")
	}
}
