package mesh

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

const simNodes = 100

// simTopology returns a connected random graph on n nodes, a ring with random
// chords, whose diameter is within reach of a TTL 7 broadcast (8 hops).
func simTopology(t *testing.T, n int) [][2]int {
	for seed := uint64(1); seed < 100; seed++ {
		r := rand.New(rand.NewPCG(seed, 0)) // topology only, not cryptography
		have := map[[2]int]bool{}
		var edges [][2]int
		add := func(a, b int) {
			if a > b {
				a, b = b, a
			}
			if a != b && !have[[2]int{a, b}] {
				have[[2]int{a, b}] = true
				edges = append(edges, [2]int{a, b})
			}
		}
		for i := range n {
			add(i, (i+1)%n)
			add(i, r.IntN(n))
		}
		if diameter(n, edges) <= MaxTTL+1 {
			return edges
		}
	}
	t.Fatal("no topology with a small enough diameter")
	return nil
}

func diameter(n int, edges [][2]int) int {
	adj := make([][]int, n)
	for _, e := range edges {
		adj[e[0]] = append(adj[e[0]], e[1])
		adj[e[1]] = append(adj[e[1]], e[0])
	}
	worst := 0
	for s := range n {
		dist := make([]int, n)
		for i := range dist {
			dist[i] = -1
		}
		dist[s] = 0
		queue := []int{s}
		for len(queue) > 0 {
			u := queue[0]
			queue = queue[1:]
			for _, v := range adj[u] {
				if dist[v] < 0 {
					dist[v] = dist[u] + 1
					queue = append(queue, v)
				}
			}
		}
		for _, d := range dist {
			if d < 0 {
				return n // disconnected
			}
			worst = max(worst, d)
		}
	}
	return worst
}

// waitAll waits until cond holds for every node.
func waitAll(t *testing.T, nodes []*testNode, d time.Duration, what string, cond func(*testNode) bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		var missing []string
		for _, n := range nodes {
			if !cond(n) {
				missing = append(missing, n.name)
			}
		}
		if len(missing) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d nodes never did, e.g. %v", what, len(missing), missing[:min(5, len(missing))])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func except(nodes []*testNode, skip ...*testNode) []*testNode {
	var out []*testNode
outer:
	for _, n := range nodes {
		for _, s := range skip {
			if n == s {
				continue outer
			}
		}
		out = append(out, n)
	}
	return out
}

// TestSimulatedMesh is the Phase 4 milestone: a 100-node mesh, simulated in
// process over BLE-sized links, carries broadcasts, end-to-end encrypted
// direct messages, store-and-forward across a gap, and survives a flood.
func TestSimulatedMesh(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	m := newMesh(t, 185)
	nodes := make([]*testNode, simNodes)
	for i := range nodes {
		nodes[i] = m.create(fmt.Sprintf("n%02d", i))
	}
	edges := simTopology(t, simNodes)
	for _, e := range edges {
		m.connect(nodes[e[0]].name, nodes[e[1]].name)
	}
	for _, n := range nodes {
		go n.Run(m.ctx)
	}
	t.Logf("%d nodes, %d links, diameter %d", simNodes, len(edges), diameter(simNodes, edges))

	waitAll(t, nodes, 30*time.Second, "learn every peer", func(n *testNode) bool {
		return len(n.Peers()) >= simNodes-1
	})

	t.Run("broadcast", func(t *testing.T) {
		senders := []*testNode{nodes[0], nodes[17], nodes[42], nodes[63], nodes[99]}
		for i, s := range senders {
			if err := s.SendChannel("#general", fmt.Sprintf("broadcast %d", i)); err != nil {
				t.Fatal(err)
			}
		}
		for i, s := range senders {
			text := fmt.Sprintf("broadcast %d", i)
			waitAll(t, except(nodes, s), 30*time.Second, text, func(n *testNode) bool { return n.count(text) > 0 })
		}
		time.Sleep(200 * time.Millisecond)
		for _, n := range nodes {
			for i := range senders {
				if c := n.count(fmt.Sprintf("broadcast %d", i)); c > 1 {
					t.Fatalf("%s got broadcast %d %d times", n.name, i, c)
				}
			}
		}
	})

	t.Run("direct", func(t *testing.T) {
		r := rand.New(rand.NewPCG(7, 7))
		type pair struct{ from, to *testNode }
		var pairs []pair
		for len(pairs) < 20 {
			a, b := nodes[r.IntN(simNodes)], nodes[r.IntN(simNodes)]
			if a != b {
				pairs = append(pairs, pair{a, b})
			}
		}
		for i, p := range pairs {
			if err := p.from.SendDirect(p.to.Fingerprint(), fmt.Sprintf("secret %d", i)); err != nil {
				t.Fatal(err)
			}
		}
		for i, p := range pairs {
			text := fmt.Sprintf("secret %d", i)
			msg := p.to.waitFor(t, text, 30*time.Second)
			if msg.From != p.from.Fingerprint() {
				t.Fatalf("%s: wrong sender", text)
			}
		}
		time.Sleep(200 * time.Millisecond)
		for i, p := range pairs {
			text := fmt.Sprintf("secret %d", i)
			for _, n := range nodes {
				want := 0
				if n == p.to {
					want = 1
				}
				if c := n.count(text); c != want {
					t.Fatalf("%s delivered %d times to %s", text, c, n.name)
				}
			}
		}
	})

	t.Run("store and forward", func(t *testing.T) {
		// A newcomer writes while out of range of everyone, then walks up to
		// one node: its message spreads to the whole mesh, and it receives
		// the broadcasts it missed from that node's store.
		late := m.add("late")
		late.SendChannel("#general", "written before arriving")
		m.connect("late", nodes[50].name)
		waitAll(t, nodes, 30*time.Second, "newcomer's message", func(n *testNode) bool {
			return n.count("written before arriving") > 0
		})
		for i := range 5 {
			late.waitFor(t, fmt.Sprintf("broadcast %d", i), 10*time.Second)
		}
	})

	t.Run("flood", func(t *testing.T) {
		victim := nodes[10]
		evil := m.rawLink("evil", victim.name)
		f := newForger(t, "flood")
		for i := range 5000 {
			f.sender = PeerID(randomID())
			writePacket(t, evil, f.channel(fmt.Sprint("spam ", i), f.id.sign))
		}
		time.Sleep(4 * time.Second) // let link budgets refill
		if s := victim.Stats(); s.RateLimited < 4000 {
			t.Fatalf("victim rate-limited only %d packets", s.RateLimited)
		}
		nodes[90].SendChannel("#general", "still standing")
		waitAll(t, except(nodes, nodes[90]), 30*time.Second, "post-flood broadcast", func(n *testNode) bool {
			return n.count("still standing") > 0
		})
	})

	var s Stats
	for _, n := range nodes {
		ns := n.Stats()
		s.Relayed += ns.Relayed
		s.Duplicates += ns.Duplicates
		s.RateLimited += ns.RateLimited
		s.Dropped += ns.Dropped
	}
	t.Logf("relayed %d, duplicates %d, rate-limited %d, dropped %d", s.Relayed, s.Duplicates, s.RateLimited, s.Dropped)
}
