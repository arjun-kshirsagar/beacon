package dht

import (
	"context"
	"net/netip"
)

type candidate struct {
	Contact
	queried   bool
	responded bool
	failed    bool
	token     string
}

type lookupResult struct {
	closest []*candidate // up to K responders nearest the target
	peers   []netip.AddrPort
}

type reply struct {
	c     *candidate
	r     map[string]any
	err   error
	nodes []Contact
}

// lookup runs an iterative Kademlia lookup for target: it keeps alpha queries in
// flight to the nearest unqueried candidates and stops once the K nearest live
// candidates have all answered. With getPeers it sends get_peers and collects
// peers and announce tokens; otherwise find_node.
func (n *Node) lookup(ctx context.Context, target ID, getPeers bool) (*lookupResult, error) {
	n.mu.Lock()
	seed := n.table.closest(target, K)
	n.mu.Unlock()
	if len(seed) == 0 {
		return nil, ErrNoNodes
	}

	cands := map[ID]*candidate{}
	var order []Contact
	add := func(c Contact) {
		if c.ID == n.id || len(cands) >= maxCandidates {
			return
		}
		if _, ok := cands[c.ID]; !ok {
			cands[c.ID] = &candidate{Contact: c}
			order = append(order, c)
		}
	}
	for _, c := range seed {
		add(c)
	}

	method, key := "find_node", "target"
	if getPeers {
		method, key = "get_peers", "info_hash"
	}
	res := &lookupResult{}
	seenPeers := map[netip.AddrPort]bool{}
	replies := make(chan reply)
	inflight := 0

	for {
		// The K nearest candidates that have not failed.
		sortByDistance(order, target)
		var live []*candidate
		for _, c := range order {
			if cand := cands[c.ID]; !cand.failed {
				live = append(live, cand)
				if len(live) == K {
					break
				}
			}
		}
		for _, cand := range live {
			if inflight >= alpha {
				break
			}
			if cand.queried {
				continue
			}
			cand.queried = true
			inflight++
			go func() {
				rep := reply{c: cand}
				to, err := n.resolve(ctx, cand.Addr)
				if err == nil {
					rep.r, err = n.query(ctx, to, &cand.ID, method, map[string]any{key: string(target[:])})
				}
				rep.err = err
				if err == nil {
					if s, ok := rep.r["nodes"].(string); ok {
						rep.nodes, _ = decodeNodes([]byte(s))
					}
				}
				replies <- rep
			}()
		}
		if inflight == 0 {
			break
		}

		rep := <-replies
		inflight--
		if rep.err != nil {
			rep.c.failed = true
			continue
		}
		rep.c.responded = true
		for _, c := range rep.nodes {
			add(c)
		}
		if getPeers {
			rep.c.token, _ = rep.r["token"].(string)
			values, _ := rep.r["values"].([]any)
			for _, v := range values {
				s, _ := v.(string)
				if p, ok := decodePeer(s); ok && !seenPeers[p] && len(res.peers) < maxLookupPeers {
					seenPeers[p] = true
					res.peers = append(res.peers, p)
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for _, c := range order {
		if cand := cands[c.ID]; cand.responded {
			res.closest = append(res.closest, cand)
			if len(res.closest) == K {
				break
			}
		}
	}
	return res, nil
}
