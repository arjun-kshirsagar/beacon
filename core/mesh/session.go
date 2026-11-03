package mesh

import "time"

// dmState will hold Noise sessions for direct messages.
type dmState struct{}

func (d *dmState) init()                       {}
func (d *dmState) rotated()                    {}
func (d *dmState) tick(n *Node, now time.Time) {}

func (d *dmState) handle(n *Node, p *Packet, now time.Time) []Message { return nil }
