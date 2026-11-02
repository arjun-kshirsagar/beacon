package tracker

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// Client announces to HTTP and UDP trackers.
type Client struct {
	HTTP *http.Client
	UDP  transport.PacketTransport
}

// NewClient returns a Client whose traffic goes through the given transports.
func NewClient(t transport.Transport, pt transport.PacketTransport) *Client {
	return &Client{HTTP: NewHTTPClient(t), UDP: pt}
}

// Announce sends req to announceURL using the protocol its scheme names.
func (c *Client) Announce(ctx context.Context, announceURL string, req Request) (*Response, error) {
	u, err := url.Parse(announceURL)
	if err != nil {
		return nil, fmt.Errorf("tracker: %w", err)
	}
	switch {
	case (u.Scheme == "http" || u.Scheme == "https") && c.HTTP != nil:
		return AnnounceHTTP(ctx, c.HTTP, announceURL, req)
	case u.Scheme == "udp" && c.UDP != nil:
		return AnnounceUDP(ctx, c.UDP, announceURL, req)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupported, u.Scheme)
}
