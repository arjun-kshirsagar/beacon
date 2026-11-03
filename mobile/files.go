package mobile

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"

	"github.com/arjun-kshirsagar/beacon/core/offline"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

// Groups is the platform's Wi-Fi Direct control. Methods must return at once;
// report the outcome with Node.GroupReady or Node.GroupFailed.
type Groups interface {
	// HostGroup creates a group with this network name and passphrase.
	HostGroup(network, passphrase string)
	// JoinGroup joins the group with this network name and passphrase.
	JoinGroup(network, passphrase string)
}

type groupsAdapter struct{ g Groups }

func (a groupsAdapter) Host(network, passphrase string) { a.g.HostGroup(network, passphrase) }
func (a groupsAdapter) Join(network, passphrase string) { a.g.JoinGroup(network, passphrase) }

// EnableFiles turns on offline file sharing. Downloads go to dir; g forms the
// groups the files travel over. Call it once, before or after Start.
func (n *Node) EnableFiles(dir string, g Groups) error {
	if g == nil || dir == "" {
		return errors.New("mobile: EnableFiles needs a directory and Groups")
	}
	if err := n.usable(); err != nil {
		return err
	}
	tcp := &transport.TCP{}
	svc := offline.New(offline.Config{Mesh: n.node, Groups: groupsAdapter{g}, Dial: tcp, Dir: dir,
		Listen: func() (net.Listener, error) { return tcp.Listen(":0") }})
	if !n.files.CompareAndSwap(nil, svc) {
		svc.Close()
		return errors.New("mobile: files already enabled")
	}
	return nil
}

var errNoFiles = errors.New("mobile: file sharing is not enabled")

func (n *Node) service() (*offline.Service, error) {
	if err := n.usable(); err != nil {
		return nil, err
	}
	if f := n.files.Load(); f != nil {
		return f, nil
	}
	return nil, errNoFiles
}

// ShareFile seeds the file at path and announces it to the mesh. It returns
// the info-hash in hex.
func (n *Node) ShareFile(path string) (string, error) {
	f, err := n.service()
	if err != nil {
		return "", err
	}
	ih, err := f.Share(path)
	return hex.EncodeToString(ih[:]), err
}

// GetFile fetches an announced file by its hex info-hash.
func (n *Node) GetFile(infoHash string) error {
	f, err := n.service()
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(infoHash)
	if err != nil || len(b) != 20 {
		return errors.New("mobile: bad info-hash")
	}
	return f.Get([20]byte(b))
}

// SharesJSON lists files announced nearby: a JSON array of objects with
// infoHash, name, size, from, sources and have.
func (n *Node) SharesJSON() string {
	f, err := n.service()
	if err != nil {
		return "[]"
	}
	return toJSON(f.Seen())
}

// TransfersJSON lists our shares and downloads: a JSON array of objects with
// infoHash, name, state, pieces, totalPieces, peers, uploaded, from (verified
// bytes by sender IP), path and error.
func (n *Node) TransfersJSON() string {
	f, err := n.service()
	if err != nil {
		return "[]"
	}
	return toJSON(f.Transfers())
}

func toJSON[T any](v []T) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// GroupReady reports that this device is in the group, with address ip.
func (n *Node) GroupReady(ip string) {
	if f := n.files.Load(); f != nil {
		f.GroupReady(ip)
	}
}

// GroupFailed reports that hosting or joining a group failed.
func (n *Node) GroupFailed(reason string) {
	if f := n.files.Load(); f != nil {
		f.GroupFailed(reason)
	}
}

// GroupGone reports that the group dissolved or this device left it.
func (n *Node) GroupGone() {
	if f := n.files.Load(); f != nil {
		f.GroupGone()
	}
}
