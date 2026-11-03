package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/arjun-kshirsagar/beacon/core/lan"
	"github.com/arjun-kshirsagar/beacon/core/mesh"
	"github.com/arjun-kshirsagar/beacon/core/torrent"
	"github.com/arjun-kshirsagar/beacon/core/transport"
)

const chatHelp = `Commands:
  <text>                 send to the current channel
  /join #channel         switch channel
  /msg <name> <text>     encrypted direct message (name or fingerprint prefix)
  /peers                 who is nearby
  /whoami                your fingerprint
  /share <path>          share a file or directory with the current channel
  /shares                files shared with you
  /get <n | magnet>      download a share (seeds it afterwards)
  /downloads             download progress
  /help                  this text
  /quit                  leave`

// chatFlags are shared by chat and tui.
type chatFlags struct {
	nick, identity, dir, logFile *string
	port                         *uint
	noDiscovery, dht, verbose    *bool
	peers                        stringList
}

func addChatFlags(fs *flag.FlagSet) *chatFlags {
	cf := &chatFlags{
		nick:        fs.String("nick", defaultNick(), "your nickname"),
		identity:    fs.String("identity", defaultIdentityPath(), "file holding your identity keys"),
		dir:         fs.String("o", ".", "directory downloads are saved to"),
		logFile:     fs.String("log", "", "write logs to this file"),
		port:        fs.Uint("port", 0, "TCP port for LAN mesh links (0 picks one)"),
		noDiscovery: fs.Bool("no-discovery", false, "do not find nodes by multicast; use -peer"),
		dht:         fs.Bool("dht", false, "also find share peers through the internet DHT"),
		verbose:     fs.Bool("v", false, "verbose logging"),
	}
	fs.Var(&cf.peers, "peer", "node host:port to link to (repeatable)")
	return cf
}

func defaultNick() string {
	name := os.Getenv("USER")
	if mesh.CheckNickname(name) != nil {
		return "beacon"
	}
	return name
}

func defaultIdentityPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "beacon-identity"
	}
	return filepath.Join(dir, "beacon", "identity")
}

// loadIdentity reads the identity at path, creating one on first run. The
// file holds private keys, so it is written readable by the owner only.
func loadIdentity(path string) (*mesh.Identity, bool, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		id, err := mesh.UnmarshalIdentity(b)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		return id, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	id, err := mesh.NewIdentity()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, id.Marshal(), 0o600); err != nil {
		return nil, false, err
	}
	return id, true, nil
}

// event is one line for the user interface.
type event struct {
	Time    time.Time
	Kind    string // "channel", "dm", "info", "error"
	Channel string
	From    string
	Text    string
}

// share is a magnet link someone posted.
type share struct {
	From   string
	Name   string
	Magnet string
}

// download is a share being fetched or seeded.
type download struct {
	name   string
	swarm  *swarm // nil while metadata is fetched
	err    error
	shared bool // we are the original sharer
}

// chat is the session behind both the line interface and the TUI.
type chat struct {
	node    *mesh.Node
	links   *lan.Links
	net     netOpts
	dir     string
	ctx     context.Context
	events  chan event
	log     *slog.Logger
	channel string

	mu        sync.Mutex
	shares    []share
	downloads []*download
	nearby    map[mesh.Fingerprint]string
}

// startChat loads the identity and joins the LAN mesh.
func startChat(ctx context.Context, cf *chatFlags, logOut io.Writer) (*chat, error) {
	if err := mesh.CheckNickname(*cf.nick); err != nil {
		return nil, fmt.Errorf("nickname: %w", err)
	}
	id, created, err := loadIdentity(*cf.identity)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	level := slog.LevelInfo
	if *cf.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: level}))

	cfg := lan.Config{Stream: &transport.TCP{}, Listen: fmt.Sprintf(":%d", *cf.port), Logger: log}
	if !*cf.noDiscovery {
		cfg.Multicast = transport.UDP{}
	}
	links, err := lan.Listen(cfg)
	if err != nil {
		return nil, err
	}
	c := &chat{links: links, dir: *cf.dir, ctx: ctx, events: make(chan event, 256), log: log,
		channel: "#general", nearby: map[mesh.Fingerprint]string{}}
	c.node, err = mesh.New(mesh.Config{Identity: id, Nickname: *cf.nick, Links: links,
		OnMessage: c.onMessage, Logger: log})
	if err != nil {
		return nil, err
	}
	// Shares are found on the LAN by local peer discovery and the x.pe
	// address in the magnet; the DHT only when asked, for bridging.
	c.net = netOpts{log: log}
	if c.net.lpd, err = startLPD(ctx, log); err != nil {
		log.Warn("local peer discovery unavailable", "err", err)
	}
	if *cf.dht {
		if c.net.node, err = startDHT(ctx, 0, log); err != nil {
			return nil, err
		}
	}
	go links.Run(ctx)
	go c.node.Run(ctx)
	for _, p := range cf.peers {
		go func() {
			if err := links.Dial(ctx, p); err != nil {
				c.emit(event{Kind: "error", Text: fmt.Sprintf("linking to %s: %v", p, err)})
			}
		}()
	}
	go c.watchPeers()
	if created {
		c.emit(event{Kind: "info", Text: "created a new identity in " + *cf.identity})
	}
	c.emit(event{Kind: "info", Text: fmt.Sprintf("you are %s, fingerprint %s; LAN links on port %d",
		*cf.nick, id.Fingerprint(), links.Port())})
	return c, nil
}

func (c *chat) emit(e event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	select {
	case c.events <- e:
	case <-c.ctx.Done():
	}
}

func (c *chat) onMessage(m mesh.Message) {
	e := event{Time: m.Time, Kind: "dm", From: m.Nickname, Text: m.Text}
	if m.Channel != "" {
		e.Kind, e.Channel = "channel", m.Channel
	}
	if e.From == "" {
		e.From = m.From.Short()
	}
	c.noteShare(e.From, m.Text)
	c.emit(e)
}

// noteShare records a magnet link in a message so /get can refer to it.
func (c *chat) noteShare(from, text string) {
	i := strings.Index(text, "magnet:?")
	if i < 0 {
		return
	}
	link := strings.Fields(text[i:])[0]
	m, err := torrent.ParseMagnet(link)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.shares = append(c.shares, share{From: from, Name: m.Name, Magnet: link})
	n := len(c.shares)
	c.mu.Unlock()
	go c.emit(event{Kind: "info", Text: fmt.Sprintf("%s shared %q; type /get %d to download", from, m.Name, n)})
}

// watchPeers reports people coming into and leaving range.
func (c *chat) watchPeers() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		}
		now := map[mesh.Fingerprint]string{}
		for _, p := range c.node.Peers() {
			now[p.Fingerprint] = p.Nickname
		}
		c.mu.Lock()
		var joined, left []string
		for fp, nick := range now {
			if _, ok := c.nearby[fp]; !ok {
				joined = append(joined, fmt.Sprintf("%s (%s)", nick, fp.Short()))
			}
		}
		for fp, nick := range c.nearby {
			if _, ok := now[fp]; !ok {
				left = append(left, nick)
			}
		}
		c.nearby = now
		c.mu.Unlock()
		for _, j := range joined {
			c.emit(event{Kind: "info", Text: j + " is nearby"})
		}
		for _, l := range left {
			c.emit(event{Kind: "info", Text: l + " left"})
		}
	}
}

// errQuit asks the interface to exit.
var errQuit = errors.New("quit")

// input handles one line typed by the user.
func (c *chat) input(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if !strings.HasPrefix(line, "/") {
		if err := c.node.SendChannel(c.channel, line); err != nil {
			return err
		}
		c.emit(event{Kind: "channel", Channel: c.channel, From: "you", Text: line})
		return nil
	}
	cmd, rest, _ := strings.Cut(line, " ")
	rest = strings.TrimSpace(rest)
	switch cmd {
	case "/quit", "/exit":
		return errQuit
	case "/help":
		c.emit(event{Kind: "info", Text: chatHelp})
	case "/join":
		if err := mesh.CheckChannel(rest); err != nil {
			return fmt.Errorf("channels look like #general: %w", err)
		}
		c.channel = rest
		c.emit(event{Kind: "info", Text: "now talking in " + rest})
	case "/whoami":
		c.emit(event{Kind: "info", Text: "fingerprint " + string(c.node.Fingerprint())})
	case "/peers":
		peers := c.node.Peers()
		if len(peers) == 0 {
			c.emit(event{Kind: "info", Text: "nobody nearby yet"})
		}
		sort.Slice(peers, func(i, j int) bool { return peers[i].Nickname < peers[j].Nickname })
		for _, p := range peers {
			c.emit(event{Kind: "info", Text: fmt.Sprintf("%-16s %s", p.Nickname, p.Fingerprint)})
		}
	case "/msg":
		to, text, ok := strings.Cut(rest, " ")
		if !ok {
			return errors.New("usage: /msg <name> <text>")
		}
		p, err := c.findPeer(to)
		if err != nil {
			return err
		}
		if err := c.node.SendDirect(p.Fingerprint, strings.TrimSpace(text)); err != nil {
			return err
		}
		c.emit(event{Kind: "dm", From: "you → " + p.Nickname, Text: strings.TrimSpace(text)})
	case "/share":
		return c.share(rest)
	case "/shares":
		c.mu.Lock()
		shares := slices.Clone(c.shares)
		c.mu.Unlock()
		if len(shares) == 0 {
			c.emit(event{Kind: "info", Text: "nothing shared yet"})
		}
		for i, s := range shares {
			c.emit(event{Kind: "info", Text: fmt.Sprintf("%d. %s from %s", i+1, s.Name, s.From)})
		}
	case "/get":
		return c.get(rest)
	case "/downloads":
		for _, line := range c.progress() {
			c.emit(event{Kind: "info", Text: line})
		}
	default:
		return fmt.Errorf("unknown command %s; try /help", cmd)
	}
	return nil
}

// findPeer resolves a nickname or fingerprint prefix to one peer.
func (c *chat) findPeer(name string) (mesh.Peer, error) {
	var found []mesh.Peer
	for _, p := range c.node.Peers() {
		if p.Nickname == name || len(name) >= 4 && strings.HasPrefix(string(p.Fingerprint), name) {
			found = append(found, p)
		}
	}
	switch len(found) {
	case 0:
		return mesh.Peer{}, fmt.Errorf("nobody called %q nearby; see /peers", name)
	case 1:
		return found[0], nil
	}
	return mesh.Peer{}, fmt.Errorf("%d people are called %q; use a fingerprint prefix from /peers", len(found), name)
}

// share seeds path and posts its magnet link to the current channel.
func (c *chat) share(path string) error {
	if path == "" {
		return errors.New("usage: /share <path>")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	meta, err := torrent.Create(abs, torrent.DefaultPieceLength, "")
	if err != nil {
		return err
	}
	t, err := torrent.Parse(meta)
	if err != nil {
		return err
	}
	s, err := joinSwarm(c.ctx, t, filepath.Dir(abs), c.net)
	if err != nil {
		return err
	}
	select {
	case <-s.c.Done():
	default:
		s.stop()
		return fmt.Errorf("%s changed while being read; try again", path)
	}
	c.mu.Lock()
	c.downloads = append(c.downloads, &download{name: t.Name, swarm: s, shared: true})
	c.mu.Unlock()

	m := torrent.Magnet{InfoHash: t.InfoHash, Name: t.Name}
	if ip := lanIP(); ip != "" {
		m.Peers = []string{net.JoinHostPort(ip, fmt.Sprint(s.port))}
	}
	text := fmt.Sprintf("shared %s (%s) %s", t.Name, size(t.Length), m.String())
	if err := c.node.SendChannel(c.channel, text); err != nil {
		return fmt.Errorf("posting the link: %w", err)
	}
	c.emit(event{Kind: "channel", Channel: c.channel, From: "you", Text: text})
	return nil
}

// lanIP returns this machine's address on the default route, for others on
// the LAN to reach our shares. No packet is sent.
func lanIP() string {
	conn, err := net.Dial("udp4", lan.Group4)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// get downloads a share by number or magnet link, then keeps seeding it.
func (c *chat) get(arg string) error {
	link := arg
	if !strings.HasPrefix(arg, "magnet:") {
		var n int
		if _, err := fmt.Sscan(arg, &n); err != nil {
			return errors.New("usage: /get <n | magnet>; see /shares")
		}
		c.mu.Lock()
		if n < 1 || n > len(c.shares) {
			c.mu.Unlock()
			return fmt.Errorf("no share %d; see /shares", n)
		}
		link = c.shares[n-1].Magnet
		c.mu.Unlock()
	}
	m, err := torrent.ParseMagnet(link)
	if err != nil {
		return err
	}
	d := &download{name: m.Name}
	c.mu.Lock()
	c.downloads = append(c.downloads, d)
	c.mu.Unlock()
	c.emit(event{Kind: "info", Text: fmt.Sprintf("fetching %s", m.Name)})
	go func() {
		err := c.fetch(m, d)
		c.mu.Lock()
		d.err = err
		c.mu.Unlock()
		if err != nil && c.ctx.Err() == nil {
			c.emit(event{Kind: "error", Text: fmt.Sprintf("%s: %v", m.Name, err)})
		}
	}()
	return nil
}

func (c *chat) fetch(m *torrent.Magnet, d *download) error {
	o := c.net
	o.peers = m.Peers
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
	t, err := resolveMagnet(ctx, m, o)
	cancel()
	if err != nil {
		return fmt.Errorf("finding the file: %w", err)
	}
	s, err := joinSwarm(c.ctx, t, c.dir, o)
	if err != nil {
		return err
	}
	c.mu.Lock()
	d.name, d.swarm = t.Name, s
	c.mu.Unlock()
	select {
	case <-s.c.Done():
		c.emit(event{Kind: "info", Text: fmt.Sprintf("downloaded and verified %s into %s; now seeding it",
			t.Name, filepath.Join(c.dir, t.Name))})
	case <-c.ctx.Done():
	}
	return nil
}

// progress describes every download and share.
func (c *chat) progress() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.downloads) == 0 {
		return []string{"no downloads or shares"}
	}
	var out []string
	for _, d := range c.downloads {
		switch {
		case d.err != nil:
			out = append(out, fmt.Sprintf("%s: failed: %v", d.name, d.err))
		case d.swarm == nil:
			out = append(out, fmt.Sprintf("%s: looking for peers", d.name))
		default:
			st := d.swarm.c.Stats()
			state := fmt.Sprintf("%d/%d pieces", st.Pieces, st.TotalPieces)
			if st.Pieces == st.TotalPieces {
				state = "seeding"
			}
			if d.shared {
				state = "sharing"
			}
			out = append(out, fmt.Sprintf("%s: %s, %d peers, %s up", d.name, state, st.Peers, size(st.Uploaded)))
		}
	}
	return out
}

// close stops every swarm.
func (c *chat) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.downloads {
		if d.swarm != nil {
			d.swarm.stop()
		}
	}
}

// openLog returns where logs go: the -log file, or w.
func openLog(cf *chatFlags, w io.Writer) (io.Writer, func(), error) {
	if *cf.logFile == "" {
		return w, func() {}, nil
	}
	f, err := os.OpenFile(*cf.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// format renders an event as one line of text.
func (e event) format() string {
	ts := e.Time.Format("15:04")
	switch e.Kind {
	case "channel":
		return fmt.Sprintf("%s [%s] %s: %s", ts, e.Channel, e.From, e.Text)
	case "dm":
		return fmt.Sprintf("%s [dm] %s: %s", ts, e.From, e.Text)
	case "error":
		return fmt.Sprintf("%s ! %s", ts, e.Text)
	}
	return fmt.Sprintf("%s * %s", ts, e.Text)
}

func cmdChat(ctx context.Context, args []string) error {
	fs := newFlags("chat", "")
	cf := addChatFlags(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	logOut, closeLog, err := openLog(cf, os.Stderr)
	if err != nil {
		return err
	}
	defer closeLog()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c, err := startChat(ctx, cf, logOut)
	if err != nil {
		return err
	}
	defer c.close()
	go func() {
		for e := range c.events {
			fmt.Println(e.format())
		}
	}()
	fmt.Println("type /help for commands")

	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			lines <- sc.Text()
		}
		// At end of input keep running as a relay until interrupted.
		close(lines)
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case line, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			if err := c.input(line); errors.Is(err, errQuit) {
				return nil
			} else if err != nil {
				c.emit(event{Kind: "error", Text: err.Error()})
			}
		}
	}
}
