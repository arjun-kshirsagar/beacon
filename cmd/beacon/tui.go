package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/arjun-kshirsagar/beacon/core/mesh"
)

const (
	sidebarWidth = 32
	maxLines     = 2000 // chat history kept on screen; messages are never written to disk
)

var (
	styleHeader  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	styleDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleNick    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	styleSelf    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	styleDM      = lipgloss.NewStyle().Foreground(lipgloss.Color("13"))
	styleError   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleSection = lipgloss.NewStyle().Bold(true).Underline(true)
	styleSidebar = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderLeft(true).
			BorderForeground(lipgloss.Color("8")).PaddingLeft(1)
)

type eventMsg event
type tickMsg struct{}

type tuiModel struct {
	c        *chat
	nick     string
	input    textinput.Model
	vp       viewport.Model
	events   []event
	peers    []mesh.Peer
	progress []string
	width    int
	height   int
}

func newTUI(c *chat, nick string) *tuiModel {
	in := textinput.New()
	in.Placeholder = "message, or /help"
	in.Prompt = "> "
	in.CharLimit = mesh.MaxText
	in.Focus()
	return &tuiModel{c: c, nick: nick, input: in, vp: viewport.New(80, 20)}
}

func (m *tuiModel) waitEvent() tea.Cmd {
	return func() tea.Msg {
		select {
		case e := <-m.c.events:
			return eventMsg(e)
		case <-m.c.ctx.Done():
			return tea.Quit()
		}
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *tuiModel) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, m.waitEvent(), tick())
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyEnter:
			line := m.input.Value()
			m.input.Reset()
			if err := m.c.input(line); errors.Is(err, errQuit) {
				return m, tea.Quit
			} else if err != nil {
				m.add(event{Time: time.Now(), Kind: "error", Text: err.Error()})
			}
			return m, nil
		case tea.KeyPgUp, tea.KeyPgDown, tea.KeyUp, tea.KeyDown:
			// Scroll keys only: letters typed must reach the input.
			var cmd tea.Cmd
			m.vp, cmd = m.vp.Update(msg)
			return m, cmd
		}
	case tea.MouseMsg:
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	case eventMsg:
		m.add(event(msg))
		return m, m.waitEvent()
	case tickMsg:
		m.peers = m.c.node.Peers()
		sort.Slice(m.peers, func(i, j int) bool { return m.peers[i].Nickname < m.peers[j].Nickname })
		m.progress = m.c.progress()
		return m, tick()
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *tuiModel) add(e event) {
	m.events = append(m.events, e)
	if len(m.events) > maxLines {
		m.events = slices.Delete(m.events, 0, len(m.events)-maxLines)
	}
	atBottom := m.vp.AtBottom()
	m.render()
	if atBottom {
		m.vp.GotoBottom()
	}
}

func (m *tuiModel) chatWidth() int {
	if m.width >= 80 {
		return m.width - sidebarWidth - 1
	}
	return m.width
}

func (m *tuiModel) layout() {
	m.vp.Width = max(10, m.chatWidth())
	m.vp.Height = max(3, m.height-3) // header, divider, input
	m.input.Width = max(10, m.width-4)
	m.render()
	m.vp.GotoBottom()
}

func (m *tuiModel) render() {
	w := lipgloss.NewStyle().Width(m.vp.Width)
	var b strings.Builder
	for _, e := range m.events {
		b.WriteString(w.Render(styleLine(e)))
		b.WriteByte('\n')
	}
	m.vp.SetContent(strings.TrimSuffix(b.String(), "\n"))
}

func styleLine(e event) string {
	ts := styleDim.Render(e.Time.Format("15:04"))
	from := styleNick.Render(e.From)
	if strings.HasPrefix(e.From, "you") {
		from = styleSelf.Render(e.From)
	}
	switch e.Kind {
	case "channel":
		return fmt.Sprintf("%s %s %s: %s", ts, styleDim.Render(e.Channel), from, e.Text)
	case "dm":
		return fmt.Sprintf("%s %s %s: %s", ts, styleDM.Render("dm"), from, styleDM.Render(e.Text))
	case "error":
		return fmt.Sprintf("%s %s", ts, styleError.Render(e.Text))
	}
	return fmt.Sprintf("%s %s", ts, styleDim.Render(e.Text))
}

func (m *tuiModel) sidebar() string {
	var b strings.Builder
	b.WriteString(styleSection.Render(fmt.Sprintf("Nearby (%d)", len(m.peers))) + "\n")
	if len(m.peers) == 0 {
		b.WriteString(styleDim.Render("nobody yet") + "\n")
	}
	for _, p := range m.peers {
		b.WriteString(fmt.Sprintf("%s %s\n", styleNick.Render(trim(p.Nickname, 14)), styleDim.Render(p.Fingerprint.Short()[:8])))
	}
	b.WriteString("\n" + styleSection.Render("Files") + "\n")
	for _, p := range m.progress {
		b.WriteString(trim(p, sidebarWidth-2) + "\n")
	}
	return styleSidebar.Height(m.vp.Height).Width(sidebarWidth).Render(strings.TrimSuffix(b.String(), "\n"))
}

func trim(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func (m *tuiModel) View() string {
	if m.width == 0 {
		return "starting…"
	}
	header := styleHeader.Render(fmt.Sprintf("beacon · %s · %s", m.nick, m.c.channel)) +
		styleDim.Render(fmt.Sprintf("  %s  ·  %d nearby  ·  PgUp/PgDn scroll, Esc quits",
			m.c.node.Fingerprint().Short(), len(m.peers)))
	body := m.vp.View()
	if m.width >= 80 {
		body = lipgloss.JoinHorizontal(lipgloss.Top, body, m.sidebar())
	}
	divider := styleDim.Render(strings.Repeat("─", m.width))
	return lipgloss.JoinVertical(lipgloss.Left, trim(header, m.width+40), body, divider, m.input.View())
}

func cmdTUI(ctx context.Context, args []string) error {
	fs := newFlags("tui", "")
	cf := addChatFlags(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	// The screen is the interface; logs go to -log or nowhere.
	logOut, closeLog, err := openLog(cf, io.Discard)
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
	_, err = tea.NewProgram(newTUI(c, *cf.nick), tea.WithAltScreen(), tea.WithMouseCellMotion(),
		tea.WithContext(ctx)).Run()
	if errors.Is(err, tea.ErrProgramKilled) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
