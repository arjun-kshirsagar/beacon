package mesh

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arjun-kshirsagar/beacon/core/noise"
)

const (
	// MaxNickname bounds a nickname in bytes.
	MaxNickname = 32
	// MaxChannel bounds a channel name in bytes, including the '#'.
	MaxChannel = 32
	// MaxText bounds a message's text in bytes.
	MaxText = 1024
)

// ErrPayload reports a payload that does not follow its type's format.
var ErrPayload = errors.New("mesh: malformed payload")

// announce is an announce packet's payload.
type announce struct {
	signKey  ed25519.PublicKey
	noiseKey [noise.KeySize]byte
	nickname string
}

func (a announce) encode() []byte {
	b := append([]byte(nil), a.signKey...)
	b = append(b, a.noiseKey[:]...)
	b = append(b, byte(len(a.nickname)))
	return append(b, a.nickname...)
}

func parseAnnounce(b []byte) (announce, error) {
	const keys = ed25519.PublicKeySize + noise.KeySize
	if len(b) < keys+1 || len(b) != keys+1+int(b[keys]) {
		return announce{}, fmt.Errorf("%w: announce length", ErrPayload)
	}
	a := announce{signKey: append(ed25519.PublicKey(nil), b[:ed25519.PublicKeySize]...)}
	copy(a.noiseKey[:], b[ed25519.PublicKeySize:])
	a.nickname = string(b[keys+1:])
	if err := CheckNickname(a.nickname); err != nil {
		return announce{}, err
	}
	return a, nil
}

// CheckNickname reports whether s is a valid nickname: 1 to 32 bytes of
// printable UTF-8.
func CheckNickname(s string) error {
	if s == "" || len(s) > MaxNickname || !printable(s) {
		return fmt.Errorf("%w: nickname %q", ErrPayload, s)
	}
	return nil
}

// printable reports whether s is valid UTF-8 without control or format
// characters, which could be used to spoof how a name or message displays.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// channelMessage is a channel packet's payload.
type channelMessage struct {
	channel string
	text    string
}

func (m channelMessage) encode() []byte {
	b := append([]byte{byte(len(m.channel))}, m.channel...)
	return append(b, m.text...)
}

func parseChannelMessage(b []byte) (channelMessage, error) {
	if len(b) < 1 {
		return channelMessage{}, fmt.Errorf("%w: channel length", ErrPayload)
	}
	end := 1 + int(b[0]) // as int: 1+b[0] in byte arithmetic wraps at 255
	if len(b) < end {
		return channelMessage{}, fmt.Errorf("%w: channel length", ErrPayload)
	}
	m := channelMessage{channel: string(b[1:end]), text: string(b[end:])}
	if err := CheckChannel(m.channel); err != nil {
		return channelMessage{}, err
	}
	if err := checkText(m.text); err != nil {
		return channelMessage{}, err
	}
	return m, nil
}

// CheckChannel reports whether name is a valid channel: '#' followed by
// lowercase letters, digits, '-' or '_'.
func CheckChannel(name string) error {
	if len(name) < 2 || len(name) > MaxChannel || name[0] != '#' {
		return fmt.Errorf("%w: channel %q", ErrPayload, name)
	}
	if strings.IndexFunc(name[1:], func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	}) >= 0 {
		return fmt.Errorf("%w: channel %q", ErrPayload, name)
	}
	return nil
}

func checkText(s string) error {
	if s == "" || len(s) > MaxText || !printable(s) {
		return fmt.Errorf("%w: text", ErrPayload)
	}
	return nil
}
