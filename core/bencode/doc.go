// Package bencode implements BitTorrent's bencode encoding (BEP 3).
//
// Decoded values use four Go types: int64 for integers, string for byte strings,
// []any for lists and map[string]any for dictionaries. The decoder treats its input
// as hostile: it is strict about integer syntax, bounds nesting depth, and never
// allocates more than the input length.
package bencode
