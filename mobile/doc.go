// Package mobile is the narrow API exposed to Android through gomobile.
//
// It speaks only in types gomobile can carry: strings, numbers, []byte, and
// interfaces built from those. The platform owns the radios: for each BLE
// connection it calls Node.LinkUp, pushes received frames into the returned
// Link and implements LinkHandler to send frames. Everything the frames mean
// (packets, relaying, signatures, Noise sessions) stays in Go.
package mobile
