// Package noise implements the Noise_XX_25519_ChaChaPoly_SHA256 handshake from
// the Noise Protocol Framework (revision 34) and the cipher states it produces.
//
// XX authenticates both sides by their static X25519 keys and gives forward
// secrecy through ephemeral keys:
//
//	-> e
//	<- e, ee, s, es
//	-> s, se
//
// The implementation follows the specification's HandshakeState, SymmetricState
// and CipherState objects and is checked against the cacophony test vectors.
package noise
