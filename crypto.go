package netcode

import (
	"crypto/rand"

	"github.com/jamesruan/sodium"
)

// Generates random bytes
func RandomBytes(bytes int) ([]byte, error) {
	b := make([]byte, bytes)
	_, err := rand.Read(b)
	return b, err
}

// Generates a random key of KEY_BYTES
func GenerateKey() ([]byte, error) {
	return RandomBytes(KEY_BYTES)
}

// Encrypts the message in place with the nonce and key and optional additional buffer
func EncryptAead(message []byte, additional, nonce, key []byte) error {
	ad := sodium.Bytes(additional)
	n := sodium.AEADCPNonce { sodium.Bytes(nonce) }
	k := sodium.AEADCPKey { sodium.Bytes(key) }

	enc := sodium.Bytes(message[:]).AEADCPEncrypt(ad, n, k)
	copy(message[:cap(message)], enc)

	return nil
}

// Decrypts the message with the nonce and key and optional additional buffer returning a copy
// byte slice
func DecryptAead(message []byte, additional, nonce, key []byte) ([]byte, error) {
	ad := sodium.Bytes(additional)
	n := sodium.AEADCPNonce { sodium.Bytes(nonce) }
	k := sodium.AEADCPKey { sodium.Bytes(key) }

	return sodium.Bytes(message[:cap(message)]).AEADCPDecrypt(ad, n, k)
}
