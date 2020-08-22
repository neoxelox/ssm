package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"errors"
)

// AesCipher implements a Cipher service with AES encryption
type AesCipher struct {
}

// NewAesCipher creates an instance of AesCipher
func NewAesCipher() Cipher {
	return &AesCipher{}
}

// Init initializes AesCipher dependencies
func (c *AesCipher) init() error {
	return nil
}

// Type retrieves the type of AesCipher
func (c *AesCipher) Type() Type {
	return Ciphers.Aes
}

// PrepareKey transforms the key into AesCipher format
func (c *AesCipher) PrepareKey(key string) ([]byte, error) {
	// AES needs a 32B key
	keyHash := sha256.Sum256([]byte(key))
	return keyHash[:], nil
}

// Encrypt encrypts data with a key applying AES with GCM
func (c *AesCipher) Encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts data with a key applying AES with GCM
func (c *AesCipher) Decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data is shorter than nonce")
	}

	nonce, data := data[:nonceSize], data[nonceSize:]
	result, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}
