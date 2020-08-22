package ssm

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/neoxelox/ssm/cipher"
)

// Secret describes all the parts that form a Secret
type Secret struct {
	Public    public `json:"public"`
	Private   []byte `json:"private"`
	Protected []byte `json:"protected"`
}

// Size retrieves the size of Secret
func (s *Secret) Size() int {
	return len(s.Private)
}

// String overrides the string representation of Secret
func (s *Secret) String() string {
	return fmt.Sprintf("Secret<%s: %s>", s.Public.Encryption, byteSize(s.Size()))
}

// Tell creates a new Fact with key
func (s *Secret) Tell(key string) (*Fact, error) {
	if !cipher.Ciphers.Has(s.Public.Encryption) {
		return nil, ErrEncryptionNotSupported
	}

	cph := cipherStore.Get(s.Public.Encryption)

	pKey, err := cph.PrepareKey(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	protectedData, err := cph.Decrypt(s.Protected, pKey)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	protected := protected{}

	err = json.Unmarshal(protectedData, &protected)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	privateChecksum := sha256.Sum256(s.Private)

	if !bytes.Equal(privateChecksum[:], protected.Checksum[:]) {
		return nil, ErrChecksumMismatch
	}

	privateData, err := cph.Decrypt(s.Private, pKey)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	private := bytes.Split(privateData, protected.Separator)

	fact := &Fact{
		Public:    s.Public,
		Private:   private,
		Protected: protected,
	}

	return fact, nil
}
