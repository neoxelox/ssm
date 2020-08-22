package ssm

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/neoxelox/ssm/cipher"
)

// Fact describes all the parts that form a Fact
type Fact struct {
	Public    public    `json:"public"`
	Private   [][]byte  `json:"private"`
	Protected protected `json:"protected"`
}

// Size retrieves the size of Fact
func (f *Fact) Size() int {
	return len(f.Private)
}

// String overrides the string representation of Fact
func (f *Fact) String() string {
	return fmt.Sprintf("Fact<%s: [%d]>", f.Public.Encryption, f.Size())
}

// Hide creates a new Secret with key
func (f *Fact) Hide(key string) (*Secret, error) {
	if !cipher.Ciphers.Has(f.Public.Encryption) {
		return nil, ErrEncryptionNotSupported
	}

	cph := cipherStore.Get(f.Public.Encryption)

	pKey, err := cph.PrepareKey(key)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	privateData, err := cph.Encrypt(bytes.Join(f.Private, f.Protected.Separator), pKey)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	f.Protected.Checksum = sha256.Sum256(privateData)

	protectedData, err := json.Marshal(&f.Protected)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	protectedData, err = cph.Encrypt(protectedData, pKey)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	secret := &Secret{
		Public:    f.Public,
		Private:   privateData,
		Protected: protectedData,
	}

	return secret, nil
}
