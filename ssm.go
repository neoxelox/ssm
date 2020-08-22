// Package ssm implements functions to deal with secure secret management.
package ssm

import (
	"encoding/json"

	"github.com/neoxelox/ssm/cipher"
)

// VERSION describes the ssm version
const VERSION = "0.1.3"

var incompatibleVersions = []string{}
var cipherStore *cipher.Store

func init() {
	var err error
	cipherStore, err = cipher.NewStore()
	if err != nil {
		panic(err)
	}
}

// Parse creates a new Secret from byte data
func Parse(data []byte) (*Secret, error) {
	secret := &Secret{}

	err := json.Unmarshal(data, secret)
	if err != nil {
		return nil, ErrNotASecret
	}

	for _, version := range incompatibleVersions {
		if secret.Public.Version == version {
			return nil, ErrNotASecret
		}
	}

	if !cipher.Ciphers.Has(secret.Public.Encryption) {
		return nil, ErrNotASecret
	}

	if len(secret.Protected) < 1 {
		return nil, ErrNotASecret
	}

	return secret, nil
}

// Create creates a new Fact with encryption and separator
func Create(encryption cipher.Type, separator *string) (*Fact, error) {
	privateSeparator := []byte("%%--%%")
	if separator != nil {
		privateSeparator = []byte(*separator)
	}

	if !cipher.Ciphers.Has(encryption) {
		return nil, ErrEncryptionNotSupported
	}

	fact := &Fact{
		Public: public{
			Version:    VERSION,
			Encryption: encryption,
		},
		Protected: protected{
			Separator: privateSeparator,
		},
	}

	return fact, nil
}
