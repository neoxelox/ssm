package cipher

// Type describes the type of encryption of a Cipher
type Type string

type ciphersEnum struct {
	Mock Type
	Aes  Type
}

// Has checks if cipherType is in Ciphers
func (c ciphersEnum) Has(cipherType Type) bool {
	return cipherType == c.Mock ||
		cipherType == c.Aes
}

// Ciphers enumerates the supported Cipher types
var Ciphers = &ciphersEnum{
	Mock: "MOCK",
	Aes:  "AES",
}

// Cipher is a component to interact with the different Cipher services
type Cipher interface {
	init() error
	Type() Type
	PrepareKey(key string) ([]byte, error)
	Encrypt(data []byte, key []byte) ([]byte, error)
	Decrypt(data []byte, key []byte) ([]byte, error)
}

// Store maintains Ciphers with it's dependencies
type Store struct {
	mock Cipher
	aes  Cipher
}

// NewStore creates an instance of Store
func NewStore() (*Store, error) {
	store := &Store{
		mock: NewMockCipher(),
		aes:  NewAesCipher(),
	}

	err := store.aes.init()
	if err != nil {
		return nil, err
	}

	return store, nil
}

// Get retrieves the Cipher by it's type
func (s Store) Get(cipherType Type) Cipher {
	switch cipherType {
	case Ciphers.Aes:
		return s.aes
	default:
		return s.mock
	}
}
