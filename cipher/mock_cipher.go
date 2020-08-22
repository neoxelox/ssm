package cipher

import (
	"github.com/stretchr/testify/mock"
)

// MockCipher mocks a Cipher service
type MockCipher struct {
	mock.Mock
}

// NewMockCipher creates an instance of MockCipher
func NewMockCipher() *MockCipher {
	return &MockCipher{}
}

// Init mocks Init function
func (m *MockCipher) init() error {
	args := m.Called()
	return args.Error(0)
}

// Type mocks Type function
func (m *MockCipher) Type() Type {
	return Ciphers.Mock
}

// PrepareKey mocks PrepareKey function
func (m *MockCipher) PrepareKey(key string) ([]byte, error) {
	args := m.Called(key)
	return args.Get(0).([]byte), args.Error(1)
}

// Encrypt mocks Encrypt function
func (m *MockCipher) Encrypt(data []byte, key []byte) ([]byte, error) {
	args := m.Called(data, key)
	return args.Get(0).([]byte), args.Error(1)
}

// Decrypt mocks Decrypt function
func (m *MockCipher) Decrypt(data []byte, key []byte) ([]byte, error) {
	args := m.Called(data, key)
	return args.Get(0).([]byte), args.Error(1)
}
