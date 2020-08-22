package ssm

import "errors"

var (
	// ErrEncryptionNotSupported : encryption not supported
	ErrEncryptionNotSupported = errors.New("encryption not supported")

	// ErrEncryptionFailed : encryption failed
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrDecryptionFailed : decryption failed
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrChecksumMismatch : private and protected checksums do not match
	ErrChecksumMismatch = errors.New("checksums do not match")

	// ErrNotASecret : input is not a secret
	ErrNotASecret = errors.New("input is not a secret")
)
