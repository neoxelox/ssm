package ssm

import "errors"

var (
	// ErrEncryptionNotSupported ...
	ErrEncryptionNotSupported = errors.New("encryption not supported")

	// ErrEncryptionFailed ...
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrDecryptionFailed ...
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrChecksumMismatch ...
	ErrChecksumMismatch = errors.New("checksums do not match")

	// ErrNotASecret ...
	ErrNotASecret = errors.New("input is not a secret")
)
