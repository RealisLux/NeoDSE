// File purpose: Wraps the controller database key under an administrator passphrase in a keyslot file.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package storekey protects the random key that encrypts the controller
// database. The key exists in plaintext only in memory. On disk, a keyslot
// holds it sealed with AES-256-GCM under a key derived from the administrator
// passphrase with Argon2id, so changing the passphrase never re-encrypts the
// database. The passphrase itself is never stored.
package storekey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	// KeySize matches the AES-256-XTS key length used by the store.
	KeySize = 64
	// MinPassphraseBytes is the shortest passphrase accepted for a new keyslot.
	MinPassphraseBytes = 16
	// MaxPassphraseBytes bounds operator input and key-derivation work.
	MaxPassphraseBytes = 1024
	// MaxFileBytes bounds keyslot parsing.
	MaxFileBytes = 4096

	format     = "neodse-database-keyslot"
	version    = 1
	kdfName    = "argon2id"
	cipherName = "aes-256-xts"
	saltBytes  = 32
	kekBytes   = 32
)

var (
	// ErrIncorrectPassphrase reports a passphrase that does not open the keyslot.
	ErrIncorrectPassphrase = errors.New("incorrect passphrase or damaged keyslot")
	// ErrInvalidKeyslot reports keyslot contents that do not follow format version 1.
	ErrInvalidKeyslot = errors.New("invalid database keyslot")
)

// Params selects the Argon2id cost recorded in a keyslot.
type Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// DefaultParams is the second recommended Argon2id option of RFC 9106.
var DefaultParams = Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// valid bounds the cost an untrusted keyslot can request from the controller.
func (p Params) valid() bool {
	return p.Time >= 1 && p.Time <= 16 && p.MemoryKiB >= 1024 && p.MemoryKiB <= 1024*1024 && p.Threads >= 1 && p.Threads <= 16
}

// keyslot is the JSON form of format version 1.
type keyslot struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	Cipher     string `json:"cipher"`
	KDF        string `json:"kdf"`
	Time       uint32 `json:"time"`
	MemoryKiB  uint32 `json:"memory_kib"`
	Threads    uint8  `json:"threads"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	WrappedKey string `json:"wrapped_key"`
}

// Path returns the keyslot location for a database file.
func Path(database string) string {
	return database + ".keyslot"
}

// GenerateKey returns a new random database key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ValidatePassphrase applies the policy for passphrases chosen by an administrator.
func ValidatePassphrase(passphrase []byte) error {
	if len(passphrase) < MinPassphraseBytes || len(passphrase) > MaxPassphraseBytes {
		return fmt.Errorf("passphrase must be %d-%d bytes", MinPassphraseBytes, MaxPassphraseBytes)
	}
	if !utf8.Valid(passphrase) || bytes.ContainsAny(passphrase, "\x00\r\n") {
		return errors.New("passphrase must be valid UTF-8 without NUL or line breaks")
	}
	return nil
}

// Seal wraps key under passphrase with the default Argon2id cost.
func Seal(key, passphrase []byte) ([]byte, error) {
	return SealWith(key, passphrase, DefaultParams)
}

// SealWith wraps key under passphrase with an explicit Argon2id cost.
func SealWith(key, passphrase []byte, params Params) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("database key must be %d bytes", KeySize)
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return nil, err
	}
	if !params.valid() {
		return nil, errors.New("Argon2id parameters are outside supported bounds")
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := keyWrapper(passphrase, salt, params)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	wrapped := aead.Seal(nil, nonce, key, associatedData(params, salt))
	contents, err := json.MarshalIndent(keyslot{
		Format: format, Version: version, Cipher: cipherName, KDF: kdfName,
		Time: params.Time, MemoryKiB: params.MemoryKiB, Threads: params.Threads,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		WrappedKey: base64.StdEncoding.EncodeToString(wrapped),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(contents, '\n'), nil
}

// Unseal returns the database key when passphrase opens contents.
func Unseal(contents, passphrase []byte) ([]byte, error) {
	params, salt, nonce, wrapped, err := parse(contents)
	if err != nil {
		return nil, err
	}
	if len(passphrase) == 0 || len(passphrase) > MaxPassphraseBytes {
		return nil, ErrIncorrectPassphrase
	}
	aead, err := keyWrapper(passphrase, salt, params)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: nonce length", ErrInvalidKeyslot)
	}
	key, err := aead.Open(nil, nonce, wrapped, associatedData(params, salt))
	if err != nil {
		return nil, ErrIncorrectPassphrase
	}
	if len(key) != KeySize {
		clear(key)
		return nil, fmt.Errorf("%w: key length", ErrInvalidKeyslot)
	}
	return key, nil
}

// parse strictly decodes one bounded format version 1 keyslot.
func parse(contents []byte) (Params, []byte, []byte, []byte, error) {
	var slot keyslot
	if len(contents) > MaxFileBytes {
		return Params{}, nil, nil, nil, fmt.Errorf("%w: exceeds %d bytes", ErrInvalidKeyslot, MaxFileBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&slot); err != nil {
		return Params{}, nil, nil, nil, fmt.Errorf("%w: %v", ErrInvalidKeyslot, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Params{}, nil, nil, nil, fmt.Errorf("%w: trailing data", ErrInvalidKeyslot)
	}
	if slot.Format != format || slot.Version != version || slot.Cipher != cipherName || slot.KDF != kdfName {
		return Params{}, nil, nil, nil, fmt.Errorf("%w: unsupported format", ErrInvalidKeyslot)
	}
	params := Params{Time: slot.Time, MemoryKiB: slot.MemoryKiB, Threads: slot.Threads}
	if !params.valid() {
		return Params{}, nil, nil, nil, fmt.Errorf("%w: Argon2id parameters are outside supported bounds", ErrInvalidKeyslot)
	}
	salt, saltErr := base64.StdEncoding.Strict().DecodeString(slot.Salt)
	nonce, nonceErr := base64.StdEncoding.Strict().DecodeString(slot.Nonce)
	wrapped, wrappedErr := base64.StdEncoding.Strict().DecodeString(slot.WrappedKey)
	if saltErr != nil || nonceErr != nil || wrappedErr != nil || len(salt) != saltBytes {
		return Params{}, nil, nil, nil, fmt.Errorf("%w: encoding", ErrInvalidKeyslot)
	}
	return params, salt, nonce, wrapped, nil
}

// keyWrapper derives the key-encryption key and returns its AES-256-GCM AEAD.
func keyWrapper(passphrase, salt []byte, params Params) (cipher.AEAD, error) {
	kek := argon2.IDKey(passphrase, salt, params.Time, params.MemoryKiB, params.Threads, kekBytes)
	defer clear(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// associatedData binds the wrapped key to the format, cipher and key-derivation inputs.
func associatedData(params Params, salt []byte) []byte {
	data := []byte(format + "\x00" + cipherName + "\x00" + kdfName + "\x00")
	data = binary.BigEndian.AppendUint32(data, version)
	data = binary.BigEndian.AppendUint32(data, params.Time)
	data = binary.BigEndian.AppendUint32(data, params.MemoryKiB)
	data = append(data, params.Threads)
	return append(data, salt...)
}
