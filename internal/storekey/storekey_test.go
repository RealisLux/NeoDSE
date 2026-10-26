// File purpose: Verifies keyslot sealing, passphrase checks, tamper detection, and strict parsing.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package storekey

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"
)

// fastParams keeps tests quick; production keyslots use DefaultParams.
var fastParams = Params{Time: 1, MemoryKiB: 1024, Threads: 1}

// TestSealUnsealRoundTrip recovers the exact key and never stores the passphrase.
func TestSealUnsealRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("correct horse battery staple")
	sealed, err := SealWith(key, passphrase, fastParams)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, passphrase) || bytes.Contains(sealed, key) {
		t.Fatal("keyslot contains the passphrase or the plaintext key")
	}
	opened, err := Unseal(sealed, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, key) {
		t.Fatal("unsealed key differs")
	}
	again, err := SealWith(key, passphrase, fastParams)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(again, sealed) {
		t.Fatal("sealing twice produced identical keyslots; salt or nonce is not random")
	}
}

// TestDefaultParamsSeal keeps the production cost within the accepted bounds.
func TestDefaultParamsSeal(t *testing.T) {
	if testing.Short() {
		t.Skip("default Argon2id cost uses 64 MiB")
	}
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(key, []byte("a production length passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := Unseal(sealed, []byte("a production length passphrase")); err != nil || !bytes.Equal(opened, key) {
		t.Fatalf("default parameters: %v", err)
	}
}

// TestUnsealRejectsWrongPassphrase reports one error for every wrong input.
func TestUnsealRejectsWrongPassphrase(t *testing.T) {
	key, _ := GenerateKey()
	sealed, err := SealWith(key, []byte("correct horse battery staple"), fastParams)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []string{"", "correct horse battery stapl", "correct horse battery staple ", "Correct horse battery staple", strings.Repeat("x", MaxPassphraseBytes+1)} {
		if opened, err := Unseal(sealed, []byte(wrong)); !errors.Is(err, ErrIncorrectPassphrase) || opened != nil {
			t.Fatalf("passphrase %q: key=%v error=%v", wrong, opened != nil, err)
		}
	}
}

// TestUnsealDetectsTampering rejects modified authenticated fields.
func TestUnsealDetectsTampering(t *testing.T) {
	key, _ := GenerateKey()
	passphrase := []byte("correct horse battery staple")
	sealed, err := SealWith(key, passphrase, fastParams)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"time":        func(slot map[string]any) { slot["time"] = 2 },
		"memory":      func(slot map[string]any) { slot["memory_kib"] = 2048 },
		"threads":     func(slot map[string]any) { slot["threads"] = 2 },
		"salt":        func(slot map[string]any) { slot["salt"] = flipBase64(slot["salt"].(string)) },
		"nonce":       func(slot map[string]any) { slot["nonce"] = flipBase64(slot["nonce"].(string)) },
		"wrapped_key": func(slot map[string]any) { slot["wrapped_key"] = flipBase64(slot["wrapped_key"].(string)) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var slot map[string]any
			if err := json.Unmarshal(sealed, &slot); err != nil {
				t.Fatal(err)
			}
			mutate(slot)
			changed, err := json.Marshal(slot)
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := Unseal(changed, passphrase); err == nil || opened != nil {
				t.Fatal("tampered keyslot was accepted")
			}
		})
	}
}

// TestUnsealRejectsMalformedKeyslots enforces the strict format.
func TestUnsealRejectsMalformedKeyslots(t *testing.T) {
	key, _ := GenerateKey()
	passphrase := []byte("correct horse battery staple")
	sealed, err := SealWith(key, passphrase, fastParams)
	if err != nil {
		t.Fatal(err)
	}
	var valid map[string]any
	if err := json.Unmarshal(sealed, &valid); err != nil {
		t.Fatal(err)
	}
	variant := func(change func(map[string]any)) []byte {
		copied := make(map[string]any, len(valid))
		maps.Copy(copied, valid)
		change(copied)
		contents, err := json.Marshal(copied)
		if err != nil {
			t.Fatal(err)
		}
		return contents
	}
	cases := map[string][]byte{
		"empty":            nil,
		"not json":         []byte("not a keyslot"),
		"trailing":         append(bytes.Clone(sealed), []byte("{}")...),
		"oversized":        append(bytes.Clone(sealed), bytes.Repeat([]byte(" "), MaxFileBytes)...),
		"unknown field":    variant(func(slot map[string]any) { slot["extra"] = true }),
		"format":           variant(func(slot map[string]any) { slot["format"] = "other" }),
		"version":          variant(func(slot map[string]any) { slot["version"] = 2 }),
		"cipher":           variant(func(slot map[string]any) { slot["cipher"] = "aes-128-xts" }),
		"kdf":              variant(func(slot map[string]any) { slot["kdf"] = "pbkdf2" }),
		"excessive memory": variant(func(slot map[string]any) { slot["memory_kib"] = 2 * 1024 * 1024 }),
		"zero time":        variant(func(slot map[string]any) { slot["time"] = 0 }),
		"short salt":       variant(func(slot map[string]any) { slot["salt"] = "AAAA" }),
		"bad base64":       variant(func(slot map[string]any) { slot["wrapped_key"] = "***" }),
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			if opened, err := Unseal(contents, passphrase); !errors.Is(err, ErrInvalidKeyslot) || opened != nil {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// TestUnsealRejectsWrongNonceAndKeyLengths refuses authenticated slots that do not hold a database key.
func TestUnsealRejectsWrongNonceAndKeyLengths(t *testing.T) {
	passphrase := []byte("correct horse battery staple")
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	aead, err := keyWrapper(passphrase, salt, fastParams)
	if err != nil {
		t.Fatal(err)
	}
	craft := func(nonce, key []byte) []byte {
		contents, err := json.Marshal(keyslot{
			Format: format, Version: version, Cipher: cipherName, KDF: kdfName,
			Time: fastParams.Time, MemoryKiB: fastParams.MemoryKiB, Threads: fastParams.Threads,
			Salt:       base64.StdEncoding.EncodeToString(salt),
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			WrappedKey: base64.StdEncoding.EncodeToString(aead.Seal(nil, make([]byte, aead.NonceSize()), key, associatedData(fastParams, salt))),
		})
		if err != nil {
			t.Fatal(err)
		}
		return contents
	}
	if _, err := Unseal(craft(make([]byte, 8), make([]byte, KeySize)), passphrase); !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("short nonce error = %v", err)
	}
	if _, err := Unseal(craft(make([]byte, aead.NonceSize()), make([]byte, 32)), passphrase); !errors.Is(err, ErrInvalidKeyslot) {
		t.Fatalf("short sealed key error = %v", err)
	}
	if key, err := Unseal(craft(make([]byte, aead.NonceSize()), bytes.Repeat([]byte{7}, KeySize)), passphrase); err != nil || !bytes.Equal(key, bytes.Repeat([]byte{7}, KeySize)) {
		t.Fatalf("crafted valid keyslot: %v", err)
	}
}

// TestPassphrasePolicy enforces length and character rules for new passphrases.
func TestPassphrasePolicy(t *testing.T) {
	for passphrase, valid := range map[string]bool{
		strings.Repeat("a", MinPassphraseBytes-1): false,
		strings.Repeat("a", MinPassphraseBytes):   true,
		strings.Repeat("a", MaxPassphraseBytes):   true,
		strings.Repeat("a", MaxPassphraseBytes+1): false,
		"sixteen bytes ok but\x00nul":             false,
		"sixteen bytes ok but\nnewline":           false,
		"sixteen bytes ok but\rreturn":            false,
		"invalid utf-8 sequence \xff\xfe":         false,
		"unicode passphrase äöü ✓ works":          true,
	} {
		if err := ValidatePassphrase([]byte(passphrase)); (err == nil) != valid {
			t.Fatalf("passphrase %q valid=%t error=%v", passphrase, valid, err)
		}
	}
	key, _ := GenerateKey()
	if _, err := SealWith(key, []byte("too short"), fastParams); err == nil {
		t.Fatal("short passphrase was sealed")
	}
	if _, err := SealWith(key[:32], []byte("correct horse battery staple"), fastParams); err == nil {
		t.Fatal("short key was sealed")
	}
	if _, err := SealWith(key, []byte("correct horse battery staple"), Params{Time: 1, MemoryKiB: 8, Threads: 1}); err == nil {
		t.Fatal("parameters below the supported bounds were sealed")
	}
}

// TestPath derives the keyslot next to its database.
func TestPath(t *testing.T) {
	if got := Path("/var/lib/neodse/controller.db"); got != "/var/lib/neodse/controller.db.keyslot" {
		t.Fatalf("Path = %q", got)
	}
}

// flipBase64 changes the first encoded character to a different valid one.
func flipBase64(value string) string {
	if value[0] == 'A' {
		return "B" + value[1:]
	}
	return "A" + value[1:]
}
