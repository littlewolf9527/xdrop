// Package secret seals node credentials with a file-backed master key.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strings"
)

type Key struct{ aead cipher.AEAD }

func aad(name string) []byte { return []byte(name) }

var errKey = errors.New("invalid secret_key_file: require 0600 and base64 encoding of 32 bytes")

func Load(path string) (*Key, error) {
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		return nil, errKey
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errKey
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != 32 {
		return nil, errKey
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, errKey
	}
	aead, err := cipher.NewGCM(block)
	return &Key{aead}, err
}

func Init(path string) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return errors.New("cannot generate secret_key_file")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create secret_key_file (refusing overwrite)")
	}
	defer f.Close()
	if err = f.Chmod(0600); err == nil {
		_, err = f.WriteString(base64.StdEncoding.EncodeToString(raw) + "\n")
	}
	if err != nil {
		return errors.New("cannot write secret_key_file")
	}
	return nil
}

func (k *Key) Seal(name, plain string) ([]byte, []byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, errors.New("cannot seal node key")
	}
	return nonce, k.aead.Seal(nil, nonce, []byte(plain), aad(name)), nil
}

func (k *Key) Open(name string, nonce, sealed []byte) (string, error) {
	if k == nil || len(nonce) != k.aead.NonceSize() {
		return "", errors.New("node key unreadable")
	}
	plain, err := k.aead.Open(nil, nonce, sealed, aad(name))
	if err != nil {
		return "", errors.New("node key unreadable")
	}
	return string(plain), nil
}
