package crypt

import (
	"crypto/sha512"
)

func New_hash(text []byte) []byte {
	hash := sha512.Sum512(text)
	return hash[:]
}
