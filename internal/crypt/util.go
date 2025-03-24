package crypt

import (
	"crypto/rand"
)

func Random_bytes(num_bytes int) ([]byte, error) {
	rand_bytes := make([]byte, num_bytes)
	_, err := rand.Read(rand_bytes)
	if err != nil {
		return nil, err
	}
	return rand_bytes, nil
}
