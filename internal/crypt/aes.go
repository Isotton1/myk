package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"errors"
)
// TODO:
// 	 - Revise 

// Encrypt the key (plaintext) with the master (aes key) and return the byte string of 
// IV + ciphertext (one may argue that the IV or nouce is part of the ciphertext, so for the this
// function the IV is not part of the ciphertext but appended to it).
func Encrypt(key, master []byte) ([]byte, error) {
	key32bytes := sha512.Sum512_256(master) //The keys need to be 32 bytes, so in order to allow any key size for users I hash the master key.

	block, err := aes.NewCipher(key32bytes[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	IV, err := Random_bytes(aesGCM.NonceSize())
	if err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(IV, IV, key, nil)
	return ciphertext, nil
}

// Decrypt the ciphertext with master and return the password/plaintext.
func Decrypt(ciphertext, master []byte) ([]byte, error) {
	key32bytes := sha512.Sum512_256(master)

	block, err := aes.NewCipher(key32bytes[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce_size := aesGCM.NonceSize()
	if len(ciphertext) < nonce_size {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encryptedText := ciphertext[:nonce_size], ciphertext[nonce_size:]
	plaintext, err := aesGCM.Open(nil, nonce, encryptedText, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}


