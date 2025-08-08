package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

func GenerateEcdsaKey() (*ecdsa.PrivateKey, error) {
	// Generate a new ecdsa key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func HashPassword(password string) ([]byte, error) {
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hashedPassword, nil
}
