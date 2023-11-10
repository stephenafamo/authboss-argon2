package authbossargon2

import (
	"errors"

	"github.com/alexedwards/argon2id"
)

var ErrMismatchedHashAndPassword = errors.New("hashedPassword is not the hash of the given password")

// NewArgon2Hasher returns a hasher that uses the argon2id hashing algorithm.
// It is compatible with the `authboss.Hasher` interface
func New(params *argon2id.Params) *argon2Hasher {
	if params == nil {
		params = argon2id.DefaultParams
	}
	return &argon2Hasher{params: *params}
}

type argon2Hasher struct {
	params argon2id.Params
}

func (h argon2Hasher) GenerateHash(password string) (string, error) {
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

func (h *argon2Hasher) CompareHashAndPassword(hashedPassword, password string) error {
	matched, err := argon2id.ComparePasswordAndHash(password, hashedPassword)
	if err != nil {
		return err
	}
	if !matched {
		return ErrMismatchedHashAndPassword
	}

	return nil
}
