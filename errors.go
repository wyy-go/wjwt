package wjwt

import (
	"errors"
)

var (
	// ErrMissingToken can be thrown by follow
	// if authing with a HTTP header, the Auth header needs to be set
	// if authing with URL Query, the query token variable is empty
	// if authing with a cookie, the token cookie is empty
	// if authing with parameter in path, the parameter in path is empty
	ErrMissingToken = errors.New("auth token is empty")
	// ErrInvalidAuthHeader indicates auth header is invalid
	ErrInvalidAuthHeader = errors.New("auth header is invalid")
	// ErrInvalidToken indicates token is invalid
	ErrInvalidToken = errors.New("token is invalid")
	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired")
	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid,
	// needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")
	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")
	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")
	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrMissingIdentity indicates Identity is required
	ErrMissingIdentity = errors.New("identity is required")
)
