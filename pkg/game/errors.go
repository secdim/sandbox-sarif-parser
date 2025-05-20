package game

import "errors"

var (
	ErrUnauthorized   = errors.New("unauthorized: invalid API key")
	ErrAlreadyExists  = errors.New("already exists")
	ErrNotFound       = errors.New("not found")
	ErrInvalidPayload = errors.New("invalid payload: missing required fields")
)
