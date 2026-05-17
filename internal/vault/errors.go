package vault

import "errors"

// Sentinel errors returned by port implementations. Callers compare with
// errors.Is rather than string-matching on Error().
var (
	ErrNotFound        = errors.New("vault: not found")
	ErrAlreadyExists   = errors.New("vault: already exists")
	ErrUnauthorized    = errors.New("vault: unauthorized")
	ErrInvalidArgument = errors.New("vault: invalid argument")
)
