package jwt

import (
	"testing"

	"github.com/go-jose/go-jose/v4/testutils/assert"
)

// TestErrIssuedInTheFutureMessage pins the exact text of ErrIssuedInTheFuture.
// Issue #301: the message read "validation field" instead of "validation
// failed", unlike every other validation error in this file.
func TestErrIssuedInTheFutureMessage(t *testing.T) {
	assert.Equal(t,
		ErrIssuedInTheFuture.Error(),
		"go-jose/go-jose/jwt: validation failed, token issued in the future (iat)")
}
