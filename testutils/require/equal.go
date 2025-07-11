package require

import (
	"github.com/go-jose/go-jose/v4/testutils/assert"
)

type TInterface interface {
	Errorf(format string, args ...any)
	Helper()
	FailNow()
}

func NoError(t TInterface, err error, errMsg ...any) {
	t.Helper()
	if !assert.NoError(t, err, errMsg...) {
		t.FailNow()
	}
}

func Equal[T comparable](t TInterface, actual, expected T) {
	t.Helper()
	if !assert.Equal(t, actual, expected) {
		t.FailNow()
	}
}
