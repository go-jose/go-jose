package assert

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

type TInterface interface {
	Errorf(format string, args ...any)
	Helper()
}

func Equal[T comparable](t TInterface, actual, expected T) bool {
	t.Helper()
	if expected != actual {
		t.Errorf("expected '%+v', but actual value is '%+v'", expected, actual)
		return false
	}
	return true
}

func EqualSlice[T comparable](t TInterface, actual, expected []T) bool {
	t.Helper()
	if !slices.Equal(expected, actual) {
		t.Errorf("expected slice (%+v) is not equal to actual slice (%+v)", expected, actual)
		return false
	}
	return true
}

func EqualJSON[K comparable, V comparable](t TInterface, actual, expected map[K]V) bool {
	t.Helper()
	if len(expected) != len(actual) {
		t.Errorf("length mismatch: expected %d, got %d", len(expected), len(actual))
		return false
	}

	for i := range expected {
		if _, ok := actual[i]; !ok {
			t.Errorf("expected map's keys (%+v) don't match actual map's keys (%+v)", expected, actual)
			return false
		}
		v1, err1 := json.Marshal(expected[i])
		v2, err2 := json.Marshal(actual[i])
		if err1 != nil || err2 != nil || !bytes.Equal(v1, v2) {
			t.Errorf("expected JSON output (%+v) is not equal to actual JSON output (%+v)", expected, actual)
			return false
		}
	}
	return true
}

func NoError(t TInterface, err error, errMsg ...any) bool {
	t.Helper()
	if err != nil {
		t.Errorf("expected no error. Got error: %s%s", err, getMsgParameter(errMsg))
		return false
	}
	return true
}

func Error(t TInterface, err error, errMsg ...any) bool {
	t.Helper()
	if err == nil {
		t.Errorf("expected an error, but got none%s", getMsgParameter(errMsg))
		return false
	}
	return true
}

func ErrorIs(t TInterface, actual, expected error) bool {
	t.Helper()
	if !errors.Is(actual, expected) {
		t.Errorf("expected error %s, got %s", expected, actual)
		return false
	}
	return true
}

func Len[T comparable](t TInterface, expected []T, length int) bool {
	t.Helper()
	if len(expected) != length {
		t.Errorf("expected length %d, got %d", length, len(expected))
		return false
	}
	return true
}

func getMsgParameter(errMsg ...any) string {
	if len(errMsg) > 0 {
		msg := errMsg[0]
		errMsgString, ok := msg.(string)
		if ok && len(errMsg) > 1 {
			return ". Message: " + fmt.Sprintf(errMsgString, errMsg[1:]...)
		} else {
			return ". Message: " + errMsgString
		}
	}
	return ""
}
