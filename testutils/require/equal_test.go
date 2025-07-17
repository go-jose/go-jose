package require

import (
	"errors"
	"fmt"
	"testing"
)

type mockT struct {
	errors  []string
	failed  bool
	failnow bool
}

func (m *mockT) Errorf(format string, args ...any) {
	m.errors = append(m.errors, fmt.Sprintf(format, args...))
	m.failed = true
}
func (m *mockT) Helper() {

}

func (m *mockT) FailNow() {
	m.failnow = true
}
func TestEqual(t *testing.T) {
	m := &mockT{}
	Equal(m, "one", "one")
	if m.failnow {
		t.Fatalf("expected equal")
	}
	m.failed = false
	m.failnow = false
	m.errors = []string{}
	Equal(m, "one", "two")
	if !m.failnow {
		t.Fatalf("test didn't fail. Expected test to have failnow = true")
	}
}

func TestNoError(t *testing.T) {
	m := &mockT{}
	NoError(m, nil)
	if m.failnow {
		t.Fatalf("expected no error")
	}
	m.failed = false
	m.failnow = false
	m.errors = []string{}
	NoError(m, errors.New("error"))
	if !m.failnow {
		t.Fatalf("test didn't fail. Expected test to have failnow = true")
	}
}
