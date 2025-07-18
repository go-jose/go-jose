package assert

import (
	"errors"
	"fmt"
	"testing"
)

type mockT struct {
	errors []string
	failed bool
}

func (m *mockT) Errorf(format string, args ...any) {
	m.errors = append(m.errors, fmt.Sprintf(format, args...))
	m.failed = true
}
func (m *mockT) Helper() {

}
func TestEqual(t *testing.T) {
	m := &mockT{}
	if !Equal(m, "one", "one") {
		t.Fatalf("expected equal")
	}
	m.failed = false
	m.errors = []string{}
	if Equal(m, "one", "two") {
		if !m.failed {
			t.Fatalf("test didn't fail. Expected test to have failed = true")
		}
	}
}

func TestEqualSlice(t *testing.T) {
	m := &mockT{}
	if !EqualSlice(m, []string{"one", "two"}, []string{"one", "two"}) {
		t.Fatalf("expected equal")
	}
	m.failed = false
	m.errors = []string{}
	if EqualSlice(m, []string{"one", "two"}, []string{"one", "three"}) {
		if !m.failed {
			t.Fatalf("test didn't fail. Expected test to have failed = true")
		}
	}
}

func TestJSON(t *testing.T) {
	m := &mockT{}
	if !EqualJSON(m, map[string]string{"one": "two"}, map[string]string{"one": "two"}) {
		t.Fatalf("expected equal")
	}
	m.failed = false
	m.errors = []string{}
	if EqualJSON(m, map[string]string{"one": "two"}, map[string]string{"one": "three"}) {
		if !m.failed {
			t.Fatalf("test didn't fail. Expected test to have failed = true")
		}
	}
	m.failed = false
	m.errors = []string{}
	if EqualJSON(m, map[string]string{"one": "two"}, map[string]string{"two": "three"}) {
		if !m.failed {
			t.Fatalf("test didn't fail. Expected test to have failed = true")
		}
	}
}

func TestNoError(t *testing.T) {
	m := &mockT{}
	if !NoError(m, nil) {
		t.Fatalf("expected no error")
	}
	m.failed = false
	m.errors = []string{}
	if NoError(m, errors.New("error")) {
		if !m.failed {
			t.Fatalf("test didn't fail. Expected test to have failed = true")
		}
	}
}

func TestError(t *testing.T) {
	m := &mockT{}
	if !Error(m, errors.New("error")) {
		t.Fatalf("expected error")
	}
	m.failed = false
	m.errors = []string{}
	if Error(m, nil) {
		if !m.failed {
			t.Fatalf("test didn't fail. Expected test to have failed = true")
		}
	}
}

func TestErrorIs(t *testing.T) {
	m := &mockT{}

	var ErrNotFound = errors.New("not found")
	if !ErrorIs(m, ErrNotFound, ErrNotFound) {
		t.Fatalf("expected error not found")
	}
	m.failed = false
	m.errors = []string{}
	if ErrorIs(m, errors.New("another error"), ErrNotFound) {
		if !m.failed {
			t.Fatalf("test didn't fail. Expected test to have failed = true")
		}
	}
}

func TestLen(t *testing.T) {
	m := &mockT{}

	if !Len(m, []int{1, 1, 1, 1}, 4) {
		t.Fatalf("expected len 4")
	}
	m.failed = false
	m.errors = []string{}
	if Len(m, []int{1, 1, 1, 1}, 5) {
		if !m.failed {
			t.Fatalf("test didn't fail. Expected test to have failed = true")
		}
	}
}

func TestGetMsgParameter(t *testing.T) {
	message := getMsgParameter("this is the %s", "message")
	expected := ". Message: this is the message"
	if message != expected {
		t.Fatalf("got %s, expected %s", message, expected)
	}
}
