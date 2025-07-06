package assert

type EqualCapability interface {
	Equal(any) bool
}

func EqualSliceFunc[T any](t TInterface, expected, actual []T) bool {
	t.Helper()
	if len(expected) != len(actual) {
		t.Errorf("slice are not of equal lengths")
	}
	for i := range actual {
		v1Typed, ok := any(actual[i]).(EqualCapability)
		if !ok {
			t.Errorf("actual value slice element doesn't contain Equal(any) function")
		}
		v2Typed, ok := any(expected[i]).(EqualCapability)
		if !ok {
			t.Errorf("expected value slice element doesn't contain Equal(any) function")
		}
		if !v2Typed.Equal(v1Typed) {
			t.Errorf("expected slice (%+v) is not equal to actual slice (%+v)", actual, expected)
		}
	}

	return true
}

func EqualFunc(t TInterface, expected, actual EqualCapability) bool {
	t.Helper()
	if !expected.Equal(actual) {
		t.Errorf("expected (%+v) is not equal to actual (%+v)", expected, actual)
	}
	return true
}
