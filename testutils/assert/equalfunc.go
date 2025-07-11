package assert

type EqualCapability[T any] interface {
	Equal(T) bool
}

func EqualSliceFunc[T EqualCapability[T]](t TInterface, expected, actual []T) bool {
	t.Helper()
	if len(expected) != len(actual) {
		t.Errorf("slices are not of equal length")
		return false
	}
	for i := range actual {
		if !expected[i].Equal(actual[i]) {
			t.Errorf("expected slice (%+v) is not equal to actual slice (%+v)", expected, actual)
			return false
		}
	}

	return true
}

func EqualFunc[T EqualCapability[T]](t TInterface, expected, actual T) bool {
	t.Helper()
	if !expected.Equal(actual) {
		t.Errorf("expected (%+v) is not equal to actual (%+v)", expected, actual)
		return false
	}
	return true
}
