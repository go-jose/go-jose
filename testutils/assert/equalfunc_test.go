package assert

import "testing"

type TestStruct1 struct {
	A string
	B int
}

func (ts1 TestStruct1) Equal(ts2 any) bool {
	return ts1.A == ts2.(TestStruct1).A && ts1.B == ts2.(TestStruct1).B
}

func TestEqualSliceFunc(t *testing.T) {
	m := &mockT{}
	if !EqualSliceFunc(m, []TestStruct1{{A: "test", B: 1}}, []TestStruct1{{A: "test", B: 1}}) {
		t.Fatalf("equal slice func not equal. Expected equal")
	}
}

func TestEqualFunc(t *testing.T) {
	m := &mockT{}
	if !EqualFunc(m, TestStruct1{A: "test", B: 1}, TestStruct1{A: "test", B: 1}) {
		t.Fatalf("equal slice func not equal. Expected equal")
	}
}
