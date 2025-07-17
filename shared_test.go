package jose

import (
	"reflect"
	"testing"
)

func TestHeaderEqual(t *testing.T) {
	header1 := Header{
		KeyID:        "1-2-3-4",
		Algorithm:    "test",
		ExtraHeaders: map[HeaderKey]interface{}{"kid": "1-2-3-4"},
	}
	header2 := Header{
		KeyID:        "1-2-3-4",
		Algorithm:    "test",
		ExtraHeaders: map[HeaderKey]interface{}{"kid": "1-2-3-4"},
	}
	if !reflect.DeepEqual(header1, header2) {
		t.Fatalf("header1 and header2 are not equal, expected equal")
	}
}

func TestHeaderNotEqual(t *testing.T) {
	header1 := Header{
		KeyID:        "1-2-3-4",
		Algorithm:    "test",
		ExtraHeaders: map[HeaderKey]interface{}{"kid": "1-2-3-4"},
	}
	header2 := Header{
		KeyID:        "1-2-3-4",
		Algorithm:    "test",
		ExtraHeaders: map[HeaderKey]interface{}{"kid": "9-9-9-9"},
	}
	if reflect.DeepEqual(header1, header2) {
		t.Fatalf("header1 and header2 are equal, expected not equal")
	}
}
