package jose

import (
	"reflect"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
)

func TestMergeHeaders(t *testing.T) {
	var dst, src rawHeader
	err := json.Unmarshal([]byte(`{"empty":"","null":null,"zero":0,"false":false,"set":"dst"}`), &dst)
	if err != nil {
		t.Fatalf("unmarshaling dst: %s", err)
	}
	err = json.Unmarshal([]byte(`{"empty":"src","null":"src","zero":"src","false":"src","set":"src","new":"src"}`), &src)
	if err != nil {
		t.Fatalf("unmarshaling src: %s", err)
	}

	dst.merge(&src)

	for k, want := range map[HeaderKey]string{
		"empty": `""`,
		"null":  `null`,
		"zero":  `0`,
		"false": `false`,
		"set":   `"dst"`,
		"new":   `"src"`,
	} {
		v, ok := dst[k]
		if !ok {
			t.Errorf("merge() dropped %q, want %s", k, want)
			continue
		}
		// A JSON null is stored as a present key with a nil value.
		got := "null"
		if v != nil {
			got = string(*v)
		}
		if got != want {
			t.Errorf("merge() set %q to %s, want %s", k, got, want)
		}
	}
}

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
