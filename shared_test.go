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

func TestCheckSupportedCriticalRequiresListedParam(t *testing.T) {
	supported := map[string]struct{}{headerB64: {}}

	missing := rawHeader{}
	if err := missing.set(headerCritical, []string{headerB64}); err != nil {
		t.Fatal(err)
	}
	if err := missing.checkSupportedCritical(supported); err == nil {
		t.Error("checkSupportedCritical accepted crit listing b64 without b64 in the same header")
	}

	present := rawHeader{}
	if err := present.set(headerCritical, []string{headerB64}); err != nil {
		t.Fatal(err)
	}
	if err := present.set(headerB64, false); err != nil {
		t.Fatal(err)
	}
	if err := present.checkSupportedCritical(supported); err != nil {
		t.Errorf("checkSupportedCritical rejected protected b64: %v", err)
	}

	unknown := rawHeader{}
	if err := unknown.set(headerCritical, []string{"unknown-critical-header"}); err != nil {
		t.Fatal(err)
	}
	if err := unknown.checkSupportedCritical(supported); err == nil {
		t.Error("checkSupportedCritical accepted unknown crit header")
	}

	empty := rawHeader{}
	if err := empty.checkSupportedCritical(supported); err != nil {
		t.Errorf("checkSupportedCritical rejected header without crit: %v", err)
	}
}
