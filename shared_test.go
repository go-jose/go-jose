package jose

import (
	"reflect"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
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

// getJWK extracts parsed "jwk" from the raw JSON.
func (parsed rawHeader) getJWK() (*JSONWebKey, error) {
	v := parsed[headerJWK]
	if v == nil {
		return nil, nil
	}
	var jwk *JSONWebKey
	err := json.Unmarshal(*v, &jwk)
	if err != nil {
		return nil, err
	}
	return jwk, nil
}

func TestParseProtectedHeader(t *testing.T) {
	testCases := []struct {
		name    string
		in      *byteBuffer
		wantNil bool
		wantAlg string
		wantErr bool
	}{
		{name: "nil buffer", in: nil, wantNil: true},
		{name: "empty buffer", in: &byteBuffer{data: []byte{}}, wantNil: true},
		{name: "empty object", in: newBuffer([]byte(`{}`))},
		{name: "object", in: newBuffer([]byte(`{"alg":"HS256"}`)), wantAlg: "HS256"},
		{name: "object with whitespace", in: newBuffer([]byte(` {"alg":"HS256"} `)), wantAlg: "HS256"},
		{name: "null", in: newBuffer([]byte(`null`)), wantErr: true},
		{name: "null with whitespace", in: newBuffer([]byte(` null `)), wantErr: true},
		{name: "array", in: newBuffer([]byte(`[]`)), wantErr: true},
		{name: "number", in: newBuffer([]byte(`5`)), wantErr: true},
		{name: "string", in: newBuffer([]byte(`"s"`)), wantErr: true},
		{name: "bool", in: newBuffer([]byte(`true`)), wantErr: true},
		{name: "invalid JSON", in: newBuffer([]byte(`{`)), wantErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header, err := parseProtectedHeader(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got header %v", header)
				}
				if header != nil {
					t.Errorf("expected nil header on error, got %v", header)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantNil {
				if header != nil {
					t.Errorf("expected nil header, got %v", header)
				}
				return
			}
			if header == nil || *header == nil {
				t.Fatalf("expected non-nil header map, got %v", header)
			}
			if alg := string(header.getAlgorithm()); alg != tc.wantAlg {
				t.Errorf("expected alg %q, got %q", tc.wantAlg, alg)
			}
		})
	}
}
