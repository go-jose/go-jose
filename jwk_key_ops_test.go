package jose

import (
	"bytes"
	"crypto"
	"encoding/json"
	"reflect"
	"testing"
)

// keyOpsTestKeys returns one private and one public key of every supported
// asymmetric key type, plus a symmetric key.
func keyOpsTestKeys() []interface{} {
	return []interface{}{
		rsaTestKey,
		rsaTestKey.Public(),
		ecTestKey256,
		ecTestKey256.Public(),
		ecTestKey384,
		ecTestKey384.Public(),
		ecTestKey521,
		ecTestKey521.Public(),
		ed25519PrivateKey,
		ed25519PrivateKey.Public(),
		[]byte{1, 2, 3, 4},
	}
}

// injectKeyOps re-marshals data with a key_ops member of the given value,
// whatever its member order was. The result is only used as input to
// UnmarshalJSON, so map-based member ordering is harmless.
func injectKeyOps(t *testing.T, data []byte, ops interface{}) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to parse JWK JSON: %v", err)
	}
	injected, err := json.Marshal(ops)
	if err != nil {
		t.Fatalf("failed to marshal key_ops value: %v", err)
	}
	m["key_ops"] = injected
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to re-marshal JWK JSON: %v", err)
	}
	return out
}

// jsonEquivalent reports whether two JWK JSON documents carry the same
// members with the same values, ignoring member order.
func jsonEquivalent(t *testing.T, a, b []byte) bool {
	t.Helper()
	var ma, mb map[string]json.RawMessage
	if err := json.Unmarshal(a, &ma); err != nil {
		t.Fatalf("failed to parse first JWK JSON: %v", err)
	}
	if err := json.Unmarshal(b, &mb); err != nil {
		t.Fatalf("failed to parse second JWK JSON: %v", err)
	}
	return reflect.DeepEqual(ma, mb)
}

// hasKeyOpsMember reports whether the JSON document contains a key_ops
// member at all.
func hasKeyOpsMember(t *testing.T, data []byte) bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to parse JWK JSON: %v", err)
	}
	_, ok := m["key_ops"]
	return ok
}

// TestKeyOpsRoundTripPreservesValues pins that a populated key_ops member
// survives a JSON round trip verbatim: same values, same order, unknown
// operation names and duplicates included (RFC 7517 forbids duplicates, but
// preserving input does not imply endorsing it).
func TestKeyOpsRoundTripPreservesValues(t *testing.T) {
	ops := []string{"sign", "custom-extension-op", "sign", "encrypt"}
	for _, key := range keyOpsTestKeys() {
		name := reflect.TypeOf(key).String()
		t.Run(name, func(t *testing.T) {
			jwk1 := JSONWebKey{Key: key}
			b1, err := jwk1.MarshalJSON()
			if err != nil {
				t.Fatalf("failed to marshal JWK: %v", err)
			}
			injected := injectKeyOps(t, b1, ops)

			var jwk2 JSONWebKey
			if err := jwk2.UnmarshalJSON(injected); err != nil {
				t.Fatalf("failed to unmarshal JWK with key_ops: %v", err)
			}
			if jwk2.KeyOps == nil {
				t.Fatal("key_ops was dropped on unmarshal")
			}
			if !reflect.DeepEqual(jwk2.KeyOps, ops) {
				t.Errorf("key_ops values or order changed: got %#v, want %#v", jwk2.KeyOps, ops)
			}

			b2, err := jwk2.MarshalJSON()
			if err != nil {
				t.Fatalf("failed to re-marshal JWK: %v", err)
			}
			if !jsonEquivalent(t, injected, b2) {
				t.Errorf("key_ops was not preserved by the round trip:\n got: %s\nwant: %s", b2, injected)
			}
		})
	}
}

// TestKeyOpsRoundTripAcrossPublicAndPrivate pins the round trip through the
// exported struct field for both public and private keys of every type,
// including the metadata a caller sets programmatically.
func TestKeyOpsRoundTripAcrossPublicAndPrivate(t *testing.T) {
	ops := []string{"verify", "encrypt"}
	for _, key := range keyOpsTestKeys() {
		name := reflect.TypeOf(key).String()
		t.Run(name, func(t *testing.T) {
			jwk1 := JSONWebKey{Key: key, KeyOps: ops, KeyID: "kid-1"}
			b1, err := jwk1.MarshalJSON()
			if err != nil {
				t.Fatalf("failed to marshal JWK: %v", err)
			}
			if !hasKeyOpsMember(t, b1) {
				t.Fatalf("marshaled JWK lost the key_ops member: %s", b1)
			}

			var jwk2 JSONWebKey
			if err := jwk2.UnmarshalJSON(b1); err != nil {
				t.Fatalf("failed to unmarshal JWK: %v", err)
			}
			if !reflect.DeepEqual(jwk2.KeyOps, ops) {
				t.Errorf("key_ops did not round-trip: got %#v, want %#v", jwk2.KeyOps, ops)
			}
		})
	}
}

// TestKeyOpsAbsentStaysAbsent pins that a JWK without a key_ops member keeps
// it absent after a round trip.
func TestKeyOpsAbsentStaysAbsent(t *testing.T) {
	for _, key := range keyOpsTestKeys() {
		name := reflect.TypeOf(key).String()
		t.Run(name, func(t *testing.T) {
			jwk1 := JSONWebKey{Key: key}
			b1, err := jwk1.MarshalJSON()
			if err != nil {
				t.Fatalf("failed to marshal JWK: %v", err)
			}
			if hasKeyOpsMember(t, b1) {
				t.Errorf("marshal invented a key_ops member: %s", b1)
			}

			var jwk2 JSONWebKey
			if err := jwk2.UnmarshalJSON(b1); err != nil {
				t.Fatalf("failed to unmarshal JWK: %v", err)
			}
			if jwk2.KeyOps != nil {
				t.Errorf("absent key_ops should stay nil, got %#v", jwk2.KeyOps)
			}
			b2, err := jwk2.MarshalJSON()
			if err != nil {
				t.Fatalf("failed to re-marshal JWK: %v", err)
			}
			if hasKeyOpsMember(t, b2) {
				t.Errorf("re-marshal invented a key_ops member: %s", b2)
			}
		})
	}
}

// TestKeyOpsExplicitEmptySurvives pins that an explicit empty key_ops array
// is distinct from an absent member and survives a round trip as [].
func TestKeyOpsExplicitEmptySurvives(t *testing.T) {
	jwk1 := JSONWebKey{Key: []byte{1, 2, 3, 4}}
	b1, err := jwk1.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}
	injected := injectKeyOps(t, b1, []string{})

	var jwk2 JSONWebKey
	if err := jwk2.UnmarshalJSON(injected); err != nil {
		t.Fatalf("failed to unmarshal JWK: %v", err)
	}
	if jwk2.KeyOps == nil {
		t.Fatal("explicit empty key_ops should unmarshal to a non-nil empty slice")
	}
	if len(jwk2.KeyOps) != 0 {
		t.Errorf("explicit empty key_ops should be empty, got %#v", jwk2.KeyOps)
	}

	b2, err := jwk2.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to re-marshal JWK: %v", err)
	}
	if !hasKeyOpsMember(t, b2) {
		t.Fatalf("explicit empty key_ops was dropped on re-marshal: %s", b2)
	}
	if !jsonEquivalent(t, injected, b2) {
		t.Errorf("explicit empty key_ops did not survive the round trip:\n got: %s\nwant: %s", b2, injected)
	}

	// The programmatic form behaves the same way.
	jwk3 := JSONWebKey{Key: []byte{1, 2, 3, 4}, KeyOps: []string{}}
	b3, err := jwk3.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}
	if !hasKeyOpsMember(t, b3) {
		t.Errorf("non-nil empty KeyOps should marshal as an empty array: %s", b3)
	}
}

// TestKeyOpsNullTreatedAsAbsent pins that a JSON null key_ops member is
// indistinguishable from an absent member.
func TestKeyOpsNullTreatedAsAbsent(t *testing.T) {
	jwk1 := JSONWebKey{Key: []byte{1, 2, 3, 4}}
	b1, err := jwk1.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}
	injected := injectKeyOps(t, b1, nil)

	var jwk2 JSONWebKey
	if err := jwk2.UnmarshalJSON(injected); err != nil {
		t.Fatalf("failed to unmarshal JWK: %v", err)
	}
	if jwk2.KeyOps != nil {
		t.Errorf("null key_ops should unmarshal to nil, got %#v", jwk2.KeyOps)
	}
	b2, err := jwk2.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to re-marshal JWK: %v", err)
	}
	if hasKeyOpsMember(t, b2) {
		t.Errorf("null key_ops should re-marshal as absent: %s", b2)
	}
}

// TestKeyOpsPreservedOnPublicKey pins that Public() keeps the key_ops of an
// already public key unchanged.
func TestKeyOpsPreservedOnPublicKey(t *testing.T) {
	ops := []string{"verify"}
	jwk := JSONWebKey{Key: rsaTestKey.Public(), KeyOps: ops, Algorithm: "RS256"}
	pub := jwk.Public()
	if !reflect.DeepEqual(pub.KeyOps, ops) {
		t.Errorf("Public() dropped key_ops of a public key: got %#v, want %#v", pub.KeyOps, ops)
	}
}

// TestKeyOpsDroppedOnPrivateToPublicConversion pins the documented Public()
// behavior for private keys: the converted public key carries no key_ops,
// because no implicit mapping from private to public operations exists.
func TestKeyOpsDroppedOnPrivateToPublicConversion(t *testing.T) {
	for _, priv := range []interface{}{rsaTestKey, ecTestKey256, ed25519PrivateKey} {
		name := reflect.TypeOf(priv).String()
		t.Run(name, func(t *testing.T) {
			jwk := JSONWebKey{Key: priv, KeyOps: []string{"sign"}, Use: "sig", Algorithm: "alg-1", KeyID: "kid-9"}
			pub := jwk.Public()
			if pub.KeyOps != nil {
				t.Errorf("Public() should drop key_ops on private conversion, got %#v", pub.KeyOps)
			}
			if !pub.IsPublic() {
				t.Error("Public() did not return a public key")
			}
			// Key-unrelated metadata must keep round-tripping as before.
			if pub.Use != "sig" || pub.Algorithm != "alg-1" || pub.KeyID != "kid-9" {
				t.Errorf("Public() lost unrelated metadata: use=%q alg=%q kid=%q", pub.Use, pub.Algorithm, pub.KeyID)
			}
		})
	}
}

// TestThumbprintIgnoresKeyOps pins RFC 7638: the thumbprint is computed from
// the required key members only, so key_ops never changes it.
func TestThumbprintIgnoresKeyOps(t *testing.T) {
	// Symmetric keys have no thumbprint support at all (Thumbprint returns
	// an error for them), so the invariant is pinned on asymmetric keys.
	asymmetric := []interface{}{
		rsaTestKey,
		rsaTestKey.Public(),
		ecTestKey256,
		ecTestKey256.Public(),
		ed25519PrivateKey,
		ed25519PrivateKey.Public(),
	}
	for _, key := range asymmetric {
		name := reflect.TypeOf(key).String()
		t.Run(name, func(t *testing.T) {
			without := JSONWebKey{Key: key}
			with := JSONWebKey{Key: key, KeyOps: []string{"sign", "verify"}}
			tp1, err := without.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatalf("thumbprint failed: %v", err)
			}
			tp2, err := with.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatalf("thumbprint failed: %v", err)
			}
			if !bytes.Equal(tp1, tp2) {
				t.Error("key_ops changed the JWK thumbprint")
			}
		})
	}
}
