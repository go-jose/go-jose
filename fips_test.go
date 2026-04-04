package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestFIPSRSAOAEPSHA1Rejected(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("FIPS mode not enabled")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	// Encrypt path
	encrypter, err := NewEncrypter(A256CBC_HS512, Recipient{
		Algorithm: RSA_OAEP,
		Key:       &priv.PublicKey,
	}, nil)
	if err != nil {
		t.Fatalf("NewEncrypter should succeed (error is at encrypt time): %v", err)
	}

	_, err = encrypter.Encrypt([]byte("test"))
	if err == nil {
		t.Fatal("expected error for RSA-OAEP encrypt with SHA-1 in FIPS mode")
	}
	if !strings.Contains(err.Error(), "FIPS") {
		t.Fatalf("expected FIPS error on encrypt, got: %v", err)
	}

	// Decrypt path — use a pre-built JWE with RSA-OAEP (SHA-1) and verify
	// that decryption fails without panicking. The FIPS error from the key
	// decryption is intentionally masked by ErrCryptoFailure (side-channel
	// protection), but the important thing is no panic from sha1.New().
	rsaOAEPJWE := "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAifQ.U946MVfIm4Dpk_86HrnIA-QXyiUu0LZ67PL93CMLmEtJemMNDqmRd9fXyenCIhAC7jPIV1aaqW7gS194xyrrnUpBoJBdbegiPqOfquy493Iq_GQ8OXnFxFibPNQ6rU0l8BwIfh28ei_VIF2jqN6bhxFURCVW7fG6n6zkCCuEyc7IcxWafSHjH2FNttREuVj-jS-4LYDZsFzSKbpqoYF6mHt8H3btNEZDTSmy_6v0fV1foNtUKNfWopCp-iE4hNh4EzJfDuU8eXLhDb03aoOockrUiUCh-E0tQx9su4rOv-mDEOHHAQK7swm5etxoa7__9PC3Hg97_p4GM9gC9ykNgw.pnXwvoSPi0kMQP54of-HGg.RPJt1CMWs1nyotx1fOIfZ8760mYQ69HlyDp3XmdVsZ8.Yxw2iPVWaBROFE_FGbvodA"
	parsed, err := ParseEncrypted(rsaOAEPJWE, []KeyAlgorithm{RSA_OAEP}, []ContentEncryption{A128CBC_HS256})
	if err != nil {
		t.Fatalf("ParseEncrypted failed: %v", err)
	}

	_, err = parsed.Decrypt(priv)
	if err == nil {
		t.Fatal("expected error for RSA-OAEP decrypt with SHA-1 in FIPS mode")
	}
}

func TestFIPSX5tSHA1Rejected(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("FIPS mode not enabled")
	}

	cert := generateTestCert(t)

	// Use a dummy 20-byte SHA-1-sized thumbprint (we can't call sha1.Sum in fips140=only mode)
	dummyThumbprint := make([]byte, 20)
	copy(dummyThumbprint, "12345678901234567890")

	// Marshal path: JWK with CertificateThumbprintSHA1 should be rejected
	jwk := JSONWebKey{
		Key:                       cert.PublicKey,
		Certificates:              []*x509.Certificate{cert},
		CertificateThumbprintSHA1: dummyThumbprint,
	}

	_, err := jwk.MarshalJSON()
	if err == nil {
		t.Fatal("expected error when marshaling JWK with x5t in FIPS mode")
	}
	if !strings.Contains(err.Error(), "FIPS") {
		t.Fatalf("expected FIPS error, got: %v", err)
	}

	// Unmarshal path: JWK JSON with x5t field should also be rejected
	jwkJSON := `{"kty":"RSA","x5t":"dGVzdHRodW1icHJpbnQxMjM0","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`
	var parsed JSONWebKey
	err = json.Unmarshal([]byte(jwkJSON), &parsed)
	if err == nil {
		t.Fatal("expected error when unmarshaling JWK with x5t in FIPS mode")
	}
	if !strings.Contains(err.Error(), "FIPS") {
		t.Fatalf("expected FIPS error, got: %v", err)
	}
}

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	return cert
}
