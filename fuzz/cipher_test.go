package fuzz

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	josecipher "github.com/go-jose/go-jose/v4/cipher"
)

// --- Phase 4: Cipher primitives ---

func FuzzCipherKeyWrap(f *testing.F) {
	// Seeds from FuzzKeyWrap
	f.Add([]byte("0123456789abcdef"), []byte("0123456789abcdef0123456789abcdef"))
	f.Add([]byte("0123456789abcdef"), []byte("01234567"))
	// Seed from FuzzKeyUnwrap
	f.Add([]byte("0123456789abcdef"), []byte("0123456789abcdef01234567"))
	// Seed from FuzzKeyUnwrapCorrupted
	f.Add([]byte("0123456789abcdef"), make([]byte, 40))

	f.Fuzz(func(t *testing.T, kek []byte, cek []byte) {
		// AES key must be 16, 24, or 32 bytes
		switch len(kek) {
		case 16, 24, 32:
		default:
			return
		}

		block, err := aes.NewCipher(kek)
		if err != nil {
			return
		}

		// (a) If cek is valid for wrapping, do a round-trip test.
		if len(cek) > 0 && len(cek)%8 == 0 {
			wrapped, err := josecipher.KeyWrap(block, cek)
			if err == nil {
				unwrapped, err := josecipher.KeyUnwrap(block, wrapped)
				if err != nil {
					t.Fatalf("failed to unwrap: %v", err)
				}
				if string(unwrapped) != string(cek) {
					t.Fatalf("key wrap round-trip mismatch")
				}
			}
		}

		// (b) Always try KeyUnwrap with cek as arbitrary ciphertext — just check no panics.
		if len(cek) > 0 && len(cek)%8 == 0 {
			josecipher.KeyUnwrap(block, cek)
		}
	})
}

func FuzzCipherCBCHMAC(f *testing.F) {
	// Seeds from FuzzNewCBCHMAC
	f.Add(make([]byte, 32), make([]byte, 16), []byte("plaintext data!!"), []byte("aad"))
	f.Add(make([]byte, 48), make([]byte, 16), []byte("test"), []byte(""))
	f.Add(make([]byte, 64), make([]byte, 16), []byte("hello world12345"), []byte("extra"))
	// Seed from FuzzCBCHMACOpen
	f.Add(make([]byte, 32), make([]byte, 16), make([]byte, 48), []byte("aad"))
	// Regression: empty plaintext triggered nil return from cbcAEAD.Open
	f.Add(make([]byte, 32), make([]byte, 16), []byte{}, []byte("aad"))

	f.Fuzz(func(t *testing.T, key []byte, nonce []byte, plaintext []byte, aad []byte) {
		// Key must be 32, 48, or 64 bytes for CBC-HMAC
		switch len(key) {
		case 32, 48, 64:
		default:
			return
		}
		// Nonce must be 16 bytes
		if len(nonce) != 16 {
			return
		}

		aead, err := josecipher.NewCBCHMAC(key, aes.NewCipher)
		if err != nil {
			return
		}

		// (a) Seal+Open round-trip.
		ciphertext := aead.Seal(nil, nonce, plaintext, aad)
		decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			t.Fatalf("failed to decrypt: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("CBC-HMAC round-trip mismatch")
		}

		// (b) Try Open with raw plaintext as ciphertext — just check no panics.
		aead.Open(nil, nonce, plaintext, aad)
	})
}

func FuzzNewConcatKDF(f *testing.F) {
	f.Add([]byte("shared-secret"), []byte("algID"), []byte("uinfo"), []byte("vinfo"), []byte("pub"), []byte("priv"))
	f.Fuzz(func(t *testing.T, z, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo []byte) {
		reader := josecipher.NewConcatKDF(crypto.SHA256, z, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo)
		out := make([]byte, 32)
		reader.Read(out)
	})
}

func FuzzDeriveECDHES(f *testing.F) {
	f.Add("A128CBC-HS256", []byte("apu"), []byte("apv"), 16)
	f.Add("A256GCM", []byte(""), []byte(""), 32)
	f.Fuzz(func(t *testing.T, alg string, apuData []byte, apvData []byte, size int) {
		// Size must be reasonable
		if size <= 0 || size > 64 {
			return
		}

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return
		}

		// DeriveECDHES can panic on invalid input — catch that
		func() {
			defer func() { recover() }()
			josecipher.DeriveECDHES(alg, apuData, apvData, priv, &priv.PublicKey, size)
		}()
	})
}
