package fuzz

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
)

var allKeyAlgorithms = []jose.KeyAlgorithm{
	jose.ED25519, jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256,
	jose.A128KW, jose.A192KW, jose.A256KW,
	jose.DIRECT,
	jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW,
	jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW,
	jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW,
}

var allContentEncryption = []jose.ContentEncryption{
	jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512,
	jose.A128GCM, jose.A192GCM, jose.A256GCM,
}

// FuzzJWEParse checks we don't panic on parsing or re-serializing the encrypted message
func FuzzJWEParse(f *testing.F) {
	f.Add("!.AAAA.AAAA.AAAA.AAAA")
	f.Add("")
	f.Add("a.b.c.d")
	f.Add("a.b.c.d.e")
	f.Add("a.b.c.d.e.f")
	f.Add("ew.AAAA.AAAA.AAAA.AAAA")
	f.Add("eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJNVTJodVMyT3pJTUtsZF9pIiwidGFnIjoiY0xldlJJWnBRZHNKOHhkWko3enZrQSJ9.nmE8ERep_vWBriJ6qSsQdg.mRkpRQqWe6p-1bhN.bK2_SYmDMW7pp8Ga.2FPfqdjx_0CzpXwav0_vuQ")
	f.Add("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.Eps_c7uZasil9gZnciCjghyrPw8-MpwI.4qU2Cs19yC-nk7fi.JfK4R56uvqSzyha5.NqSNgOaASNbssJTQpnONyg")
	f.Add("eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI3YmszNmZJbWFWNHUzd2xvX0VGdFg0VjdYMHVBRktsek5nMVVuUm9sX2trIiwieSI6IlZfZTZ6NUZ0ZU9DMWJNWEZna0JVVDY3OVZoTlVrM19ya1VPUzVSWGNyNGcifX0.vZq09Z0umzpbZgGHUwwg83p5-BcWE7ni.aoAzFuDn3iUwHcZM.JlEuQkQE6cigUmRq.QLNSeLUHf1cAjSTQHrlW1w")
	f.Add("eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjo2MDAwMDAsInAycyI6IkFQZVRwQWZhbkxsVGZRWWFLeUtmUmcifQ.7aoD6-rt1_aUsTMM8HHoCu00P925ocIL.OfA9ZInu_G29_kyq.rdtQDpMQO0iihYT0.YdU_rRKKuwB8VgHU55tA3Q")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.!.AAAA.AAAA.AAAA")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..rWNEu0YwIsFi9PQP.ZKHze6GbWYT5n2sz.FH1WdggmHH2wNlTJm_VqWA")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.AAAA.!.AAAA.AAAA")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.AAAA.AAAA.!.AAAA")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.AAAA.AAAA.AAAA.!")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJmb28ifQ.AAAA.AAAA.AAAA.AAAA")
	f.Add("eyJhbGciOiJkaXIifQ.AAAA.AAAA.AAAA.AAAA")
	f.Add("eyJhbGciOiJmb28iLCJlbmMiOiJBMTI4R0NNIn0.AAAA.AAAA.AAAA.AAAA")
	f.Add("eyJhbGciOjV9.AAAA.AAAA.AAAA.AAAA")
	f.Add("eyJlbmMiOiJBMTI4R0NNIn0.AAAA.AAAA.AAAA.AAAA")
	f.Add(`{"protected":"","unprotected":{"alg":"dir","enc":"A128GCM"},"iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"}`)
	f.Add(`{"protected":"ew","iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0","aad":"YWFk","encrypted_key":"QZIspcjFNtm-JoyVuo7cbtRnDJv7wFmr","iv":"4xd5_8wQ_LPEMHrk","ciphertext":"gBrNCE5jlxkaGHTx","tag":"ZQPt3fS38Vhx1FRROVaf-w"}`)
	f.Add(`{"protected":"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"K7uWnEr4gkH8uS96s9yXCTZCvaiiubcc","iv":"Ft69CRF8monVyiLi","ciphertext":"DLOBj1u8M9kRqKOw","tag":"Xphp3uWGmGjo2VUTvybTnw"}`)
	f.Add(`{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0","header":{"nonce":"abc"},"ciphertext":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0","recipients":[{"encrypted_key":"!"}],"ciphertext":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0","recipients":[{"header":{"nonce":"abc"}}],"ciphertext":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0","unprotected":{"alg":"foo"},"ciphertext":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0","unprotected":{"enc":"foo"},"ciphertext":"AAAA"}`)
	f.Add(`{"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0","unprotected":{"nonce":"abc"},"ciphertext":"AAAA"}`)
	f.Add(`{"protected":"eyJlbmMiOiJBMTI4R0NNIn0","recipients":[{"header":{"alg":"A128KW","kid":"k1"},"encrypted_key":"3RXnhmDBfv7xMn40wCK5yXXTSuMd86Et"},{"header":{"alg":"A256KW","kid":"k2"},"encrypted_key":"6TudHEUBsv4iUVoOtc-yFgXzmrsk_hYi"}],"encrypted_key":"3RXnhmDBfv7xMn40wCK5yXXTSuMd86Et","iv":"F1ozP8AjFpjCbDpR","ciphertext":"FEzQQI3xXqk6ohGP","tag":"w2tmzZozFZ3lgC9PjQOrKw"}`)
	f.Add(`{"protected":"eyJlbmMiOiJBMTI4R0NNIn0","recipients":[{"header":{"alg":"foo"}}],"ciphertext":"AAAA"}`)
	f.Add(`{"protected":"eyJlbmMiOiJBMTI4R0NNIn0","recipients":[{"header":{"kid":"k1"}}],"ciphertext":"AAAA"}`)
	f.Add(`{"protected":5,"iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"}`)
	f.Add(`{"protected":`)
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, data string) {
		enc, err := jose.ParseEncrypted(data, allKeyAlgorithms, allContentEncryption)
		if err == nil {
			enc.FullSerialize()
			_, _ = enc.CompactSerialize()
			_ = enc.GetAuthData()
		}
		enc, err = jose.ParseEncryptedCompact(data, allKeyAlgorithms, allContentEncryption)
		if err == nil {
			enc.FullSerialize()
			_, _ = enc.CompactSerialize()
		}
		enc, err = jose.ParseEncryptedJSON(data, allKeyAlgorithms, allContentEncryption)
		if err == nil {
			enc.FullSerialize()
			_, _ = enc.CompactSerialize()
		}
	})
}
