package fuzz

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// jwtKeyAlgorithms is the subset of key algorithms permitted for JWT encryption.
// jwt.ParseEncrypted rejects asymmetric and password-based algorithms outright
// (validateKeyEncryptionAlgorithm), so passing those would fail before parsing.
var jwtKeyAlgorithms = []jose.KeyAlgorithm{
	jose.A128KW, jose.A192KW, jose.A256KW,
	jose.DIRECT,
	jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW,
}

// FuzzJWTParseSigned checks we don't panic on parsing a signed JWT, reading its
// claims without verification, and validating them.
func FuzzJWTParseSigned(f *testing.F) {
	f.Add("")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJIUzI1NiJ9.bm90IGpzb24.YFDw-TWFHzWWH_QL25-v85VbvbEZXcoXhtIDGlcv3fI")
	f.Add("eyJhbGciOiJIUzI1NiJ9.ew.1rjFi-RPDZ_J7nYS1BRMPygqItGEy3ipuPmDP5NZxqM")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJzaW5nbGUifQ.sYQdoyypGSN4VV8uQNhGM45jUvHC97_JCs-92ejOTcI")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOjV9._yuZVyYdDnRAAEi3cjjkzMl277ky_qVucDuJRv9JqeY")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiYSIsImIiXX0.q7DOZqZTldnyEwwOn51au0hKXhqEOGr90jmu8KXxXxo")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiYSIsNV19.PiR9BxMfJttpFN6467_kIdPPETCeVh2Yg7xFknGm8Ck")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiZXhwIjoyMDAwMDAwMDAwLCJpYXQiOjEwMDAwMDAwMDAsImlzcyI6Imlzc3VlciIsImp0aSI6ImlkIiwibmJmIjoxMDAwMDAwMDAwLCJzdWIiOiJzdWJqZWN0In0.mtKneR2QLqqpxZp62CWgoARW5IZZ-6oJEI4SlrWdtyk")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOltdfQ.TG25vfgxyv6M3BTxIb5nN6xuNt9hjc02NYyLZrR2V6M")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOi0xfQ.b-wfRTDWpxIJlTZ6HhqixoEVjpOwbXH9X06A5P_EXTk")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOiJub3RhbnVtYmVyIn0.kouStcxIDI_0iZKh5BGtIKcPmQruOSLqEPGtKvrVOFg")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjFlMTB9.32Uk1ulghgLYrtage12J7qQmrFzCAIeR_m35oBxOnkk")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjkyMjMzNzIwMzY4NTQ3NzU4MDd9.z-hjKKWLsbISH5EWCuztWkHCW3UBYeoNci5C-6XAr2k")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ4Iiwic3ViIjoieSIsImp0aSI6InoiLCJpYXQiOjB9.yBlI7FGd0xTq1X_Frn0W8gXDFs50y5CeQSK3YLB2jXc")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJuYmYiOjEuNX0.YeoIxC8dJCa_Pw1HUTFXxM_kAbSafOqQskOd0B55D34")
	f.Add("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiZXhwIjoyMDAwMDAwMDAwLCJpYXQiOjEwMDAwMDAwMDAsImlzcyI6Imlzc3VlciIsImp0aSI6ImlkIiwibmJmIjoxMDAwMDAwMDAwLCJzdWIiOiJzdWJqZWN0In0.RJobv0NbMn_1Nomy_nqY5P_QqlDiI9ykRxK8NnPuvbVppI9s7NS5xqUzVADmm4xGn13Q8GjEdvJsgmN1XmSP_lVd6zi8OAGOLWyS2NKLW_xqPIbCWl1rLAJiiamAvwNv2_A8KOiAI9KsGvZ6LlUwc-fVJhFaKQUHISD24Bvt8gItNWoFBJiRkQOc5PvV50dJdZzP54ie-ejTtXIEx9La_Z5fjEdGPP1QejHQQ9LKqcXy4kEwzJRNlXqlVssBVVh0XSKC48zzb0LCDqGHGwuGP0yVgTDYKsxXY9HQR9VxDNiMV12Kd2Ge34Rvv3N29hnUi4OI-hkCNfx8z8WQAk_O7Q")
	f.Fuzz(func(t *testing.T, data string) {
		tok, err := jwt.ParseSigned(data, allSignatureAlgorithms)
		if err != nil {
			_ = err.Error()
			return
		}
		var claims jwt.Claims
		if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
			_ = err.Error()
			return
		}
		_ = claims.Validate(jwt.Expected{})
		_ = claims.ValidateWithLeeway(jwt.Expected{
			Issuer:      claims.Issuer,
			Subject:     claims.Subject,
			ID:          claims.ID,
			AnyAudience: jwt.Audience{"aud1"},
			Time:        time.Unix(1_500_000_000, 0),
		}, 0)
	})
}

// FuzzJWTParseEncrypted checks we don't panic parsing the JWE form of a JWT.
func FuzzJWTParseEncrypted(f *testing.F) {
	f.Add("")
	f.Add("a.b.c.d.e")
	f.Add("eyJhbGciOiJkaXIiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSldUIn0..xm_OaF8RmwY6YAds.N2TFTINlDJ2QAgECqHa8se5anT7Pviu2gmIcwpfjeCMxvv6D-L8-2f4766FURCvD-vrSm6USpvC0MxV4GnwxaPaaHPgW57V_ZVxxJQK4AZB68F11V6ORE8ZjbYvv4782LJtTQknPtN7cSPQ0i7WC3vkWqvyurYkM2M87aIZgH-veWTTfaOrr3a-Tw7y_Njd_JaKeuT4G94XV-QWkCm0UpRmWwqPRx8MHe1HKNLcdgrjVQwy7ww0Y1fuOdP8IWgY59qGAW9PNV5HAdG2Mqdk12psvnW_MnlzRjFd36w.ug6dMbHAgIss4-BYvbTA3A")
	f.Add("eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwidHlwIjoiSldUIn0..KKp6pCbQO7jG-Ibh.sc-KjnX3senGirWaYn6Crod4x5oK5r4GXvSh_Xak0vQshGbI_aOpI6M5D-iA9WvGvQLNNUSq8pB-QHfvlTIlYhSaquhQNprm863NNAmfcvu_TEsVdgWptnwXtdmcFPWbvyW5f0h_WZ9Ue-CRml7GBpEJAFE.Axtro3itceWzJaKC_uVsFA")
	f.Fuzz(func(t *testing.T, data string) {
		if tok, err := jwt.ParseEncrypted(data, jwtKeyAlgorithms, allContentEncryption); err != nil {
			_ = err.Error()
		} else {
			_ = tok.Headers
		}
		if nested, err := jwt.ParseSignedAndEncrypted(data, jwtKeyAlgorithms, allContentEncryption, allSignatureAlgorithms); err != nil {
			_ = err.Error()
		} else {
			_ = nested.Headers
		}
	})
}
