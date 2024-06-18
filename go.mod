module github.com/go-jose/go-jose/v3

// https://pkg.go.dev/vuln/GO-2024-2598
// crypto/x509.Certificate.Verify panics on unknown public key algorithm.
// Fixed in Go 1.21.8
go 1.21.8

require (
	github.com/google/go-cmp v0.5.9
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.19.0
)
