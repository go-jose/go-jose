module github.com/go-jose/go-jose/jose-util

go 1.12

require (
	github.com/alecthomas/template v0.0.0-20160405071501-a0175ee3bccc // indirect
	github.com/alecthomas/units v0.0.0-20151022065526-2efee857e7cf // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	github.com/go-jose/go-jose/v3 v3.0.0-00010101000000-000000000000
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

replace github.com/go-jose/go-jose/v3 => ../
