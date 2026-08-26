module main

go 1.27.0

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20260427185012-515ba073c4c1
	github.com/google/go-tpm v0.9.9-0.20260124013517-8f8f42cba0de
	github.com/salrashid123/tpmaead v0.0.0
	github.com/tink-crypto/tink-go/v2 v2.8.0
)

require (
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/salrashid123/tpmaead => ../
