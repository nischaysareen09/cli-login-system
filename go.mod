module cli-login-system

go 1.22.2

replace golang.org/x/crypto => github.com/golang/crypto v0.24.0

replace golang.org/x/sys => github.com/golang/sys v0.21.0

require (
	github.com/chzyer/readline v1.5.1
	github.com/google/uuid v1.6.0
	github.com/mattn/go-sqlite3 v1.14.49
	github.com/mdp/qrterminal/v3 v3.2.1
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.24.0
	golang.org/x/term v0.21.0
	rsc.io/qr v0.2.0
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	golang.org/x/sys v0.29.0 // indirect
)

replace golang.org/x/term => github.com/golang/term v0.21.0

replace rsc.io/qr => github.com/rsc/qr v0.2.0
