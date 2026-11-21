module github.com/lightningmail/desktop

go 1.26.1

require (
	github.com/bnema/puregotk v0.5.4
	github.com/bnema/puregotk-webkit v0.1.0
)

require github.com/bnema/purego v0.13.0-bnema.1 // indirect

require github.com/lightningmail/lm1 v0.0.0

replace github.com/lightningmail/lm1 => ../lm1
