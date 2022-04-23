GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o ./bin/vault-plugin-secrets-solana ./cmd/vault-plugin-secrets-solana/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault secrets enable -path=solana-secrets vault-plugin-secrets-solana

clean:
	rm -f ./vault/plugins/vault-plugin-secrets-solana

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
