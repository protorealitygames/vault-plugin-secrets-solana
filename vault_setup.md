# Introduction
This document covers how to setup vault in order to use this plugin

## Example vault configuration file
```text
plugin_directory = "plugins"
```

## Example solana plugin policy for token
```text
path "vault-plugin-secrets-solana/sign" {
    capabilities = ["create"]
}

path "vault-plugin-secrets-solana/key" {
    capabilities = ["create", "update", "read"]
}

path "vault-plugin-secrets-solana/config" {
    capabilities = ["read"]
}
```

## Commands to run

```shell
# Enables JWT plugin
./vault auth enable jwt
# Register our plugin here.
./vault plugin register -sha256=$(shasum -a 256 plugins/vault-plugin-secrets-solana| cut -d\  -f1) secret vault-plugin-secrets-solana
# Enable our custom plugin
./vault secrets enable vault-plugin-secrets-solana
```