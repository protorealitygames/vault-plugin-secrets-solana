# Vault solana plugin

## Introduction
Vault solana plugin stores fee payer key on behalf of the organization as well as user's private key and sign incoming Solana
transaction.

## Demo
We have node.js demo available in `node_demo` folder.

## API

### Set configuration
One time operation. Should only be allowed to be done by root user.
Root bearer token required.
Path: `{{vault_server}}/v1/vault-plugin-secrets-solana/config`
HTTP Method: POST
Body: 
```json
{
  "fee_payer_key": "<fee payer private key>"
}
```

Response: 
Response code: 204
No body

### Get configuration
Get the configuration that was done by root user. Recommended to use user token here.
User bearer token required.
Path: `{{vault_server}}/v1/vault-plugin-secrets-solana/config`
HTTP Method: GET

Response:
Response code: 200
```json
{
    "request_id": "6a986bb1-dc61-e8bf-5d89-3a7b1244dbe5",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "config": {
            "fee_payer_pub_key": "<fee payer PUBLIC key>"
        }
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
```

### Set User key
Asks plugin to generate a key for the user. Can only be called one time per user.
User bearer token required.
Path: `{{vault_server}}/v1/vault-plugin-secrets-solana/key`
HTTP Method: POST

Response: 
Response code: 200
```json
{
    "request_id": "0c89acf1-f6db-0804-7592-1293ad32d1c1",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "keydata": {
            "user_key_pub_key": "<User public key>"
        }
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
```

### Get User key
Gets the user's generated key.
User bearer token required.
Path: `{{vault_server}}/v1/vault-plugin-secrets-solana/key`
HTTP Method: GET

Response:
Response code: 200
```json
{
    "request_id": "0c89acf1-f6db-0804-7592-1293ad32d1c1",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "keydata": {
            "user_key_pub_key": "<User public key>"
        }
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
```

### Sign the solana tx message
Signs a solana message using the global fee payer key and local user key.
User bearer token required.
If additional signatures are provided in the signing request the public key must be used in one or 
more instruction and the signature must be valid. 
If the signing request is valid, the plugin will sign the message and incorporate the additional signatures
provided, package it in solana tx, serialize it and encode the serialized bytes to base64.
PATH: `{{vault_server}}/v1/vault-plugin-secrets-solana/sign`
HTTP Method: POST
Body: 
```json
{
    "msg_payload": "<transaction message serialized and encoded in base64>",
    "additional_signatures": [
        {
            "<base58 encoded public key>": "<base58 encoded signature>"
        },
        {
            "<base58 encoded public key>": "<base58 encoded signature>"
        }
    ]
}
```

Response:
Response code: 200
Body: 
```json
{
  "request_id": "85420bfc-184f-302c-b49e-aa83e1507faa",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "signed_tx": {
      "signed_tx": "<transaction serialized and encoded in base64>",
    }
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

## Production Guidelines
1. Upgrading of vault plugin: We need to follow procedure outlined in [documentation](https://www.vaultproject.io/docs/upgrading/plugins)
2. Taking regular backup: To prevent any data loss, in production periodic backup of underlying storage is necessary.
