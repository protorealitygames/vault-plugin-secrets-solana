package solana

import (
	"context"
	"fmt"
	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// UserKeyData stores user key and supporting data
type UserKeyData struct {
	UserKey string `json:"user_key"`
}

// UserKeyDataDisplay is display version of UserKeyData
type UserKeyDataDisplay struct {
	UserKeyPubKey string `json:"user_key_pub_key"`
}

func (b *backend) key() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `key$`,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleKeyRead,
					Summary:  "Read key of the user.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleKeyCreate,
					Summary:  "Create a new key only if there is no key yet",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleKeyCreate,
					Summary:  "Create a new key only if there is no key yet",
				},
			},
		},
	}
}

func (b *backend) handleKeyCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	previousEntry, err := req.Storage.Get(ctx, req.EntityID+"/"+"key")
	if err != nil {
		return nil, fmt.Errorf("unable to get existing user key if any due to an error: %v", err)
	}
	if previousEntry != nil {
		return nil, fmt.Errorf("user key already exists")
	}

	privKey, err := solana.NewRandomPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("unable to create new key, error: %v", err)
	}

	keyData := UserKeyData{
		UserKey: privKey.String(),
	}

	entry, err := logical.StorageEntryJSON(req.EntityID+"/"+"key", keyData)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize configuration json, error: %v", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("unable to store configuration, error: %v", err)
	}

	displayKeyData := UserKeyDataDisplay{
		UserKeyPubKey: privKey.PublicKey().String(),
	}

	respData := make(map[string]interface{})
	respData["keydata"] = displayKeyData

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) handleKeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	previousEntry, err := req.Storage.Get(ctx, req.EntityID+"/"+"key")
	if err != nil {
		return nil, fmt.Errorf("unable to get existing user key if any due to an error: %v", err)
	}
	if previousEntry == nil {
		return nil, fmt.Errorf("user key does not exists, please create one")
	}

	keyData := UserKeyData{}
	if err := previousEntry.DecodeJSON(&keyData); err != nil {
		return nil, fmt.Errorf("unable to decode user key retrieved from storage due to an error: %s", err)
	}

	privKey, err := solana.PrivateKeyFromBase58(keyData.UserKey)
	if err != nil {
		return nil, fmt.Errorf("unable to read user key, error: %v", err)
	}

	displayKeyData := UserKeyDataDisplay{
		UserKeyPubKey: privKey.PublicKey().String(),
	}

	respData := make(map[string]interface{})
	respData["keydata"] = displayKeyData

	return &logical.Response{
		Data: respData,
	}, nil

}
