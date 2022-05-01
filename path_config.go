package solana

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Config stores configuration for the plugin
type Config struct {
	FeePayerKey string `json:"fee_payer_key"`
}

// ConfigDisplay is display version of Config
type ConfigDisplay struct {
	FeePayerPubKey string `json:"fee_payer_pub_key"`
}

func (b *backend) config() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `config$`,

			Fields: map[string]*framework.FieldSchema{
				"fee_payer_key": {
					Type:        framework.TypeString,
					Description: "Specifies the fee payer private key that will be paying fees for the tx",
					Required:    true,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleConfigRead,
					Summary:  "Read key of the user.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleConfigCreate,
					Summary:  "Create a new key only if there is no key yet",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleConfigCreate,
					Summary:  "Create a new key only if there is no key yet",
				},
			},

			ExistenceCheck: b.handleConfigExistenceCheck,
		},
	}
}

func (b *backend) handleConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (b *backend) handleConfigCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	rawFeePayerKey, exists, err := data.GetOkErr("fee_payer_key")
	if !exists || rawFeePayerKey == nil {
		return nil, fmt.Errorf("empty fee payer key")
	}
	if err != nil {
		return nil, fmt.Errorf("invalid data for fee payer key: %v", rawFeePayerKey)
	}
	feePayerKey, ok := rawFeePayerKey.(string)
	if !ok {
		return nil, fmt.Errorf("invalid fee payer key value: %v", rawFeePayerKey)
	}

	decodedPrivKey, err := solana.PrivateKeyFromBase58(feePayerKey)
	if err != nil {
		return nil, fmt.Errorf("invalid fee payer key, error: %v", err)
	}

	if len(decodedPrivKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid fee payer key, expected: %d bytes, got %d bytes", ed25519.PrivateKeySize, len(decodedPrivKey))
	}

	entry, err := logical.StorageEntryJSON("config", Config{
		FeePayerKey: feePayerKey,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to serialize configuration json, error: %v", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("unable to store configuration, error: %v", err)
	}

	pubCfg := ConfigDisplay{}
	pubCfg.FeePayerPubKey = decodedPrivKey.PublicKey().String()

	respData := make(map[string]interface{})
	respData["config"] = pubCfg

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) handleConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return nil, fmt.Errorf("unable to get the config entry, error: %v", err)
	}
	if entry == nil {
		return nil, nil
	}

	cfg := &Config{}
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode config json, error: %v", err)
	}

	privKey, err := solana.PrivateKeyFromBase58(cfg.FeePayerKey)
	if err != nil {
		return nil, fmt.Errorf("unable to read fee payer key, error: %v", err)
	}

	pubCfg := ConfigDisplay{}
	pubCfg.FeePayerPubKey = privKey.PublicKey().String()

	respData := make(map[string]interface{})
	respData["config"] = pubCfg

	return &logical.Response{
		Data: respData,
	}, nil
}
