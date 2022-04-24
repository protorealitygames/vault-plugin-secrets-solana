package solana

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type StorageConfig struct {
	FeePayerKey string `json:"fee_payer_key"`
}

type UserKeyData struct {
	UserKey string `json:"user_key"`
}

type UserKeyDataDisplay struct {
	UserKeyPubKey string `json:"user_key_pub_key"`
}

type StoreConfigDisplay struct {
	FeePayerPubKey string `json:"fee_payer_pub_key"`
}

type SignOutput struct {
	SignedTx string `json:"signed_tx"`
}

// backend wraps the backend framework and adds a map for storing key value pairs
type backend struct {
	*framework.Backend
}

var _ logical.Factory = Factory

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*backend, error) {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(solanaHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			b.sign(),
			b.key(),
			b.config(),
		),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
	}

	return b, nil
}

func (b *backend) config() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `config$`,

			Fields: map[string]*framework.FieldSchema{
				"fee_payer_key": {
					Type:        framework.TypeString,
					Description: "Specifies the fee payer private key that will be paying fees for the tx",
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
			},

			ExistenceCheck: b.handleKeyExistenceCheck,
		},
	}
}

func (b *backend) sign() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `sign$`,

			Fields: map[string]*framework.FieldSchema{
				"tx_payload": {
					Type:        framework.TypeString,
					Description: "Specifies the tx payload to be signed",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleSign,
					Summary:  "Store a secret at the specified location.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleSign,
				},
			},
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

	feePayerKey := data.Get("fee_payer_key").(string)
	if feePayerKey == "" {
		return nil, fmt.Errorf("empty fee payer key")
	}

	decodedPrivKey, err := solana.PrivateKeyFromBase58(feePayerKey)
	if err != nil {
		return nil, fmt.Errorf("invalid fee payer key, error: %v", err)
	}

	if len(decodedPrivKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid fee payer key, expected: %d bytes, got %d bytes", ed25519.PrivateKeySize, len(decodedPrivKey))
	}

	entry, err := logical.StorageEntryJSON("config", StorageConfig{
		FeePayerKey: feePayerKey,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to serialize configuration json, error: %v", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("unable to store configuration, error: %v", err)
	}

	return nil, nil
}

func (b *backend) handleConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return nil, fmt.Errorf("unable to get the config entry, error: %v", err)
	}

	cfg := &StorageConfig{}
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode config json, error: %v", err)
	}

	privKey, err := solana.PrivateKeyFromBase58(cfg.FeePayerKey)
	if err != nil {
		return nil, fmt.Errorf("unable to read fee payer key, error: %v", err)
	}

	pubCfg := StoreConfigDisplay{}
	pubCfg.FeePayerPubKey = privKey.PublicKey().String()

	respData := make(map[string]interface{})
	respData["config"] = pubCfg

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) handleKeyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.EntityID+"/"+"key")
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
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

	return nil, nil
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

func validateAndSignTx(tx *solana.Transaction, feePayerKey, userKey solana.PrivateKey) (*solana.Transaction, error) {
	derivedFeePayerPubkey := tx.Message.AccountKeys[0]
	if !derivedFeePayerPubkey.Equals(feePayerKey.PublicKey()) {
		return nil, fmt.Errorf("fee payer pubkey must be the included in account keys at 0th Index")
	}

	for instructionIndex, instruction := range tx.Message.Instructions {
		for instructionAccountIdx, keyIndex := range instruction.Accounts {
			if keyIndex == 0 {
				return nil, fmt.Errorf("fee payer pubkey is used as part of the instruction at: %d with index: %d", instructionIndex, instructionAccountIdx)
			}
		}
	}

	_, err := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key == derivedFeePayerPubkey {
			return &feePayerKey
		} else if key == userKey.PublicKey() {
			return &userKey
		} else {
			return nil
		}
	})
	if err != nil {
		return nil, err
	}

	return tx, nil
}

func (b *backend) handleSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return nil, fmt.Errorf("unable to get the config entry, error: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("plugin is not configured, please write to /config path")
	}

	payload := data.Get("tx_payload").(string)
	if payload == "" {
		return nil, fmt.Errorf("empty tx payload")
	}

	binaryTx, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("unable to decode tx payload")
	}

	// parse transaction:
	tx, err := solana.TransactionFromDecoder(bin.NewBinDecoder(binaryTx))
	if err != nil {
		return nil, fmt.Errorf("unable to construct a transaction from tx payload")
	}

	cfg := &StorageConfig{}
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode config json, error: %v", err)
	}

	feePayerKey, err := solana.PrivateKeyFromBase58(cfg.FeePayerKey)
	if err != nil {
		return nil, fmt.Errorf("unable to read fee payer key, error: %v", err)
	}

	userKeyEntry, err := req.Storage.Get(ctx, req.EntityID+"/"+"key")
	if err != nil {
		return nil, fmt.Errorf("unable to get existing user key if any due to an error: %v", err)
	}
	if userKeyEntry == nil {
		return nil, fmt.Errorf("user key does not exists, please create one")
	}

	keyData := UserKeyData{}
	if err := userKeyEntry.DecodeJSON(&keyData); err != nil {
		return nil, fmt.Errorf("unable to decode user key retrieved from storage due to an error: %s", err)
	}

	privateKey, err := solana.PrivateKeyFromBase58(keyData.UserKey)
	if err != nil {
		return nil, fmt.Errorf("unable to read user key, error: %v", err)
	}

	signedTx, err := validateAndSignTx(tx, feePayerKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to sign tx due to an error: %v", err)
	}

	output := SignOutput{
		SignedTx: signedTx.MustToBase64(),
	}

	respData := make(map[string]interface{})
	respData["signed_tx"] = output

	return &logical.Response{
		Data: respData,
	}, nil
}

const solanaHelp = `
Solana secret backend allows user to sign tx by acting as secure signing module.
`
