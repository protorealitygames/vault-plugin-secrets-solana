package solana

import (
	"context"
	"encoding/base64"
	"fmt"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// SignOutput contains signature data
type SignOutput struct {
	SignedTx string `json:"signed_tx"`
}

// SignaturePair contains raw signature of the message and corresponding PubKey
type SignaturePair struct {
	Signature string `json:"signature"`
	Pubkey    string `json:"pubkey"`
}

// ParsedSignaturePair contains parsed signature of the message and corresponding PubKey
type ParsedSignaturePair struct {
	Signature solana.Signature
	PubKey    solana.PublicKey
}

// validateAndSignMsg takes a solana message, additional signatures required to be filled in the transaction, fee payer private key
// and user key. It creates a map of public key and signature using signature pair and two private keys. Makes sure that
// we have all signatures required by the message and create tx with that message and all the signatures.
func validateAndSignMsg(msg solana.Message, additionalSignatures []ParsedSignaturePair, feePayerKey, userKey solana.PrivateKey) (*solana.Transaction, error) {
	if !msg.AccountKeys[0].Equals(feePayerKey.PublicKey()) {
		return nil, fmt.Errorf("fee payer pubkey must be the included in account keys at 0th Index")
	}

	for instructionIndex, instruction := range msg.Instructions {
		for instructionAccountIdx, keyIndex := range instruction.Accounts {
			if keyIndex == 0 {
				return nil, fmt.Errorf("fee payer pubkey is used as part of the instruction at: %d with index: %d", instructionIndex, instructionAccountIdx)
			}
		}
	}

	messageContent, err := msg.MarshalBinary()
	if err != nil {
		return nil, err
	}

	feePayerSignature, err := feePayerKey.Sign(messageContent)
	if err != nil {
		return nil, err
	}

	userSignature, err := userKey.Sign(messageContent)
	if err != nil {
		return nil, err
	}

	additionalSignatures = append(additionalSignatures,
		ParsedSignaturePair{
			Signature: feePayerSignature,
			PubKey:    feePayerKey.PublicKey(),
		}, ParsedSignaturePair{
			Signature: userSignature,
			PubKey:    userKey.PublicKey(),
		},
	)

	signatureRequiredPubkeys := msg.AccountKeys[0:msg.Header.NumRequiredSignatures]

	signatureKeyPairMap := make(map[solana.PublicKey]solana.Signature)
	for _, additionalSignature := range additionalSignatures {
		if _, ok := signatureKeyPairMap[additionalSignature.PubKey]; ok {
			return nil, fmt.Errorf("duplicate entry in signature detected with Pubkey: %s", additionalSignature.PubKey.String())
		}
		if !additionalSignature.Signature.Verify(additionalSignature.PubKey, messageContent) {
			return nil, fmt.Errorf("mismatch between signature: %s and public key: %s", additionalSignature.Signature.String(), additionalSignature.PubKey.String())
		}
		signatureKeyPairMap[additionalSignature.PubKey] = additionalSignature.Signature
	}

	tx := solana.Transaction{}
	tx.Message = msg

	for _, pubkey := range signatureRequiredPubkeys {
		if signature, ok := signatureKeyPairMap[pubkey]; !ok {
			return nil, fmt.Errorf("no signature detected for Pubkey: %s", pubkey.String())
		} else {
			tx.Signatures = append(tx.Signatures, signature)
		}
	}

	return &tx, nil
}

// parseAdditionalSignature takes the raw map we got from user and parse the public key as well as signature
func parseAdditionalSignature(additionalSignatures map[string]string) ([]ParsedSignaturePair, error) {
	parsedSignatures := make([]ParsedSignaturePair, 0)

	for pubkey, signature := range additionalSignatures {
		parsedPubKey, err := solana.PublicKeyFromBase58(pubkey)
		if err != nil {
			return nil, fmt.Errorf("unable to parse pubkey: %s", pubkey)
		}

		parsedSignature, err := solana.SignatureFromBase58(signature)
		if err != nil {
			return nil, fmt.Errorf("unable to parse signature: %s", signature)
		}

		parsedSignatures = append(parsedSignatures, ParsedSignaturePair{
			Signature: parsedSignature,
			PubKey:    parsedPubKey,
		})
	}

	return parsedSignatures, nil
}

func (b *backend) sign() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `sign$`,

			Fields: map[string]*framework.FieldSchema{
				"msg_payload": {
					Type:        framework.TypeString,
					Description: "Specifies the msg payload to be signed",
					Required:    true,
				},
				"additional_signatures": {
					Type:        framework.TypeKVPairs,
					Description: "Map of additional signatures",
					Required:    false,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleSign,
					Summary:  "Signs a message payload",
				},
			},

			ExistenceCheck: b.handleSignExistenceCheck,
		},
	}
}

func (b *backend) handleSignExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
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

	rawPayload, exists, err := data.GetOkErr("msg_payload")
	if !exists || rawPayload == nil {
		return nil, fmt.Errorf("empty message payload")
	}
	if err != nil {
		return nil, fmt.Errorf("invalid data for message payload: %v", rawPayload)
	}
	payload, ok := rawPayload.(string)
	if !ok {
		return nil, fmt.Errorf("invalid payload value: %v", rawPayload)
	}

	additionalSignatureRawMap, exists, err := data.GetOkErr("additional_signatures")
	if !exists || additionalSignatureRawMap == nil {
		additionalSignatureRawMap = make(map[string]string)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid data for additional signature: %v", err)
	}
	additionalSignatureMap, ok := additionalSignatureRawMap.(map[string]string)
	if !ok {
		return nil, fmt.Errorf("invalid additional signature map: %+v", additionalSignatureRawMap)
	}

	parsedSignatures, err := parseAdditionalSignature(additionalSignatureMap)
	if err != nil {
		return nil, fmt.Errorf("unable to parse additional signature due to an error: %s", err)
	}

	binaryMsg, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("unable to decode tx payload")
	}

	// parse message:
	msg := solana.Message{}
	if err := msg.UnmarshalWithDecoder(bin.NewBinDecoder(binaryMsg)); err != nil {
		return nil, fmt.Errorf("unable to construct a message from message payload")
	}

	cfg := &Config{}
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

	signedTx, err := validateAndSignMsg(msg, parsedSignatures, feePayerKey, privateKey)
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
