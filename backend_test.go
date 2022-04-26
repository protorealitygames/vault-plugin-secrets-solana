package solana

import (
	"encoding/base64"
	"fmt"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/test-go/testify/require"
	"testing"
)

func TestGenerateTx(t *testing.T) {
	feePayerPrivateKey, _ := solana.PrivateKeyFromBase58("4VmNTtyhpPbwoBQB9AQQVoyzLHqKfmbfFyR9HZie3dJbSqn3JMdNgfwBw8ZHWvbR8nV7WVa9pFZAc1KhA73UpN4Q")
	fmt.Println("Fee payer private key is:", feePayerPrivateKey.String())

	feePayerPubkey, err := solana.PublicKeyFromBase58(feePayerPrivateKey.PublicKey().String())
	require.NoError(t, err, "There should not be any error")

	userKey, _ := solana.PrivateKeyFromBase58("5QeZQzxF6jiVjWaQArsAvULixmQkymaLQgt7hfVWNUg3HaBVrUb1RdvoRuQDT6QCnGwczfMGyRRRCuu2hehs8qKn")
	fmt.Println("user key is:", userKey)
	userPubkey := userKey.PublicKey()
	require.NoError(t, err, "There should not be any error")

	messageBinary, _ := base64.StdEncoding.DecodeString("AgABBFT0AJyUQT2jHkwYohTOeFSWqD75Xej3Zjscwj57U1YBm16UfAUlKBAB1HvYUWeI41rYucnrvsSjvTAWfv/cnHlKW/JoAneU0GPTD8uUN3K7KoLNhc8/xxeQLLLyGQ3wiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhUPGSFNL4TozduSc41UG+gar5Ia01XF9olKrm4GIw18BAwIBAgwCAAAACgAAAAAAAAA=")
	msg := solana.Message{}
	err = msg.UnmarshalWithDecoder(bin.NewBinDecoder(messageBinary))
	require.NoError(t, err, "No error")

	tx := solana.Transaction{}
	tx.Message = msg

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(userPubkey) {
			return &userKey
		} else if key.Equals(feePayerPubkey) {
			return &feePayerPrivateKey
		} else {
			return nil
		}
	})
	require.NoError(t, err, "No error should happen here")

	base64Payload, err := tx.ToBase64()
	require.NoError(t, err, "We should be able to get the base64 payload")

	fmt.Println(base64Payload)
}

func TestValidateAndSignTxWithAdditionalSignatures(t *testing.T) {
	feePayerKey, _ := solana.NewRandomPrivateKey()
	userKey, _ := solana.NewRandomPrivateKey()
	programKey, _ := solana.NewRandomPrivateKey()
	additionalKey, _ := solana.NewRandomPrivateKey()
	otherKey, _ := solana.NewRandomPrivateKey()

	txWithAdditionalSignatures, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
			solana.NewAccountMeta(additionalKey.PublicKey(), true, true),
			solana.NewAccountMeta(otherKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).SetFeePayer(feePayerKey.PublicKey()).Build()
	require.NoError(t, err, "We should be able to build tx")

	msgContent, err := txWithAdditionalSignatures.Message.MarshalBinary()
	require.NoError(t, err, "We should be able to marshal message binary")

	additionalKeySignature, err := additionalKey.Sign(msgContent)
	require.NoError(t, err, "We should be able to sign message content")

	otherKeySignature, err := otherKey.Sign(msgContent)
	require.NoError(t, err, "We should be able to sign message content")

	signedTx, err := validateAndSignMsg(txWithAdditionalSignatures.Message, []ParsedSignaturePair{
		{
			Signature: additionalKeySignature,
			PubKey:    additionalKey.PublicKey(),
		},
		{
			Signature: otherKeySignature,
			PubKey:    otherKey.PublicKey(),
		},
	}, feePayerKey, userKey)
	require.NoError(t, err, "We should be able to validate tx")

	require.Equal(t, 4, len(signedTx.Signatures), "There needs to be 4 signatures")

	_, err = validateAndSignMsg(txWithAdditionalSignatures.Message, []ParsedSignaturePair{
		{
			Signature: additionalKeySignature,
			PubKey:    otherKey.PublicKey(),
		},
		{
			Signature: otherKeySignature,
			PubKey:    additionalKey.PublicKey(),
		},
	}, feePayerKey, userKey)
	require.EqualError(t, err, fmt.Sprintf("mismatch between signature: %s and public key: %s", additionalKeySignature, otherKey.PublicKey()), "We should not be able to validate tx")

	_, err = validateAndSignMsg(txWithAdditionalSignatures.Message, []ParsedSignaturePair{
		{
			Signature: otherKeySignature,
			PubKey:    otherKey.PublicKey(),
		},
		{
			Signature: additionalKeySignature,
			PubKey:    otherKey.PublicKey(),
		},
	}, feePayerKey, userKey)
	require.EqualError(t, err, fmt.Sprintf("duplicate entry in signature detected with Pubkey: %s", otherKey.PublicKey()), "We should not be able to validate tx")

}

func TestValidateAndSignTx(t *testing.T) {
	feePayerKey, _ := solana.NewRandomPrivateKey()
	userKey, _ := solana.NewRandomPrivateKey()
	programKey, _ := solana.NewRandomPrivateKey()

	tx, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).SetFeePayer(feePayerKey.PublicKey()).Build()
	require.NoError(t, err, "We should be able to build tx")

	tx, err = validateAndSignMsg(tx.Message, []ParsedSignaturePair{}, feePayerKey, userKey)
	require.NoError(t, err, "We should be able sign a valid tx")

	require.Equal(t, 2, len(tx.Signatures), "There need to be two signatures")

	invalidTxWithNoFeePayer, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
			solana.NewAccountMeta(feePayerKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).Build()
	require.NoError(t, err, "We should be able to build tx")

	_, err = validateAndSignMsg(invalidTxWithNoFeePayer.Message, []ParsedSignaturePair{}, feePayerKey, userKey)
	require.EqualError(t, err, "fee payer pubkey must be the included in account keys at 0th Index", "We should get the exact error")

	invalidTxFeePayerUsed, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
			solana.NewAccountMeta(feePayerKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).SetFeePayer(feePayerKey.PublicKey()).Build()
	require.NoError(t, err, "We should be able to build tx")

	_, err = validateAndSignMsg(invalidTxFeePayerUsed.Message, []ParsedSignaturePair{}, feePayerKey, userKey)
	require.EqualError(
		t,
		err,
		"fee payer pubkey is used as part of the instruction at: 0 with index: 1",
		"We should get the exact error",
	)

	randomKey, _ := solana.NewRandomPrivateKey()
	invalidTxUnknownSigningAccount, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
			solana.NewAccountMeta(randomKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).SetFeePayer(feePayerKey.PublicKey()).Build()
	require.NoError(t, err, "We should be able to build tx")

	_, err = validateAndSignMsg(invalidTxUnknownSigningAccount.Message, []ParsedSignaturePair{}, feePayerKey, userKey)
	require.EqualError(
		t,
		err,
		fmt.Sprintf("no signature detected for Pubkey: %s", randomKey.PublicKey().String()),
		"Signing should be failed with this error",
	)
}
