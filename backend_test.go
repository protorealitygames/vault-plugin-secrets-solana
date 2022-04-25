package solana

import (
	"fmt"
	"github.com/gagliardetto/solana-go"
	"github.com/test-go/testify/require"
	"testing"
)

func TestGenerateTx(t *testing.T) {
	feePayerPrivateKey, _ := solana.NewRandomPrivateKey()
	fmt.Println("Fee payer pub key is: ", feePayerPrivateKey.PublicKey().String())
	fmt.Println("Fee payer private key is:", feePayerPrivateKey.String())
	feePayerPubkey, err := solana.PublicKeyFromBase58(feePayerPrivateKey.PublicKey().String())
	require.NoError(t, err, "There should not be any error")

	userPubkey, err := solana.PublicKeyFromBase58("EdZ19deVHLz89nDZLY6UxfdHvcqiZJAjQYaue1jAu6Y8")
	require.NoError(t, err, "There should not be any error")

	programKey, _ := solana.NewRandomPrivateKey()

	tx, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userPubkey, true, true),
		}, []byte{1, 2, 3}),
	).SetFeePayer(feePayerPubkey).Build()
	require.NoError(t, err, "We should be able to build tx")

	base64Payload := tx.Message.ToBase64()
	require.NoError(t, err, "We should be able to get the base64 payload")

	fmt.Println(base64Payload)
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

	tx, err = validateAndSignMsg(tx.Message, feePayerKey, userKey)
	require.NoError(t, err, "We should be able sign a valid tx")

	require.Equal(t, 2, len(tx.Signatures), "There need to be two signatures")

	invalidTxWithNoFeePayer, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
			solana.NewAccountMeta(feePayerKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).Build()
	require.NoError(t, err, "We should be able to build tx")

	_, err = validateAndSignMsg(invalidTxWithNoFeePayer.Message, feePayerKey, userKey)
	require.EqualError(t, err, "fee payer pubkey must be the included in account keys at 0th Index", "We should get the exact error")

	invalidTxFeePayerUsed, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
			solana.NewAccountMeta(feePayerKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).SetFeePayer(feePayerKey.PublicKey()).Build()
	require.NoError(t, err, "We should be able to build tx")

	_, err = validateAndSignMsg(invalidTxFeePayerUsed.Message, feePayerKey, userKey)
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

	_, err = validateAndSignMsg(invalidTxUnknownSigningAccount.Message, feePayerKey, userKey)
	require.EqualError(
		t,
		err,
		fmt.Sprintf("signer key %q not found. Ensure all the signer keys are in the vault", randomKey.PublicKey().String()),
		"Signing should be failed with this error",
	)
}
