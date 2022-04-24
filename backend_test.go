package solana

import (
	"fmt"
	"github.com/gagliardetto/solana-go"
	"github.com/test-go/testify/require"
	"testing"
)

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

	_, err = validateAndSignTx(tx, feePayerKey, userKey)
	require.NoError(t, err, "We should be able sign a valid tx")

	require.Equal(t, 2, len(tx.Signatures), "There need to be two signatures")

	invalidTxWithNoFeePayer, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
			solana.NewAccountMeta(feePayerKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).Build()
	require.NoError(t, err, "We should be able to build tx")

	_, err = validateAndSignTx(invalidTxWithNoFeePayer, feePayerKey, userKey)
	require.EqualError(t, err, "fee payer pubkey must be the included in account keys at 0th Index", "We should get the exact error")

	require.Equal(t, 0, len(invalidTxWithNoFeePayer.Signatures), "There need to be zero signatures")

	invalidTxFeePayerUsed, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
			solana.NewAccountMeta(feePayerKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).SetFeePayer(feePayerKey.PublicKey()).Build()
	require.NoError(t, err, "We should be able to build tx")

	_, err = validateAndSignTx(invalidTxFeePayerUsed, feePayerKey, userKey)
	require.EqualError(
		t,
		err,
		"fee payer pubkey is used as part of the instruction at: 0 with index: 1",
		"We should get the exact error",
	)

	require.Equal(t, 0, len(invalidTxFeePayerUsed.Signatures), "There need to be zero signatures")

	randomKey, _ := solana.NewRandomPrivateKey()
	invalidTxUnknownSigningAccount, err := solana.NewTransactionBuilder().AddInstruction(
		solana.NewInstruction(programKey.PublicKey(), []*solana.AccountMeta{
			solana.NewAccountMeta(userKey.PublicKey(), true, true),
			solana.NewAccountMeta(randomKey.PublicKey(), true, true),
		}, []byte{1, 2, 3}),
	).SetFeePayer(feePayerKey.PublicKey()).Build()
	require.NoError(t, err, "We should be able to build tx")

	_, err = validateAndSignTx(invalidTxUnknownSigningAccount, feePayerKey, userKey)
	require.EqualError(
		t,
		err,
		fmt.Sprintf("signer key %q not found. Ensure all the signer keys are in the vault", randomKey.PublicKey().String()),
		"Signing should be failed with this error",
	)

	require.Equal(t, 2, len(invalidTxUnknownSigningAccount.Signatures), "There need to be zero signatures")
}
