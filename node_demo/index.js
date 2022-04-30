const http = require('follow-redirects').http;
const web3 = require('@solana/web3.js');
const bs58 = require('bs58');
const timers = require('timers/promises');

function req(options, obj) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => (body += chunk.toString()));
            res.on('error', reject);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode <= 299) {
                    resolve({statusCode: res.statusCode, headers: res.headers, body});
                } else {
                    reject(
                        'Get Request failed. status: ' + res.statusCode + ', body: ' + body
                    );
                }
            });
        });
        if (obj !== undefined) {
            req.write(JSON.stringify(obj));
        }
        req.on('error', reject);
        req.end();
    });
}

// For simplicity's sake we have hard coded vault token here
// But, in production it needs to come from JWT plugin from vault.
// Template:
// URL: {{vault_server}}/v1/auth/jwt/login
// Method: POST
// Body: {
//     "jwt": "{{jwt_id_token}}"
// }
// Here {{vault_server}} refers to the ip address or domain name of the vault server.
// {{jwt_id_token}} refers to the id token that application get from the keycloak OIDC.
//
// Example response from vault:
// {
//     "request_id": "7533879d-4862-24d9-1976-ca8e6c76a1de",
//     "lease_id": "",
//     "renewable": false,
//     "lease_duration": 0,
//     "data": null,
//     "wrap_info": null,
//     "warnings": null,
//     "auth": {
//         "client_token": "hvs.CAESICLp9gL_6vfuI4pFUyejCIPK5-P5S8Si_jVoFU0faLvSGh4KHGh2cy5QNVZmdzRsUVBwSHZPSW52eGlHcTdtZU4",
//         "accessor": "gXPblR2nmm5fUziVJZ589TsP",
//         "policies": [
//             "solana"
//         ],
//         "token_policies": [
//             "solana"
//         ],
//         "metadata": {
//             "email": "lucis_nam@do119.com",
//             "name": "Lucis Nam",
//             "role": "solana",
//             "token_id": "84a7e805-b52c-4b4d-901f-66f735976b44",
//             "unique_name": "experimentation_stuff"
//         },
//         "lease_duration": 2764800,
//         "renewable": true,
//         "entity_id": "aa99c897-0aea-0573-0168-08170948785a",
//         "token_type": "service",
//         "orphan": true,
//         "mfa_requirement": null,
//         "num_uses": 0
//     }
// }
// The vault token refers to client_token in above response.
function createOptionForVault(method, path) {
    return {
        method,
        hostname: 'localhost',
        port: 8200,
        path,
        headers: {
            Authorization:
                'Bearer hvs.CAESICLp9gL_6vfuI4pFUyejCIPK5-P5S8Si_jVoFU0faLvSGh4KHGh2cy5QNVZmdzRsUVBwSHZPSW52eGlHcTdtZU4',
            'Content-Type': 'application/json'
        },
        maxRedirects: 20
    };
}

async function run() {
    // Connecting to solana network. For our purpose we are
    // connecting to devnet.
    const connection = new web3.Connection(
        web3.clusterApiUrl('devnet'),
        'confirmed'
    );

    // Gets the pubkey of the user from the vault. The key need to be set
    // first time the user signs up.
    // Authorization: Bearer vault token issued to the user via JWT
    const getUserPubkeyOption = createOptionForVault(
        'GET',
        '/v1/vault-plugin-secrets-solana/key'
    );
    let out = await req(getUserPubkeyOption);
    let jsonResponse = JSON.parse(out.body);

    const accountFromPubkey = new web3.PublicKey(
        jsonResponse.data.keydata.user_key_pub_key
    );

    console.log(
        'Got user pub key from vault',
        jsonResponse.data.keydata.user_key_pub_key
    );

    // Gets the fee payer pubkey from the vault. Fee payer key is configured by Proto reality gaming
    // The key need to be set first time the user signs up on the app.
    // Authorization: Bearer vault token issued to the user via JWT vault plugin.
    const getFeePayerPubkeyOption = createOptionForVault(
        'GET',
        '/v1/vault-plugin-secrets-solana/config'
    );
    out = await req(getFeePayerPubkeyOption);
    jsonResponse = JSON.parse(out.body);

    const feePayerPubkey = new web3.PublicKey(
        jsonResponse.data.config.fee_payer_pub_key
    );

    console.log(
        'Got fee pub key from vault',
        jsonResponse.data.config.fee_payer_pub_key
    );

    const newAccountKey = web3.Keypair.generate();
    const programIdKey = web3.Keypair.fromSecretKey(
        bs58.decode(
            '44GeNewbQZYP5hmWfE7VQ8xJDEhgd8iwSeYeVHisK1nkqQa5mwwLEsvuDHCD3ohku8T3jA4bEVMPkQtSRCseiXsv'
        )
    );

    console.log('Trying to get funds to the fee payer and user account:');

    // Getting funds from solana devnet (This step is only required for testnet)
    let airdropSignature = await connection.requestAirdrop(
        accountFromPubkey,
        web3.LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(airdropSignature);

    await timers.setTimeout(10000);

    // Getting funds from solana devnet (This step is only required for testnet)
    airdropSignature = await connection.requestAirdrop(
        accountFromPubkey,
        web3.LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(airdropSignature);

    console.log('Got funds in account from pubkey');

    await timers.setTimeout(10000);

    // Getting funds from solana devnet (This step is only required for testnet)
    airdropSignature = await connection.requestAirdrop(
        feePayerPubkey,
        web3.LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(airdropSignature);
    console.log('Got funds in fee payer account');

    await timers.setTimeout(10000);

    const blockhashObj = await connection.getRecentBlockhash('finalized');
    const recentBlockhash = blockhashObj.blockhash;

    // Creating a transaction. Currently for simplicity purpose it is system create account.
    // But it could be any type of transaction.
    const transaction = new web3.Transaction({
        feePayer: feePayerPubkey,
        recentBlockhash
    }).add(
        web3.SystemProgram.createAccount({
            fromPubkey: accountFromPubkey,
            newAccountPubkey: newAccountKey.publicKey,
            lamports: web3.LAMPORTS_PER_SOL,
            space: 300,
            programId: programIdKey.publicKey
        })
    );

    // We are partially signing it here, as vault only sign
    // on fee payer and user's behalf. We will have to provide
    // additional signatures if required to the vault.
    transaction.partialSign({
        publicKey: newAccountKey.publicKey,
        secretKey: newAccountKey.secretKey
    });

    // Get the underlying message, serialize it to bytes and encode it to base64
    const message = transaction.compileMessage().serialize().toString('base64');

    console.log('Sending data over to vault for signing');

    // Preparing vault request body.
    // Here the `msg_payload` field refer to the base64 serialized message.
    // additional signature refers to an array of key value pairs
    // with key being pubkey and value being its signature.
    const vaultRequestBody = {
        msg_payload: message,
        additional_signatures: []
    };

    // Gathering additional signatures and putting it in request body.
    for (const sig of transaction.signatures) {
        if (sig.signature != null) {
            const signature = bs58.encode(new Uint8Array(sig.signature));
            const pubKey = sig.publicKey.toBase58();

            vaultRequestBody.additional_signatures.push({
                [pubKey]: signature
            });
        }
    }

    // POSTing to the sign endpoint of solana plugin
    // Authorization: Bearer vault token issued to the user by vault JWT plugin.
    // If the message and signature is valid, it will give *whole* tx serialized and
    // encoded as base64.
    const signOptions = createOptionForVault(
        'POST',
        '/v1/vault-plugin-secrets-solana/sign'
    );

    out = await req(signOptions, vaultRequestBody);
    jsonResponse = JSON.parse(out.body);

    console.log('Got signed tx from vault');
    console.log('Sending tx to the blockchain');

    // We take above serialized message and feed it into vault plugin, below is the output:

    const txBuffer = Buffer.from(jsonResponse.data.signed_tx.signed_tx, 'base64');

    // We are sending it after decoding from base64.
    const signature = await web3.sendAndConfirmRawTransaction(
        connection,
        txBuffer
    );
    console.log('SIGNATURE', signature);
};

run();