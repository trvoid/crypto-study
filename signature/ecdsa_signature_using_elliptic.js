//
// Sign/verify EcDSA signature using elliptic module
//

const EC = require('elliptic').ec;
const crypto = require('crypto');

// Elliptic curve secp256k1
const ec = new EC('secp256k1');

// 1. Generate EcDSA key pair
const key = ec.genKeyPair();

const privateKey = key.getPrivate('hex');
const publicKey = key.getPublic('hex');

// 2. Message to be signed
const message = "This is the message to be signed.";

// 3. Generate hash (SHA-256)
const msgHash = crypto.createHash('sha256').update(message).digest();
console.log("SHA-256 hash: " + msgHash.toString('hex'))

// 4. Sign message
const signature = key.sign(msgHash);

// 5. Convert signature into DER format
const derSignature = signature.toDER();

// 6. Verify signature
const isValid = ec.keyFromPublic(publicKey, 'hex').verify(msgHash, derSignature);

console.log("Private key:", privateKey);
console.log("Public key:", publicKey);
console.log("Signature (DER):", derSignature.toString('hex'));
console.log("Is valid:", isValid);
