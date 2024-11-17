################################################################################
# Sign/verify Ed25519 signature using cryptography module                      #
################################################################################

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils

def generate_key_pair():
    private_key = ec.generate_private_key(
        ec.SECP256K1()
        #ec.SECP256R1()
        #ec.SECP384R1()
    )

    public_key = private_key.public_key()

    return private_key, public_key
    
# Save EcDSA key pair
def save_key_pair(sk, vk):
    # Save signing key (PEM format)
    with open("ecdsa_sk_using_cryptography.pem", "wb") as f:
        f.write(sk.to_pem())

    # Save verifying key (PEM format)
    with open("ecdsa_vk_using_cryptography.pem", "wb") as f:
        f.write(vk.to_pem())

# Save signature
def save_signature(signature):
    with open("ecdsa_signature_using_cryptography.bin", "wb") as f:
        f.write(signature)

# Load signature
def load_signature():
    with open("ecdsa_signature_using_cryptography.bin", "rb") as f:
        signature = f.read()

    return signature

# 1. Generate EcDSA key pair
sk, vk = generate_key_pair()

# 2. Save EcDSA key pair
#save_key_pair(sk, vk)

# 3. Message to be signed
message = b"This is the message to be signed."

# 4. Sign message
#sk = load_sk()
signature = sk.sign(message, ec.ECDSA(hashes.SHA256()))
save_signature(signature)

# 5. Verify signature
print('** Signature (algorithm: EcDSA) **')
signature = load_signature()
#vk = load_vk()
try:
    vk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print('Is valid: True')
except:
    print('Is valid: False')

# 6. Verify with prehashed data
print('** Verify with prehashed data **')
chosen_hash = hashes.SHA256()
hasher = hashes.Hash(chosen_hash)
hasher.update(message)
digest = hasher.finalize()
print('* SHA-256 hash of the original message by hasher (hex string):')
print(digest.hex())

try:
    vk.verify(signature, digest, ec.ECDSA(utils.Prehashed(chosen_hash)))
    print('Is valid: True')
except:
    print('Is valid: False')
