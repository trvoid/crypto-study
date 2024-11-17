################################################################################
# Sign/verify EcDSA signature using ecdsa module                               #
################################################################################

from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Save EcDSA key pair
def save_key_pair(sk, vk):
    # Save signing key (PEM format)
    with open("ecdsa_sk_using_ecdsa.pem", "wb") as f:
        f.write(sk.to_pem())

    # Save verifying key (PEM format)
    with open("ecdsa_vk_using_ecdsa.pem", "wb") as f:
        f.write(vk.to_pem())

# Load signing key
def load_sk():
    with open("ecdsa_sk_using_ecdsa.pem", "rb") as f:
        sk = SigningKey.from_pem(f.read())

    return sk

# Load verifying key
def load_vk():
    with open("ecdsa_vk_using_ecdsa.pem", "rb") as f:
        vk = VerifyingKey.from_pem(f.read())

    return vk

# Save signature
def save_signature(signature):
    with open("ecdsa_signature_using_ecdsa.bin", "wb") as f:
        f.write(signature)

# Load signature
def load_signature():
    with open("ecdsa_signature_using_ecdsa.bin", "rb") as f:
        signature = f.read()

    return signature

# 1. Generate EcDSA key pair
sk = SigningKey.generate(curve=SECP256k1)
vk = sk.verifying_key

# 2. Save EcDSA key pair
save_key_pair(sk, vk)

# 3. Message to be signed
message = b"This is the message to be signed."

# 4. Sign message
sk = load_sk()
signature = sk.sign(message)
save_signature(signature)

# 5. Verify signature
signature = load_signature()
vk = load_vk()
try:
    vk.verify(signature, message)
    print('Is valid: True')
except:
    print('Is valid: False')
