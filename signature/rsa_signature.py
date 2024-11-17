################################################################################
# Sign/verify RSA signature                                                    #
################################################################################

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

import hashlib

# Generate private and public keys
def generate_key_pair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return private_key, public_key

# Save private and public keys
def save_key_pair(private_key, public_key):
    # Save private key (PEM format)
    with open("rsa_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key (PEM format)
    with open("rsa_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Load private key
def load_private_key():
    with open("rsa_private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), 
                                                         password=None)

    return private_key

# Load public key
def load_public_key():
    with open("rsa_public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return public_key

# Sign message
def sign_message(private_key, message, padding_inst, algorithm):
    signature = private_key.sign(
        message,
        padding_inst,
        algorithm
    )

    return signature

# Save signature
def save_signature(signature):
    with open("rsa_signature.bin", "wb") as f:
        f.write(signature)

# Load signature
def load_signature():
    with open("rsa_signature.bin", "rb") as f:
        signature = f.read()

    return signature

# Verify signature
def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# 1. Generate RSA key pair
private_key, public_key = generate_key_pair()

# 2. Save RSA key pair
save_key_pair(private_key, public_key)

# 3. Message to be signed
message = b"This is the message to be signed."

# 4. Sign message
private_key = load_private_key()
padding_inst = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
algorithm = hashes.SHA256()
signature = sign_message(private_key, message, padding_inst, algorithm)
save_signature(signature)

# 5. Verify signature
signature = load_signature()
public_key = load_public_key()
is_valid = verify_signature(message, 
                            signature, 
                            public_key)

# 6. Print results
print('** Signature (algorithm: RSA) **')
print(f'Byte size: {len(signature)}')
print(f"Hex string: {signature.hex()}")
print(f"Is valid: {is_valid}")

# 7. Cross-check
print('\n** Cross-check **')

# 7.1. Using hashlib
m = hashlib.sha256()
m.update(message)
print('* SHA-256 hash of the original message by hashlib library (hex string):')
print(m.hexdigest())

# 7.2. Recover data from signature using PKCS1v15 padding
# (PKCS1v15 not recommended for new applications)
padding_inst = padding.PKCS1v15()
signature = sign_message(private_key, message, padding_inst, algorithm)
data = public_key.recover_data_from_signature(signature, padding_inst, algorithm)
print('* SHA-256 hash recovered from the signature by cryptography library (hex string):')
print(data.hex())

# 7.3. Sign prehashed data
padding_inst = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
prehashed = utils.Prehashed(hashes.SHA256())
signature = sign_message(private_key, m.digest(), padding_inst, prehashed)
is_valid = verify_signature(message, 
                            signature, 
                            public_key)
print('* Sign prehashed data and verify signature')
print(f'Is valid: {is_valid}')
