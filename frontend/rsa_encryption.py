from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def prepare_rsa_key(public_key_pem: str) -> tuple[bytes, bytes]:
    session_key = AESGCM.generate_key(bit_length=256)

    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))

    aad_component = public_key.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key, aad_component
