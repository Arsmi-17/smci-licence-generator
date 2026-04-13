import base64
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_b = priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

pub_b = pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

enc_key = os.urandom(32)

print("LICENSE_PRIVATE_KEY_B64=", base64.b64encode(priv_b).decode("utf-8"))
print("LICENSE_PUBLIC_KEY_B64=", base64.b64encode(pub_b).decode("utf-8"))
print("LICENSE_ENC_KEY_B64=", base64.b64encode(enc_key).decode("utf-8"))
