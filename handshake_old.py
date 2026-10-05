import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa

PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_IDENTIFIER = b"ffdhe3072"

ROLE_GATEWAY = b"gateway"
ROLE_NODE = b"node"

KDF_LABEL = b"CSCE465-KDF-v1"

DH_WIDTH = 384       # 3072 / 8
NONCE_WIDTH = 16

GATEWAY_ID = "gateway-01"
NODE_ID = "node-01"


def generate_rsa_signing_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,


#gateway_rsa_private = generate_rsa_signing_key()
#node_rsa_private = generate_rsa_signing_key()

#gateway_rsa_public = gateway_rsa_private.public_key()
#node_rsa_public = node_rsa_private.public_key()

def save_private_key(private_key, filename: str):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    Path(filename).write_bytes(pem)

def save_public_key(public_key, filename: str):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(filename).write_bytes(pem)

def load_private_key(filename: str):
    return serialization.load_pem_private_key(
        Path(filename).read_bytes(),
        password=None,
    )


def load_public_key(filename: str):
    return serialization.load_pem_public_key(
        Path(filename).read_bytes()
    )

def load_or_create_rsa_keypair(owner: str):
    private_file = Path(f"{owner}_rsa_private.pem")
    public_file = Path(f"{owner}_rsa_public.pem")

    if private_file.exists() and public_file.exists():
        private_key = load_private_key(str(private_file))
        public_key = load_public_key(str(public_file))
        return private_key, public_key

    private_key = generate_rsa_signing_key()
    public_key = private_key.public_key()

    save_private_key(private_key, str(private_file))
    save_public_key(public_key, str(public_file))

    return private_key, public_key


## gateway_rsa_private, gateway_rsa_public = load_or_create_rsa_keypair(
#    "gateway"
#)

#node_rsa_private, node_rsa_public = load_or_create_rsa_keypair(
#    "node"
#)

def load_ffdhe3072_parameters(filename: str):
    pem_data = Path(filename).read_bytes()

    try:
        parameters = serialization.load_pem_parameters(pem_data)
    except ValueError as exc:
        raise ValueError("Could not load DH parameters from PEM file") from exc

    if not isinstance(parameters, dh.DHParameters):
        raise ValueError("PEM file does not contain DH parameters")

    parameter_numbers = parameters.parameter_numbers()
    p = parameter_numbers.p
    g = parameter_numbers.g

    if p.bit_length() != 3072:
        raise ValueError("Expected a 3072-bit DH modulus")

    if g != 2:
        raise ValueError("Expected ffdhe3072 generator g = 2")

    return parameters, p, g

def int_to_384_bytes(value: int) -> bytes:
    if value < 0:
        raise ValueError("Negative DH integer is invalid")

    if value >= (1 << 3072):
        raise ValueError("DH integer does not fit 384-byte encoding")

    return value.to_bytes(DH_WIDTH, "big")
def generate_ephemeral_dh_keypair(parameters):
    private_key = parameters.generate_private_key()

    public_y = private_key.public_key().public_numbers().y
    public_bytes = int_to_384_bytes(public_y)

    return private_key, public_bytes
def generate_nonce() -> bytes:
    return os.urandom(NONCE_WIDTH)

gateway_dh_private, gateway_dh_public = generate_ephemeral_dh_keypair(
    dh_parameters
)
gateway_nonce = generate_nonce()

node_dh_private, node_dh_public = generate_ephemeral_dh_keypair(
    dh_parameters
)
node_nonce = generate_nonce()

def main():
    dh_parameters, p, g = load_ffdhe3072_parameters(
        "ffdhe3072.pem"
    )

    gateway_dh_private, gateway_dh_public = generate_ephemeral_keypair(
        dh_parameters
    )

    node_dh_private, node_dh_public = generate_ephemeral_keypair(
        dh_parameters
    )

    print("Gateway DH public length:", len(gateway_dh_public))
    print("Node DH public length:", len(node_dh_public))

    assert len(gateway_dh_public) == 384
    assert len(node_dh_public) == 384
