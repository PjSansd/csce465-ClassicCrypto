#!/usr/bin/env python3

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa


# ---------------------------------------------------------------------
# Protocol constants required by the assignment
# ---------------------------------------------------------------------

PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_IDENTIFIER = b"ffdhe3072"

ROLE_GATEWAY = b"gateway"
ROLE_NODE = b"node"

KDF_LABEL = b"CSCE465-KDF-v1"

GATEWAY_ID = "gateway-01"
NODE_ID = "node-01"

DH_WIDTH = 384          # ffdhe3072: 3072 bits / 8 = 384 bytes
NONCE_WIDTH = 16        # Assignment requirement


# ---------------------------------------------------------------------
# Exceptions and data containers
# ---------------------------------------------------------------------

class HandshakeError(Exception):
    """Raised when any handshake validation or verification fails."""


@dataclass(frozen=True)
class SessionKeys:
    transcript_hash: bytes
    k_master: bytes
    k_g2n_enc: bytes
    k_g2n_mac: bytes
    k_n2g_enc: bytes
    k_n2g_mac: bytes
    session_id: bytes


# ---------------------------------------------------------------------
# RSA long-term signing keys
# ---------------------------------------------------------------------

def generate_rsa_signing_key():
    """Generate a 3072-bit RSA private signing key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )


def save_private_key(private_key, filename: str):
    """
    Save private key in PEM format.

    For homework-only local files, NoEncryption is convenient.
    Production systems should encrypt private keys and restrict permissions.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    Path(filename).write_bytes(pem)


def load_private_key(filename: str):
    """Load a PEM RSA private key."""
    try:
        private_key = serialization.load_pem_private_key(
            Path(filename).read_bytes(),
            password=None,
        )
    except (OSError, ValueError, TypeError) as exc:
        raise HandshakeError(
            f"Could not load private key {filename}"
        ) from exc

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise HandshakeError(f"{filename} is not an RSA private key")

    if private_key.key_size != 3072:
        raise HandshakeError(f"{filename} is not a 3072-bit RSA key")

    return private_key


def load_or_create_rsa_key(owner: str):
    """
    Create a key only if it does not already exist, so it behaves as a
    long-term key across repeated script executions.
    """
    filename = Path(f"{owner}_rsa_private.pem")

    if filename.exists():
        private_key = load_private_key(str(filename))
    else:
        private_key = generate_rsa_signing_key()
        save_private_key(private_key, str(filename))

    return private_key, private_key.public_key()


# ---------------------------------------------------------------------
# ffdhe3072 parameter loading
# ---------------------------------------------------------------------

def load_ffdhe3072_parameters(filename: str):
    """
    Load OpenSSL-generated ffdhe3072 DH parameters from ffdhe3072.pem.
    Validate that the loaded parameter set is the expected 3072-bit group.
    """
    try:
        pem_data = Path(filename).read_bytes()
    except OSError as exc:
        raise HandshakeError(
            f"Cannot read DH parameter file: {filename}"
        ) from exc

    try:
        parameters = serialization.load_pem_parameters(pem_data)
    except ValueError as exc:
        raise HandshakeError(
            "Unable to load PEM DH parameters"
        ) from exc

    if not isinstance(parameters, dh.DHParameters):
        raise HandshakeError("Parameter PEM does not contain DH parameters")

    numbers = parameters.parameter_numbers()
    p = numbers.p
    g = numbers.g

    if p.bit_length() != 3072:
        raise HandshakeError(
            "Expected a 3072-bit ffdhe3072 modulus"
        )

    if g != 2:
        raise HandshakeError(
            "Expected ffdhe3072 generator g = 2"
        )

    return parameters, p, g


# ---------------------------------------------------------------------
# DH value generation, encoding, and validation
# ---------------------------------------------------------------------

def int_to_384_bytes(value: int) -> bytes:
    """
    Required encoding for ffdhe3072 public values and Z:
    exactly 384 big-endian bytes, zero-padded on the left.
    """
    if value < 0:
        raise HandshakeError("Cannot encode a negative integer")

    if value >= (1 << 3072):
        raise HandshakeError("Integer does not fit into 384 bytes")

    return value.to_bytes(DH_WIDTH, "big")


def generate_ephemeral_dh_keypair(parameters):
    """
    Generate a fresh per-session finite-field DH private key and public
    value. The library performs the DH arithmetic.
    """
    private_key = parameters.generate_private_key()

    public_y = private_key.public_key().public_numbers().y
    public_bytes = int_to_384_bytes(public_y)

    if len(public_bytes) != DH_WIDTH:
        raise HandshakeError("DH public value was not 384 bytes")

    return private_key, public_bytes


def generate_nonce() -> bytes:
    """Generate a fresh 16-byte random nonce."""
    return os.urandom(NONCE_WIDTH)


def validate_peer_dh_public(peer_public: bytes, p: int) -> int:
    """
    Check width and reject clearly invalid finite-field public values.
    """
    if len(peer_public) != DH_WIDTH:
        raise HandshakeError(
            "Peer DH public value must be exactly 384 bytes"
        )

    y = int.from_bytes(peer_public, "big")

    if not (1 < y < p - 1):
        raise HandshakeError(
            "Peer DH public value is outside allowed range"
        )

    return y


def peer_dh_public_key_from_bytes(
    peer_public: bytes,
    p: int,
    g: int,
):
    """
    Rebuild a cryptography DH public key from a validated 384-byte public
    value. Library code performs the actual DH operation later.
    """
    y = validate_peer_dh_public(peer_public, p)

    try:
        parameter_numbers = dh.DHParameterNumbers(p, g)
        public_numbers = dh.DHPublicNumbers(y, parameter_numbers)
        return public_numbers.public_key()
    except ValueError as exc:
        raise HandshakeError("Invalid peer DH public key") from exc


def compute_dh_shared_secret(
    local_private_key,
    peer_public: bytes,
    p: int,
    g: int,
) -> bytes:
    """
    Compute Z using the library, then encode it as required:
    exactly 384-byte big-endian representation.
    """
    peer_public_key = peer_dh_public_key_from_bytes(
        peer_public,
        p,
        g,
    )

    try:
        raw_secret = local_private_key.exchange(peer_public_key)
    except ValueError as exc:
        raise HandshakeError("DH key exchange failed") from exc

    z_integer = int.from_bytes(raw_secret, "big")
    z = int_to_384_bytes(z_integer)

    if len(z) != DH_WIDTH:
        raise HandshakeError("Shared secret Z was not 384 bytes")

    return z


# ---------------------------------------------------------------------
# Canonical transcript: 4-byte length-prefixed fields
# ---------------------------------------------------------------------

def encode_field(field: bytes) -> bytes:
    """
    Encode one transcript field as:
        4-byte big-endian field length || field
    """
    if not isinstance(field, bytes):
        raise HandshakeError("Transcript field must be bytes")

    if len(field) > 0xFFFFFFFF:
        raise HandshakeError("Transcript field is too large")

    return len(field).to_bytes(4, "big") + field


def build_transcript(
    gateway_id: str,
    node_id: str,
    gateway_public: bytes,
    node_public: bytes,
    gateway_nonce: bytes,
    node_nonce: bytes,
) -> bytes:
    """
    Required canonical field order:
      1. Protocol label
      2. Group identifier
      3. Gateway identity
      4. Node identity
      5. Gateway DH public value
      6. Node DH public value
      7. Gateway nonce
      8. Node nonce
    """
    if len(gateway_public) != DH_WIDTH:
        raise HandshakeError("Gateway DH public value must be 384 bytes")

    if len(node_public) != DH_WIDTH:
        raise HandshakeError("Node DH public value must be 384 bytes")

    if len(gateway_nonce) != NONCE_WIDTH:
        raise HandshakeError("Gateway nonce must be 16 bytes")

    if len(node_nonce) != NONCE_WIDTH:
        raise HandshakeError("Node nonce must be 16 bytes")

    fields = [
        PROTOCOL_LABEL,
        GROUP_IDENTIFIER,
        gateway_id.encode("utf-8"),
        node_id.encode("utf-8"),
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ]

    return b"".join(encode_field(field) for field in fields)


def parse_transcript(transcript: bytes) -> list[bytes]:
    """
    Parse exactly eight length-prefixed fields. Reject malformed length
    declarations, truncated data, and trailing bytes before hashing.
    """
    if not isinstance(transcript, bytes):
        raise HandshakeError("Transcript must be bytes")

    fields = []
    offset = 0

    for _ in range(8):
        if offset + 4 > len(transcript):
            raise HandshakeError(
                "Malformed transcript: missing field length"
            )

        declared_length = int.from_bytes(
            transcript[offset:offset + 4],
            "big",
        )
        offset += 4

        remaining = len(transcript) - offset

        if declared_length > remaining:
            raise HandshakeError(
                "Malformed transcript: declared length exceeds input"
            )

        field = transcript[offset:offset + declared_length]
        fields.append(field)
        offset += declared_length

    if offset != len(transcript):
        raise HandshakeError(
            "Malformed transcript: trailing bytes found"
        )

    return fields


def validate_transcript(transcript: bytes) -> dict:
    """
    Parse and validate all canonical transcript requirements before hashing,
    signing, verifying, or deriving keys.
    """
    fields = parse_transcript(transcript)

    (
        protocol_label,
        group_identifier,
        gateway_id_bytes,
        node_id_bytes,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ) = fields

    if protocol_label != PROTOCOL_LABEL:
        raise HandshakeError("Unexpected protocol label")

    if group_identifier != GROUP_IDENTIFIER:
        raise HandshakeError("Unexpected group identifier")

    if len(gateway_public) != DH_WIDTH:
        raise HandshakeError(
            "Gateway DH public value has invalid width"
        )

    if len(node_public) != DH_WIDTH:
        raise HandshakeError(
            "Node DH public value has invalid width"
        )

    if len(gateway_nonce) != NONCE_WIDTH:
        raise HandshakeError("Gateway nonce has invalid width")

    if len(node_nonce) != NONCE_WIDTH:
        raise HandshakeError("Node nonce has invalid width")

    try:
        gateway_id = gateway_id_bytes.decode("utf-8")
        node_id = node_id_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HandshakeError(
            "Transcript identity is not valid UTF-8"
        ) from exc

    return {
        "gateway_id": gateway_id,
        "node_id": node_id,
        "gateway_public": gateway_public,
        "node_public": node_public,
        "gateway_nonce": gateway_nonce,
        "node_nonce": node_nonce,
    }


# ---------------------------------------------------------------------
# RSA-PSS signatures: role || SHA-256(transcript)
# ---------------------------------------------------------------------

def transcript_hash(transcript: bytes) -> bytes:
    """Validate first, then compute TH = SHA-256(transcript)."""
    validate_transcript(transcript)
    return hashlib.sha256(transcript).digest()


def sign_transcript(private_key, role: bytes, transcript: bytes) -> bytes:
    """
    Assignment signature input:
        role || SHA-256(transcript)
    RSA-PSS uses SHA-256 and MGF1(SHA-256).
    """
    if role not in (ROLE_GATEWAY, ROLE_NODE):
        raise HandshakeError("Invalid signing role")

    th = transcript_hash(transcript)
    signed_message = role + th

    return private_key.sign(
        signed_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_transcript_signature(
    trusted_peer_public_key,
    expected_role: bytes,
    transcript: bytes,
    signature: bytes,
):
    """
    Verify a peer signature with the peer's already-configured public key
    and the expected peer role.
    """
    if expected_role not in (ROLE_GATEWAY, ROLE_NODE):
        raise HandshakeError("Invalid expected role")

    th = transcript_hash(transcript)
    signed_message = expected_role + th

    try:
        trusted_peer_public_key.verify(
            signature,
            signed_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise HandshakeError(
            "RSA-PSS signature verification failed"
        ) from exc


# ---------------------------------------------------------------------
# Assignment-specific KDF
# ---------------------------------------------------------------------

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def derive_session_keys(z: bytes, transcript: bytes) -> SessionKeys:
    """
    Exact assignment derivation:

    TH = SHA-256(transcript)

    K_master = SHA-256("CSCE465-KDF-v1" || Z || TH)

    K_g2n_enc = HMAC-SHA-256(K_master,
        "gateway-to-node encryption" || TH)

    K_g2n_mac = HMAC-SHA-256(K_master,
        "gateway-to-node MAC" || TH)

    K_n2g_enc = HMAC-SHA-256(K_master,
        "node-to-gateway encryption" || TH)

    K_n2g_mac = HMAC-SHA-256(K_master,
        "node-to-gateway MAC" || TH)

    session_id = first 8 bytes of HMAC-SHA-256(K_master,
        "session identifier" || TH)
    """
    if len(z) != DH_WIDTH:
        raise HandshakeError(
            "Shared secret Z must be exactly 384 bytes"
        )

    th = transcript_hash(transcript)

    k_master = hashlib.sha256(
        KDF_LABEL + z + th
    ).digest()

    k_g2n_enc = hmac_sha256(
        k_master,
        b"gateway-to-node encryption" + th,
    )

    k_g2n_mac = hmac_sha256(
        k_master,
        b"gateway-to-node MAC" + th,
    )

    k_n2g_enc = hmac_sha256(
        k_master,
        b"node-to-gateway encryption" + th,
    )

    k_n2g_mac = hmac_sha256(
        k_master,
        b"node-to-gateway MAC" + th,
    )

    session_id = hmac_sha256(
        k_master,
        b"session identifier" + th,
    )[:8]

    return SessionKeys(
        transcript_hash=th,
        k_master=k_master,
        k_g2n_enc=k_g2n_enc,
        k_g2n_mac=k_g2n_mac,
        k_n2g_enc=k_n2g_enc,
        k_n2g_mac=k_n2g_mac,
        session_id=session_id,
    )


# ---------------------------------------------------------------------
# Endpoint validation helpers
# ---------------------------------------------------------------------

def gateway_validate_node_response(
    transcript: bytes,
    expected_gateway_public: bytes,
    expected_gateway_nonce: bytes,
    p: int,
):
    """
    Gateway checks that the node's response refers to this current
    gateway-initiated session, rather than a changed/reflected/replayed one.
    """
    parsed = validate_transcript(transcript)

    if parsed["gateway_id"] != GATEWAY_ID:
        raise HandshakeError("Unexpected gateway identity")

    if parsed["node_id"] != NODE_ID:
        raise HandshakeError("Unexpected node identity")

    if parsed["gateway_public"] != expected_gateway_public:
        raise HandshakeError(
            "Gateway DH public value changed or reflected"
        )

    if parsed["gateway_nonce"] != expected_gateway_nonce:
        raise HandshakeError(
            "Gateway nonce changed or replayed"
        )

    validate_peer_dh_public(parsed["node_public"], p)

    return parsed


def node_validate_gateway_confirmation(
    transcript: bytes,
    original_transcript: bytes,
):
    """
    Node rejects a confirmation that does not refer to the exact transcript
    it created. Byte-for-byte equality also prevents changed nonce/value,
    replay, and transcript substitution.
    """
    validate_transcript(transcript)

    if transcript != original_transcript:
        raise HandshakeError(
            "Gateway confirmation has a different transcript"
        )


# ---------------------------------------------------------------------
# Full local in-process handshake
# ---------------------------------------------------------------------

def run_handshake():
    """
    Three-message local handshake:

      1. Gateway creates fresh ephemeral DH value and fresh nonce.
      2. Node creates fresh values, builds final transcript, signs as node.
      3. Gateway validates/signs final transcript; node validates gateway
         confirmation. Both derive identical session keys.

    Python dictionaries stand in for network packets.
    """

    # Load standard public ffdhe3072 group parameters.
    dh_parameters, p, g = load_ffdhe3072_parameters(
        "ffdhe3072.pem"
    )

    # Load/create long-term RSA signing keys.
    gateway_rsa_private, gateway_rsa_public = load_or_create_rsa_key(
        "gateway"
    )
    node_rsa_private, node_rsa_public = load_or_create_rsa_key(
        "node"
    )

    # -----------------------------------------------------------------
    # Message 1: Gateway -> Node
    # -----------------------------------------------------------------
    gateway_dh_private, gateway_dh_public = generate_ephemeral_dh_keypair(
        dh_parameters
    )
    gateway_nonce = generate_nonce()

    gateway_offer = {
        "gateway_id": GATEWAY_ID,
        "node_id": NODE_ID,
        "gateway_public": gateway_dh_public,
        "gateway_nonce": gateway_nonce,
    }

    # -----------------------------------------------------------------
    # Node receives Message 1 and validates basic received fields.
    # -----------------------------------------------------------------
    if gateway_offer["gateway_id"] != GATEWAY_ID:
        raise HandshakeError("Node rejected unexpected gateway identity")

    if gateway_offer["node_id"] != NODE_ID:
        raise HandshakeError("Node rejected message for another node")

    validate_peer_dh_public(gateway_offer["gateway_public"], p)

    if len(gateway_offer["gateway_nonce"]) != NONCE_WIDTH:
        raise HandshakeError("Node rejected malformed gateway nonce")

    # -----------------------------------------------------------------
    # Message 2: Node -> Gateway
    # -----------------------------------------------------------------
    node_dh_private, node_dh_public = generate_ephemeral_dh_keypair(
        dh_parameters
    )
    node_nonce = generate_nonce()

    transcript = build_transcript(
        GATEWAY_ID,
        NODE_ID,
        gateway_offer["gateway_public"],
        node_dh_public,
        gateway_offer["gateway_nonce"],
        node_nonce,
    )

    # Node signs: ROLE_NODE || SHA-256(transcript).
    node_signature = sign_transcript(
        node_rsa_private,
        ROLE_NODE,
        transcript,
    )

    node_response = {
        "transcript": transcript,
        "signature": node_signature,
    }

    # -----------------------------------------------------------------
    # Gateway receives Message 2 and validates node authentication.
    # -----------------------------------------------------------------
    parsed = gateway_validate_node_response(
        node_response["transcript"],
        gateway_dh_public,
        gateway_nonce,
        p,
    )

    verify_transcript_signature(
        node_rsa_public,
        ROLE_NODE,
        node_response["transcript"],
        node_response["signature"],
    )

    # Gateway derives shared secret and session keys.
    z_gateway = compute_dh_shared_secret(
        gateway_dh_private,
        parsed["node_public"],
        p,
        g,
    )

    gateway_keys = derive_session_keys(
        z_gateway,
        node_response["transcript"],
    )

    # -----------------------------------------------------------------
    # Message 3: Gateway -> Node
    # -----------------------------------------------------------------
    # Gateway signs the exact same final transcript.
    gateway_signature = sign_transcript(
        gateway_rsa_private,
        ROLE_GATEWAY,
        node_response["transcript"],
    )

    gateway_confirmation = {
        "transcript": node_response["transcript"],
        "signature": gateway_signature,
    }

    # -----------------------------------------------------------------
    # Node receives Message 3 and validates gateway authentication.
    # -----------------------------------------------------------------
    node_validate_gateway_confirmation(
        gateway_confirmation["transcript"],
        transcript,
    )

    verify_transcript_signature(
        gateway_rsa_public,
        ROLE_GATEWAY,
        gateway_confirmation["transcript"],
        gateway_confirmation["signature"],
    )

    # Node derives its shared secret and session keys.
    z_node = compute_dh_shared_secret(
        node_dh_private,
        gateway_dh_public,
        p,
        g,
    )

    node_keys = derive_session_keys(z_node, transcript)

    # Both endpoints must derive identical secrets and session material.
    if gateway_keys != node_keys:
        raise HandshakeError(
            "Gateway and node derived different session keys"
        )

    print("Handshake accepted.")
    print("Gateway identity:", GATEWAY_ID)
    print("Node identity:", NODE_ID)
    print("Transcript hash:", gateway_keys.transcript_hash.hex())
    print("Session ID:", gateway_keys.session_id.hex())

    return {
        "transcript": transcript,
        "node_signature": node_signature,
        "gateway_signature": gateway_signature,
        "gateway_rsa_public": gateway_rsa_public,
        "node_rsa_public": node_rsa_public,
        "gateway_keys": gateway_keys,
        "node_keys": node_keys,
    }


# ---------------------------------------------------------------------
# Required rejection tests
# ---------------------------------------------------------------------

def expect_rejection(description: str, function):
    """Print PASS only when the supplied operation is correctly rejected."""
    try:
        function()
    except HandshakeError:
        print(f"PASS: {description}")
        return

    raise AssertionError(f"FAIL: {description} was accepted")


def run_rejection_tests(result):
    """
    Demonstrate rejection of:
      - invalid signature
      - malformed transcript
      - reflected handshake signature
      - changed nonce/public value after signing
      - unexpected identity
    """
    transcript = result["transcript"]
    node_signature = result["node_signature"]
    gateway_signature = result["gateway_signature"]
    node_rsa_public = result["node_rsa_public"]
    gateway_rsa_public = result["gateway_rsa_public"]

    # ---------------------------------------------------------------
    # Invalid signature: alter one signature bit.
    # ---------------------------------------------------------------
    bad_signature = bytearray(node_signature)
    bad_signature[0] ^= 0x01

    expect_rejection(
        "invalid node signature rejected",
        lambda: verify_transcript_signature(
            node_rsa_public,
            ROLE_NODE,
            transcript,
            bytes(bad_signature),
        ),
    )

    # ---------------------------------------------------------------
    # Malformed transcript: declare first field to be longer than input.
    # parse/validate must reject this before hashing.
    # ---------------------------------------------------------------
    malformed = bytearray(transcript)
    malformed[0:4] = (999999).to_bytes(4, "big")

    expect_rejection(
        "malformed length-prefixed transcript rejected before hashing",
        lambda: validate_transcript(bytes(malformed)),
    )

    # ---------------------------------------------------------------
    # Reflection: verify a gateway signature as though it came from node.
    # This fails due to both expected key and role distinction.
    # ---------------------------------------------------------------
    expect_rejection(
        "reflected gateway signature rejected as node signature",
        lambda: verify_transcript_signature(
            gateway_rsa_public,
            ROLE_NODE,
            transcript,
            gateway_signature,
        ),
    )

    # ---------------------------------------------------------------
    # Changed nonce: flip a byte in the last byte of transcript.
    # The final node nonce is the last field, so this changes it.
    # The original signature cannot verify.
    # ---------------------------------------------------------------
    changed_nonce = bytearray(transcript)
    changed_nonce[-1] ^= 0x01

    expect_rejection(
        "changed nonce rejected by signature verification",
        lambda: verify_transcript_signature(
            node_rsa_public,
            ROLE_NODE,
            bytes(changed_nonce),
            node_signature,
        ),
    )

    # ---------------------------------------------------------------
    # Changed node DH public value: locate fields, rebuild transcript
    # with a modified node public value, then attempt signature verification.
    # ---------------------------------------------------------------
    parsed = validate_transcript(transcript)

    modified_node_public = bytearray(parsed["node_public"])
    modified_node_public[-1] ^= 0x01

    changed_public_transcript = build_transcript(
        parsed["gateway_id"],
        parsed["node_id"],
        parsed["gateway_public"],
        bytes(modified_node_public),
        parsed["gateway_nonce"],
        parsed["node_nonce"],
    )

    expect_rejection(
        "changed node DH public value rejected by signature verification",
        lambda: verify_transcript_signature(
            node_rsa_public,
            ROLE_NODE,
            changed_public_transcript,
            node_signature,
        ),
    )

    # ---------------------------------------------------------------
    # Unexpected identity: rebuild transcript with a wrong node identity.
    # This technically remains well-formed but is not accepted as a valid
    # handshake for the configured node.
    # ---------------------------------------------------------------
    wrong_identity_transcript = build_transcript(
        parsed["gateway_id"],
        "attacker-node",
        parsed["gateway_public"],
        parsed["node_public"],
        parsed["gateway_nonce"],
        parsed["node_nonce"],
    )

    def reject_wrong_identity():
        wrong = validate_transcript(wrong_identity_transcript)

        if wrong["gateway_id"] != GATEWAY_ID:
            raise HandshakeError("Unexpected gateway identity")

        if wrong["node_id"] != NODE_ID:
            raise HandshakeError("Unexpected node identity")

    expect_rejection(
        "unexpected peer identity rejected",
        reject_wrong_identity,
    )


def main():
    result = run_handshake()

    print()
    print("Running rejection tests...")
    run_rejection_tests(result)

    print()
    print("All required handshake checks completed.")


if __name__ == "__main__":
    main()
