#!/usr/bin/env python3
"""
secure_record.py

CSCE 465/765 Task 3:
Encrypt-then-MAC record layer using AES-256-CTR and HMAC-SHA-256.

Wire format:
    header || iv || ciphertext || tag

header:
    version(1 byte) ||
    direction(1 byte) ||
    sequence(8 bytes, big-endian) ||
    message_type(1 byte) ||
    ciphertext_length(4 bytes, big-endian)

iv:
    session_id(8 bytes) || sequence(8 bytes, big-endian)

ciphertext:
    AES-256-CTR(K_enc, iv, plaintext)

tag:
    HMAC-SHA-256(K_mac, header || iv || ciphertext)
"""

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------

VERSION = 1

# Direction values stored in the one-byte record header.
DIRECTION_GATEWAY_TO_NODE = 0x01
DIRECTION_NODE_TO_GATEWAY = 0x02

# Required record-field sizes.
HEADER_LENGTH = 15
IV_LENGTH = 16
TAG_LENGTH = 32

SESSION_ID_LENGTH = 8
AES256_KEY_LENGTH = 32
HMAC_SHA256_KEY_LENGTH = 32

MAX_SEQUENCE = (1 << 64) - 1
MAX_CIPHERTEXT_LENGTH = (1 << 32) - 1


# ---------------------------------------------------------------------
# Exceptions and sequence state
# ---------------------------------------------------------------------

class RecordError(Exception):
    """
    Raised for malformed records, invalid state, bad HMACs, unexpected
    sequence numbers, wrong directions, and other record-layer failures.

    No plaintext is returned when this exception is raised.
    """


@dataclass
class SenderState:
    """
    State for one sending direction.

    A new sender state begins at sequence number zero.
    Use one SenderState object per traffic direction.
    """
    next_sequence: int = 0


@dataclass
class ReceiverState:
    """
    State for one receiving direction.

    A new receiver state expects sequence number zero.
    Use one ReceiverState object per traffic direction.
    """
    expected_sequence: int = 0


# ---------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------

def _require_bytes(name: str, value):
    """Reject values that are not immutable Python bytes."""
    if not isinstance(value, bytes):
        raise RecordError(f"{name} must be bytes")


def _validate_session_id(session_id: bytes):
    """Task 2 session ID must be exactly 8 bytes."""
    _require_bytes("session_id", session_id)

    if len(session_id) != SESSION_ID_LENGTH:
        raise RecordError("session_id must be exactly 8 bytes")


def _validate_keys(k_enc: bytes, k_mac: bytes):
    """
    Validate directional session keys.

    AES-256 requires a 32-byte encryption key.
    HMAC-SHA-256 accepts many key lengths, but Task 2 derives 32-byte keys,
    so require the expected 32-byte K_mac output.
    """
    _require_bytes("K_enc", k_enc)
    _require_bytes("K_mac", k_mac)

    if len(k_enc) != AES256_KEY_LENGTH:
        raise RecordError("K_enc must be exactly 32 bytes for AES-256")

    if len(k_mac) != HMAC_SHA256_KEY_LENGTH:
        raise RecordError("K_mac must be exactly 32 bytes")


def _validate_direction(direction: int):
    """Only the two protocol-defined direction values are permitted."""
    if not isinstance(direction, int):
        raise RecordError("direction must be an integer")

    if direction not in (
        DIRECTION_GATEWAY_TO_NODE,
        DIRECTION_NODE_TO_GATEWAY,
    ):
        raise RecordError("Invalid record direction")


def _validate_message_type(message_type: int):
    """The message type must fit in exactly one byte."""
    if not isinstance(message_type, int):
        raise RecordError("message_type must be an integer")

    if not 0 <= message_type <= 0xFF:
        raise RecordError("message_type must be between 0 and 255")


def _validate_sequence(sequence: int):
    """The sequence number must be an unsigned 64-bit integer."""
    if not isinstance(sequence, int):
        raise RecordError("sequence must be an integer")

    if not 0 <= sequence <= MAX_SEQUENCE:
        raise RecordError("sequence must fit in uint64")


# ---------------------------------------------------------------------
# Header and IV construction/parsing
# ---------------------------------------------------------------------

def _build_header(
    version: int,
    direction: int,
    sequence: int,
    message_type: int,
    ciphertext_length: int,
) -> bytes:
    """
    Create the required 15-byte header:

        version(1) || direction(1) || sequence(8) ||
        message_type(1) || ciphertext_length(4)
    """
    if version != VERSION:
        raise RecordError("Unsupported record version")

    _validate_direction(direction)
    _validate_sequence(sequence)
    _validate_message_type(message_type)

    if not isinstance(ciphertext_length, int):
        raise RecordError("ciphertext_length must be an integer")

    if not 0 <= ciphertext_length <= MAX_CIPHERTEXT_LENGTH:
        raise RecordError("ciphertext length must fit in uint32")

    header = (
        bytes([version])
        + bytes([direction])
        + sequence.to_bytes(8, "big")
        + bytes([message_type])
        + ciphertext_length.to_bytes(4, "big")
    )

    if len(header) != HEADER_LENGTH:
        raise RecordError("Internal error: header has wrong length")

    return header


def _parse_header(header: bytes) -> dict:
    """
    Parse and validate the 15-byte record header.

    Header offsets:
        byte 0:      version
        byte 1:      direction
        bytes 2..9:  sequence
        byte 10:     message type
        bytes 11..14 ciphertext length
    """
    _require_bytes("header", header)

    if len(header) != HEADER_LENGTH:
        raise RecordError("Header must be exactly 15 bytes")

    version = header[0]
    direction = header[1]
    sequence = int.from_bytes(header[2:10], "big")
    message_type = header[10]
    ciphertext_length = int.from_bytes(header[11:15], "big")

    if version != VERSION:
        raise RecordError("Unsupported record version")

    _validate_direction(direction)
    _validate_sequence(sequence)
    _validate_message_type(message_type)

    return {
        "version": version,
        "direction": direction,
        "sequence": sequence,
        "message_type": message_type,
        "ciphertext_length": ciphertext_length,
    }


def _build_iv(session_id: bytes, sequence: int) -> bytes:
    """
    Required CTR IV construction:

        iv = session_id(8 bytes) || sequence(8 bytes)

    The sequence number is unique per sender direction/key, so this creates
    a unique IV under that AES key for each record.
    """
    _validate_session_id(session_id)
    _validate_sequence(sequence)

    iv = session_id + sequence.to_bytes(8, "big")

    if len(iv) != IV_LENGTH:
        raise RecordError("Internal error: IV must be exactly 16 bytes")

    return iv


# ---------------------------------------------------------------------
# AES-256-CTR helpers
# ---------------------------------------------------------------------

def _aes_ctr_encrypt(k_enc: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt bytes with AES-256-CTR."""
    _require_bytes("plaintext", plaintext)

    cipher = Cipher(
        algorithms.AES(k_enc),
        modes.CTR(iv),
    )

    encryptor = cipher.encryptor()

    return encryptor.update(plaintext) + encryptor.finalize()


def _aes_ctr_decrypt(k_enc: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt bytes with AES-256-CTR.

    This helper must be called only after the HMAC has verified.
    """
    _require_bytes("ciphertext", ciphertext)

    cipher = Cipher(
        algorithms.AES(k_enc),
        modes.CTR(iv),
    )

    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------------------------------------------------------------------
# HMAC-SHA-256 helpers
# ---------------------------------------------------------------------

def _compute_tag(
    k_mac: bytes,
    header: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    """
    Compute the task-required tag:

        HMAC-SHA-256(K_mac, header || iv || ciphertext)
    """
    mac = hmac.HMAC(k_mac, hashes.SHA256())
    mac.update(header + iv + ciphertext)

    tag = mac.finalize()

    if len(tag) != TAG_LENGTH:
        raise RecordError("Internal error: HMAC-SHA-256 tag is not 32 bytes")

    return tag


def _verify_tag(
    k_mac: bytes,
    header: bytes,
    iv: bytes,
    ciphertext: bytes,
    received_tag: bytes,
):
    """
    Verify the record tag with cryptography's HMAC.verify() API.

    Do not replace this with:
        expected_tag == received_tag

    verify() performs the library MAC-verification path and raises
    InvalidSignature on failure.
    """
    _require_bytes("tag", received_tag)

    if len(received_tag) != TAG_LENGTH:
        raise RecordError("HMAC tag must be exactly 32 bytes")

    mac = hmac.HMAC(k_mac, hashes.SHA256())
    mac.update(header + iv + ciphertext)

    try:
        mac.verify(received_tag)
    except InvalidSignature as exc:
        raise RecordError("HMAC verification failed") from exc


# ---------------------------------------------------------------------
# Public API: seal()
# ---------------------------------------------------------------------

def seal(
    plaintext: bytes,
    message_type: int,
    direction: int,
    session_id: bytes,
    k_enc: bytes,
    k_mac: bytes,
    state: SenderState,
) -> bytes:
    """
    Encrypt and authenticate one application record.

    Inputs:
        plaintext:
            Bytes to protect.

        message_type:
            One-byte application-defined record type, 0 through 255.

        direction:
            DIRECTION_GATEWAY_TO_NODE or DIRECTION_NODE_TO_GATEWAY.

        session_id:
            Task 2's 8-byte session ID.

        k_enc:
            The matching 32-byte directional AES encryption key.

        k_mac:
            The matching 32-byte directional HMAC key.

        state:
            SenderState for this traffic direction.

    Output:
        header || iv || ciphertext || tag

    The state sequence begins at zero. It advances only after a record is
    successfully sealed, ensuring an IV is never reused with this key.
    """
    _require_bytes("plaintext", plaintext)
    _validate_session_id(session_id)
    _validate_keys(k_enc, k_mac)
    _validate_direction(direction)
    _validate_message_type(message_type)

    if not isinstance(state, SenderState):
        raise RecordError("state must be a SenderState")

    sequence = state.next_sequence
    _validate_sequence(sequence)

    if len(plaintext) > MAX_CIPHERTEXT_LENGTH:
        raise RecordError("Plaintext is too long")

    header = _build_header(
        version=VERSION,
        direction=direction,
        sequence=sequence,
        message_type=message_type,
        ciphertext_length=len(plaintext),
    )

    iv = _build_iv(session_id, sequence)

    ciphertext = _aes_ctr_encrypt(k_enc, iv, plaintext)

    if len(ciphertext) != len(plaintext):
        raise RecordError("AES-CTR produced an unexpected ciphertext length")

    tag = _compute_tag(
        k_mac,
        header,
        iv,
        ciphertext,
    )

    record = header + iv + ciphertext + tag

    if sequence == MAX_SEQUENCE:
        raise RecordError(
            "Sequence number exhausted; establish a new session before "
            "sending another record"
        )

    state.next_sequence += 1

    return record


# ---------------------------------------------------------------------
# Public API: open_record()
# ---------------------------------------------------------------------

def open_record(
    record: bytes,
    expected_direction: int,
    session_id: bytes,
    k_enc: bytes,
    k_mac: bytes,
    state: ReceiverState,
):
    """
    Verify and decrypt one received application record.

    Inputs:
        record:
            header || iv || ciphertext || tag

        expected_direction:
            The only direction this receiver accepts on this stream.

        session_id:
            The expected 8-byte Task 2 session ID.

        k_enc / k_mac:
            Directional receive keys matching expected_direction.

        state:
            ReceiverState for this inbound traffic direction.

    Returns:
        (message_type, plaintext)

    Security order:
        1. Parse and validate record structure/header.
        2. Require expected direction.
        3. Require the exact expected sequence number.
        4. Require expected IV = session_id || sequence.
        5. Verify HMAC(header || iv || ciphertext).
        6. Only then decrypt AES-CTR ciphertext.
        7. Advance the receiver sequence after successful processing.

    If any check fails, RecordError is raised and no plaintext is returned.
    """
    _require_bytes("record", record)
    _validate_session_id(session_id)
    _validate_keys(k_enc, k_mac)
    _validate_direction(expected_direction)

    if not isinstance(state, ReceiverState):
        raise RecordError("state must be a ReceiverState")

    minimum_length = HEADER_LENGTH + IV_LENGTH + TAG_LENGTH

    if len(record) < minimum_length:
        raise RecordError("Record is too short")

    # Parse the authenticated header.
    header = record[:HEADER_LENGTH]
    parsed = _parse_header(header)

    # Reject records addressed to the wrong traffic direction.
    if parsed["direction"] != expected_direction:
        raise RecordError("Record is in the wrong direction")

    # Reject replays, skipped sequence numbers, and out-of-order records.
    if parsed["sequence"] != state.expected_sequence:
        raise RecordError("Record sequence is not the expected next sequence")

    expected_record_length = (
        HEADER_LENGTH
        + IV_LENGTH
        + parsed["ciphertext_length"]
        + TAG_LENGTH
    )

    # Header length must agree exactly with supplied bytes.
    if len(record) != expected_record_length:
        raise RecordError("Record length does not match header length")

    iv_start = HEADER_LENGTH
    ciphertext_start = HEADER_LENGTH + IV_LENGTH
    ciphertext_end = ciphertext_start + parsed["ciphertext_length"]

    iv = record[iv_start:ciphertext_start]
    ciphertext = record[ciphertext_start:ciphertext_end]
    tag = record[ciphertext_end:]

    # The IV is deterministic and must match the negotiated session and
    # expected sequence number.
    expected_iv = _build_iv(session_id, parsed["sequence"])

    if iv != expected_iv:
        raise RecordError("Record IV does not match session ID and sequence")

    # Authenticate before decryption: Encrypt-then-MAC.
    _verify_tag(
        k_mac,
        header,
        iv,
        ciphertext,
        tag,
    )

    # The tag has verified, so ciphertext is authenticated and may be opened.
    plaintext = _aes_ctr_decrypt(k_enc, iv, ciphertext)

    if parsed["sequence"] == MAX_SEQUENCE:
        raise RecordError(
            "Sequence number exhausted; establish a new session before "
            "accepting another record"
        )

    # Advance only after every validation step and decryption succeeds.
    state.expected_sequence += 1

    return parsed["message_type"], plaintext


# ---------------------------------------------------------------------
# Optional local self-test
# ---------------------------------------------------------------------

def _self_test():
    """
    Run:
        python3 secure_record.py

    This uses deterministic test values only. In the real program, replace
    them with Task 2's session_id and direction-specific derived keys.
    """
    session_id = bytes.fromhex("0011223344556677")

    k_g2n_enc = bytes.fromhex("11" * 32)
    k_g2n_mac = bytes.fromhex("22" * 32)

    k_n2g_enc = bytes.fromhex("33" * 32)
    k_n2g_mac = bytes.fromhex("44" * 32)

    gateway_sender = SenderState()
    node_receiver = ReceiverState()

    plaintext = b'{"action":"READ","path":"notes.txt"}'

    record = seal(
        plaintext=plaintext,
        message_type=0x01,
        direction=DIRECTION_GATEWAY_TO_NODE,
        session_id=session_id,
        k_enc=k_g2n_enc,
        k_mac=k_g2n_mac,
        state=gateway_sender,
    )

    message_type, recovered = open_record(
        record=record,
        expected_direction=DIRECTION_GATEWAY_TO_NODE,
        session_id=session_id,
        k_enc=k_g2n_enc,
        k_mac=k_g2n_mac,
        state=node_receiver,
    )

    assert message_type == 0x01
    assert recovered == plaintext
    assert gateway_sender.next_sequence == 1
    assert node_receiver.expected_sequence == 1

    print("PASS: valid gateway-to-node record opened successfully")

    def must_reject(label, operation):
        try:
            operation()
        except RecordError:
            print(f"PASS: {label}")
        else:
            raise AssertionError(f"FAIL: accepted {label}")

    # Create a fresh sequence-zero record for independent rejection tests.
    test_sender = SenderState()
    test_record = seal(
        plaintext=b"test record",
        message_type=0x02,
        direction=DIRECTION_GATEWAY_TO_NODE,
        session_id=session_id,
        k_enc=k_g2n_enc,
        k_mac=k_g2n_mac,
        state=test_sender,
    )

    # Change a header byte: message_type is byte index 10.
    changed_header = bytearray(test_record)
    changed_header[10] ^= 0x01

    must_reject(
        "modified header",
        lambda: open_record(
            record=bytes(changed_header),
            expected_direction=DIRECTION_GATEWAY_TO_NODE,
            session_id=session_id,
            k_enc=k_g2n_enc,
            k_mac=k_g2n_mac,
            state=ReceiverState(),
        ),
    )

    # Change one ciphertext byte. Ciphertext begins at HEADER_LENGTH + IV_LENGTH.
    changed_ciphertext = bytearray(test_record)
    changed_ciphertext[HEADER_LENGTH + IV_LENGTH] ^= 0x01

    must_reject(
        "modified ciphertext",
        lambda: open_record(
            record=bytes(changed_ciphertext),
            expected_direction=DIRECTION_GATEWAY_TO_NODE,
            session_id=session_id,
            k_enc=k_g2n_enc,
            k_mac=k_g2n_mac,
            state=ReceiverState(),
        ),
    )

    # A record created for gateway-to-node must not open as node-to-gateway.
    must_reject(
        "wrong direction",
        lambda: open_record(
            record=test_record,
            expected_direction=DIRECTION_NODE_TO_GATEWAY,
            session_id=session_id,
            k_enc=k_n2g_enc,
            k_mac=k_n2g_mac,
            state=ReceiverState(),
        ),
    )

    # Accept once, then reject a repeat of the same sequence-zero record.
    replay_receiver = ReceiverState()

    open_record(
        record=test_record,
        expected_direction=DIRECTION_GATEWAY_TO_NODE,
        session_id=session_id,
        k_enc=k_g2n_enc,
        k_mac=k_g2n_mac,
        state=replay_receiver,
    )

    must_reject(
        "replayed record",
        lambda: open_record(
            record=test_record,
            expected_direction=DIRECTION_GATEWAY_TO_NODE,
            session_id=session_id,
            k_enc=k_g2n_enc,
            k_mac=k_g2n_mac,
            state=replay_receiver,
        ),
    )

    print("All secure_record.py self-tests passed.")


if __name__ == "__main__":
    _self_test()
