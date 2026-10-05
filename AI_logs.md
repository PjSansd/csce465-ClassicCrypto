Task 1 — Demonstrate why encryption alone is insufficient (20 points)
Create baseline_ctr.py that encrypts this fixed-length command using AES-CTR without a MAC:
{"action":"READ","path":"notes.txt"}
Use a relay function to change READ to another equal-length value without learning the key. Show the XOR
relation between the original and modified bytes. Then replay the same ciphertext and show that the
receiver processes it twice. This task demonstrates the textbook point that confidentiality alone does not
provide integrity or replay protection.

Could you clarify, given the context above, what 
{"action":"READ","path":"notes.txt"}
means, and what a relay function means in relation to  integrity or replay protection?

`{"action":"READ","path":"notes.txt"}` is a small JSON command telling a receiver—such as a server, agent, or file-service simulator—to **read** the file named `notes.txt`. In the assignment, it is deliberately predictable so you can show that AES-CTR encryption alone hides the command but does not stop an intermediary from altering or resending it.

## What the command means

The JSON object has two fields:

| Field | Meaning |
|---|---|
| `"action":"READ"` | The requested operation: retrieve/read the file’s contents |
| `"path":"notes.txt"` | The file on which to perform that operation |

So a receiver might conceptually do something like:

```python
if cmd["action"] == "READ":
    return read_file(cmd["path"])
```

It is a **plaintext application command** before encryption. The sender encrypts its bytes; the receiver decrypts them and then acts on the resulting JSON.

The command is useful for the lab because `READ` has four ASCII characters. You can replace it with another four-character action, such as `DELE`, `WRIT`, or a lab-defined `DROP`, without shifting the positions of the remaining bytes. In a real protocol, a parser and authorization checks should prevent harmful commands; the point here is to demonstrate a cryptographic property in a controlled setting.

## What “relay function” means here

A relay is an attacker-controlled middleman on the communication path:

```text
Sender  ── encrypted command ──>  Relay  ── ciphertext ──> Receiver
```

In this task, the relay function is not a legitimate forwarding service. It represents a network adversary that can:

- Observe and copy transmitted ciphertext.
- Forward ciphertext normally.
- Modify ciphertext before forwarding it.
- Send a previously captured ciphertext again.

Crucially, it **does not know the AES key** and should not be able to decrypt the command. Yet AES in CTR mode is *malleable*: a carefully chosen XOR change to ciphertext causes the same chosen XOR change in the decrypted plaintext.

## Why the XOR modification works

CTR mode effectively encrypts by XORing plaintext \(P\) with a pseudorandom keystream \(S\):

\[
C = P \oplus S
\]

The receiver decrypts by doing:

\[
P = C \oplus S
\]

Suppose the relay knows—or can reasonably guess—that the encrypted plaintext includes the bytes for `READ`. It computes the desired byte difference:

\[
\Delta = \texttt{b"READ"} \oplus \texttt{b"DELE"}
\]

Then it changes only the corresponding ciphertext bytes:

\[
C' = C \oplus \Delta
\]

When the receiver decrypts:

\[
C' \oplus S
= (C \oplus \Delta) \oplus S
= (P \oplus S \oplus \Delta) \oplus S
= P \oplus \Delta
= P'
\]

Thus, the receiver sees `DELE` where it originally would have seen `READ`, even though the relay never recovered the key or decrypted the complete message. This is a breach of **integrity**: the recipient cannot tell whether the command it decrypted is exactly the one the sender issued. CTR ciphertext is malleable unless the protocol adds authentication. [crypto.stackexchange](https://crypto.stackexchange.com/questions/3654/malleability-attacks-against-encryption-without-authentication)

For a simple byte illustration:

```text
Original plaintext bytes:  R    E    A    D
Replacement bytes:         D    E    L    E
XOR delta:                 R⊕D  E⊕E  A⊕L  D⊕E

Original ciphertext:       C
Modified ciphertext:       C ⊕ delta
```

Only the location containing the action text needs to change. The rest of the ciphertext can remain untouched.

## Why replay is separate

A replay attack does not modify anything. The relay captures a valid ciphertext and sends it again:

```text
Sender → Receiver:  C     # Receiver processes the READ command once
Relay  → Receiver:  C     # Same ciphertext, unchanged
```

If the receiver simply decrypts every message and executes it, it will accept the identical ciphertext a second time and perform the same operation again. Encryption alone does not signal whether a command is fresh, already processed, delayed, or duplicated. A replay attack is harmful because an old valid request is accepted as a new authorized request. [en.wikipedia](https://en.wikipedia.org/wiki/Replay_attack)

For `READ`, duplicate processing may merely cause two reads or duplicate audit records. But the same problem becomes serious for commands such as:

```json
{"action":"PAY!","amount":100}
```

or a valid fixed-format transfer request: replaying the same protected message could repeat a payment. The issue is that ciphertext validity is not the same thing as **one-time authorization**.

## What would fix each problem

A MAC—ideally an authenticated-encryption scheme such as AES-GCM or ChaCha20-Poly1305—addresses **tampering**. The sender authenticates the ciphertext and relevant metadata; if the relay flips the bytes corresponding to `READ`, verification fails and the receiver rejects the command. A MAC is a secret-key integrity check that detects modification. [seald](https://www.seald.io/blog/3-common-mistakes-when-implementing-encryption)

However, a MAC by itself does **not necessarily stop replay**: an old message and its authentic tag remain valid. Replay protection also needs freshness data that is authenticated and tracked, such as:

- A unique message ID or nonce, with the receiver rejecting previously seen values.
- A monotonically increasing sequence number.
- A timestamp plus an expiration window, when clock assumptions are acceptable.
- A request–response challenge nonce for interactive protocols.

The key rule is: authenticate the freshness value along with the command, and have the receiver remember or validate it. Nonces, session identifiers, timestamps, and sequence numbers are common replay defenses. [en.wikipedia](https://en.wikipedia.org/wiki/Replay_attack)

So the assignment’s conclusion is:

- **AES-CTR alone:** confidentiality only; ciphertext can be altered and replayed.
- **Authenticated encryption:** detects alteration.
- **Authenticated encryption plus freshness/replay tracking:** detects alteration *and* rejects duplicates.

# Second Prompt

(.venv) ubuntu@ubuntu2204:~/csce465-agentsec/hw2$ python3 baseline_ctr.py 
{"action":"READ","path":"notes.txt"}

AES encryption key: b'6df8718f8a2c1f74dfb7768ad7f9ad8fc9ed0e88c5cdd3f0f058c256331cfc45'
Encrypted: b'1dbc5a165cfc6ab13c1a7d92f2f86b9a829d384b6e036a23b1aaaed35789e6a7daa9caddf8'
The xor:  b'\x16\x00\r\x01'
The xor xor'd with DELE:  b'READ'
The xor xor'd with READ:  b'DELE'
Original Decrypted: b'{"action":"READ","path":"notes.txt"}\n'
Tampered Decrypted: b'\xd3\xed\xb12e\xca?\xbc\x08\xa4\x1b&\xfak\xb8}G\xc7\xc3\xfc|\xa4\xd9~\x1c\xd7:\xba\xde\x8b\xba\xd0\xb5rn\x8fp'


delta = xor_bytes (b"READ", b"DELE")
print("The xor: ", repr(delta))
print("The xor xor'd with DELE: ", xor_bytes(delta, b"DELE"))
print("The xor xor'd with READ: ", xor_bytes(delta, b"READ"))
# Xoring the other would return the other. The xor seems to be correct. 


offset = plaintext.index("READ")

tampered = bytearray(ciphertext)

for i, change in enumerate(delta):
    tampered[offset + i] ^= change

tampered = bytes(tampered)


# Decrypt the ciphertext with the given key:
#   plaintext = AES-256-CTR-Decrypt(ciphertext, key, iv)
aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
decrypted = aes.decrypt(ciphertext)
print('Original Decrypted:', decrypted)

tDecrypted = aes.decrypt(tampered)
print('Tampered Decrypted:', tDecrypted)

Your XOR mask is correct. The unexpected `Tampered Decrypted` output happens because you reuse the same CTR cipher object after it has already decrypted the original ciphertext.

CTR mode is stateful: after this line,

```python
decrypted = aes.decrypt(ciphertext)
```

the internal counter has advanced by the ciphertext length. Your next call,

```python
tDecrypted = aes.decrypt(tampered)
```

starts with the **wrong position in the CTR keystream**, so every output byte looks random. Create a fresh `AESModeOfOperationCTR` object using the same key and initial counter for *each* independent decryption. [github](https://github.com/nakov/Practical-Cryptography-for-Developers-Book/blob/master/symmetric-key-ciphers/aes-encrypt-decrypt-examples.md)

## Two fixes

Also fix the `offset` type. Since `plaintext` is bytes, search for bytes:

```python
offset = plaintext.index(b"READ")
```

Then use two separate decryptor instances:

```python
# Decrypt the original ciphertext.
aes_original = pyaes.AESModeOfOperationCTR(
    key,
    pyaes.Counter(iv),
)
decrypted = aes_original.decrypt(ciphertext)
print("Original Decrypted:", decrypted)

# Decrypt the tampered ciphertext from the same initial counter.
aes_tampered = pyaes.AESModeOfOperationCTR(
    key,
    pyaes.Counter(iv),
)
tDecrypted = aes_tampered.decrypt(tampered)
print("Tampered Decrypted:", tDecrypted)
```

The relevant corrected portion together is:

```python
delta = xor_bytes(b"READ", b"DELE")
print("The xor:", repr(delta))
print("The xor xor'd with DELE:", xor_bytes(delta, b"DELE"))
print("The xor xor'd with READ:", xor_bytes(delta, b"READ"))

offset = plaintext.index(b"READ")

tampered = bytearray(ciphertext)

for i, change in enumerate(delta):
    tampered[offset + i] ^= change

tampered = bytes(tampered)

aes_original = pyaes.AESModeOfOperationCTR(
    key,
    pyaes.Counter(iv),
)
decrypted = aes_original.decrypt(ciphertext)
print("Original Decrypted:", decrypted)

aes_tampered = pyaes.AESModeOfOperationCTR(
    key,
    pyaes.Counter(iv),
)
tDecrypted = aes_tampered.decrypt(tampered)
print("Tampered Decrypted:", tDecrypted)
```

## Expected result

Provided that the `ciphertext` was generated from exactly:

```python
plaintext = b'{"action":"READ","path":"notes.txt"}\n'
```

you should see:

```text
Original Decrypted: b'{"action":"READ","path":"notes.txt"}\n'
Tampered Decrypted: b'{"action":"DELE","path":"notes.txt"}\n'
```

Your ciphertext length of 37 bytes matches that plaintext including its trailing newline, which likely comes from the `data.json` file. The replacement preserves the length: both `READ` and `DELE` are four bytes, so the rest of the message stays aligned.

## Why fresh objects matter

CTR generates a keystream based on the key and counter, then XORs it with input bytes. The cipher object advances its counter as bytes are processed. Decrypting the first ciphertext consumes the first 37 bytes of keystream; attempting to decrypt another 37-byte ciphertext using that same object instead uses bytes 38–74 of the keystream.

A new cipher object initialized with the original `key` and `iv` regenerates the same initial keystream, which is required to correctly decrypt either the original or the tampered version. The `pyaes` AES-CTR example specifically notes that the cipher object must be initialized again because CTR retains internal state. [github](https://github.com/nakov/Practical-Cryptography-for-Developers-Book/blob/master/symmetric-key-ciphers/aes-encrypt-decrypt-examples.md)

## Keep the lesson scoped

This validates the security property you are studying: **CTR-only encryption does not authenticate data**. A receiver cannot distinguish your original ciphertext from the modified version using CTR decryption alone. An authenticated mode such as AES-GCM—or an encrypt-then-MAC design for legacy CTR—would reject the altered ciphertext instead of yielding the altered command. [csrc.nist](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)


# Question 

Can you help me work through this task? 

Task 3 — Encrypt-then-MAC record layer (35 points)
Implement secure_record.py with seal() and open_record() functions.
Use this format:
header = version(1 byte) || direction(1 byte) || sequence(8 bytes) ||
message_type(1 byte) || ciphertext_length(4 bytes)
CSCE 465/765 | Computer & Network Security
CSCE 465/765 Homework • 4
iv = session_id(8 bytes) || sequence(8 bytes)
ciphertext = AES-256-CTR(K_enc, iv, plaintext)
tag = HMAC-SHA-256(K_mac, header || iv || ciphertext)
Requirements:
• separate keys in each direction;
• sequence numbers begin at zero in each direction;
• the sender never reuses an IV under one key;
• the receiver expects the exact next sequence number;
• verify HMAC before decrypting;
• reject modified headers, modified ciphertext, replays, and messages in the wrong direction;
• do not release plaintext after any error;
• use constant-time MAC verification through the library.

# Response

Task 3 builds an authenticated record format on the Task 2 directional session keys. Use AES-256-CTR only for encryption, HMAC-SHA-256 only for authentication, and always authenticate `header || iv || ciphertext` **before** decrypting anything.

The required format is an Encrypt-then-MAC construction. The `cryptography` HMAC API’s `.verify()` method securely compares the expected and supplied tags and raises `InvalidSignature` on failure, so use it rather than `==`. [cryptography](https://cryptography.io/en/3.4.8/hazmat/primitives/mac/hmac.html)

## Record format

Each record is:

```text
header || iv || ciphertext || tag
```

where:

```text
header =
    version          1 byte
    direction        1 byte
    sequence         8 bytes, unsigned big-endian
    message_type     1 byte
    ciphertext_len   4 bytes, unsigned big-endian

iv =
    session_id       8 bytes
    sequence         8 bytes, unsigned big-endian

ciphertext =
    AES-256-CTR(K_enc, iv, plaintext)

tag =
    HMAC-SHA-256(K_mac, header || iv || ciphertext)
```

The header is exactly:

\[
1 + 1 + 8 + 1 + 4 = 15 \text{ bytes}
\]

The IV is exactly:

\[
8 + 8 = 16 \text{ bytes}
\]

AES has a 16-byte block size, so `session_id || sequence` is an appropriate 16-byte CTR initialization value. CTR turns AES into a stream-like cipher by XORing plaintext with a generated keystream, and the counter/IV must be unique for a given key.  [pycryptodome.readthedocs](https://pycryptodome.readthedocs.io/en/v3.20.0/src/cipher/classic.html)

## Direction constants

Choose explicit values and use them consistently:

```python
VERSION = 1

DIRECTION_GATEWAY_TO_NODE = 0x01
DIRECTION_NODE_TO_GATEWAY = 0x02

HEADER_LENGTH = 15
IV_LENGTH = 16
TAG_LENGTH = 32
SESSION_ID_LENGTH = 8

MAX_SEQUENCE = (1 << 64) - 1
MAX_CIPHERTEXT_LENGTH = (1 << 32) - 1
```

The gateway must use only:

```python
DIRECTION_GATEWAY_TO_NODE
```

when it seals records for the node. The node must expect that exact direction when opening them.

Similarly, node-to-gateway records must use:

```python
DIRECTION_NODE_TO_GATEWAY
```

This prevents a valid record in one direction from being replayed as a record in the opposite direction. Direction-specific encryption/MAC keys from Task 2 provide an additional protection layer.

## Sender state

Each sender needs a monotonically increasing sequence number. It begins at zero and advances only after creating a record:

```python
@dataclass
class SenderState:
    next_sequence: int = 0
```

Example:

```python
gateway_to_node_sender = SenderState()

record = seal(
    plaintext=b"temperature=22.5",
    message_type=0x01,
    direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_keys.session_id,
    k_enc=session_keys.k_g2n_enc,
    k_mac=session_keys.k_g2n_mac,
    state=gateway_to_node_sender,
)
```

The first record gets sequence zero, then the sender state becomes one.

## Receiver state

The receiver also begins at zero and accepts **only** the next expected sequence number:

```python
@dataclass
class ReceiverState:
    expected_sequence: int = 0
```

If it accepts sequence 0, it advances to 1. It rejects:

- Sequence 0 again: replay.
- Sequence 2 while expecting 1: out-of-order or missing record.
- Any sequence from the opposite direction.
- Any record with a bad HMAC.
- Any header/ciphertext/tag modification.

Advance `expected_sequence` only after HMAC verification and successful decryption.

## `secure_record.py`

Copy this into a new file named `secure_record.py`:

```python
#!/usr/bin/env python3

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


VERSION = 1

DIRECTION_GATEWAY_TO_NODE = 0x01
DIRECTION_NODE_TO_GATEWAY = 0x02

HEADER_LENGTH = 15
IV_LENGTH = 16
TAG_LENGTH = 32

SESSION_ID_LENGTH = 8
AES256_KEY_LENGTH = 32
MAX_SEQUENCE = (1 << 64) - 1
MAX_CIPHERTEXT_LENGTH = (1 << 32) - 1


class RecordError(Exception):
    """Raised when a secure record is malformed or fails verification."""


@dataclass
class SenderState:
    next_sequence: int = 0


@dataclass
class ReceiverState:
    expected_sequence: int = 0


def _require_bytes(name: str, value: bytes):
    if not isinstance(value, bytes):
        raise RecordError(f"{name} must be bytes")


def _validate_session_id(session_id: bytes):
    _require_bytes("session_id", session_id)

    if len(session_id) != SESSION_ID_LENGTH:
        raise RecordError("session_id must be exactly 8 bytes")


def _validate_keys(k_enc: bytes, k_mac: bytes):
    _require_bytes("K_enc", k_enc)
    _require_bytes("K_mac", k_mac)

    if len(k_enc) != AES256_KEY_LENGTH:
        raise RecordError("K_enc must be exactly 32 bytes for AES-256")

    if len(k_mac) != 32:
        raise RecordError("K_mac must be exactly 32 bytes for HMAC-SHA-256")


def _validate_direction(direction: int):
    if direction not in (
        DIRECTION_GATEWAY_TO_NODE,
        DIRECTION_NODE_TO_GATEWAY,
    ):
        raise RecordError("Invalid record direction")


def _validate_message_type(message_type: int):
    if not isinstance(message_type, int):
        raise RecordError("message_type must be an integer")

    if not 0 <= message_type <= 0xFF:
        raise RecordError("message_type must fit in one byte")


def _validate_sequence(sequence: int):
    if not isinstance(sequence, int):
        raise RecordError("sequence must be an integer")

    if not 0 <= sequence <= MAX_SEQUENCE:
        raise RecordError("sequence is outside uint64 range")


def _build_header(
    version: int,
    direction: int,
    sequence: int,
    message_type: int,
    ciphertext_length: int,
) -> bytes:
    if version != VERSION:
        raise RecordError("Unsupported record version")

    _validate_direction(direction)
    _validate_sequence(sequence)
    _validate_message_type(message_type)

    if not 0 <= ciphertext_length <= MAX_CIPHERTEXT_LENGTH:
        raise RecordError("ciphertext length is outside uint32 range")

    return (
        bytes([version])
        + bytes([direction])
        + sequence.to_bytes(8, "big")
        + bytes([message_type])
        + ciphertext_length.to_bytes(4, "big")
    )


def _parse_header(header: bytes) -> dict:
    if len(header) != HEADER_LENGTH:
        raise RecordError("Invalid header length")

    version = header[0]
    direction = header [cryptography](https://cryptography.io/en/3.4.8/hazmat/primitives/mac/hmac.html)
    sequence = int.from_bytes(header[2:10], "big")
    message_type = header [soatok](https://soatok.blog/2021/06/07/dead-ends-in-cryptanalysis-2-timing-side-channels/)
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
    _validate_session_id(session_id)
    _validate_sequence(sequence)

    iv = session_id + sequence.to_bytes(8, "big")

    if len(iv) != IV_LENGTH:
        raise RecordError("IV must be exactly 16 bytes")

    return iv


def _aes_ctr_encrypt(k_enc: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(k_enc),
        modes.CTR(iv),
    )
    encryptor = cipher.encryptor()

    return encryptor.update(plaintext) + encryptor.finalize()


def _aes_ctr_decrypt(k_enc: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(k_enc),
        modes.CTR(iv),
    )
    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def _compute_tag(k_mac: bytes, header: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    mac = hmac.HMAC(k_mac, hashes.SHA256())
    mac.update(header + iv + ciphertext)
    return mac.finalize()


def _verify_tag(
    k_mac: bytes,
    header: bytes,
    iv: bytes,
    ciphertext: bytes,
    received_tag: bytes,
):
    if len(received_tag) != TAG_LENGTH:
        raise RecordError("Record tag must be exactly 32 bytes")

    mac = hmac.HMAC(k_mac, hashes.SHA256())
    mac.update(header + iv + ciphertext)

    try:
        # Library verification performs secure MAC verification.
        mac.verify(received_tag)
    except InvalidSignature as exc:
        raise RecordError("Record HMAC verification failed") from exc


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
    Create one authenticated record.

    Returns:
        header || iv || ciphertext || tag

    The sender uses state.next_sequence and increments it only after
    successfully creating the record.
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
        raise RecordError("Unexpected AES-CTR ciphertext length")

    tag = _compute_tag(k_mac, header, iv, ciphertext)

    record = header + iv + ciphertext + tag

    if sequence == MAX_SEQUENCE:
        raise RecordError(
            "Sequence number exhausted; rekey before sending another record"
        )

    state.next_sequence += 1

    return record


def open_record(
    record: bytes,
    expected_direction: int,
    session_id: bytes,
    k_enc: bytes,
    k_mac: bytes,
    state: ReceiverState,
):
    """
    Verify and open one authenticated record.

    Returns:
        (message_type, plaintext)

    Requirements enforced:
    - expected protocol version
    - expected direction
    - exact next sequence number
    - IV equals session_id || sequence
    - exact ciphertext length stated in the header
    - HMAC verification BEFORE AES-CTR decryption
    - no plaintext returned on any error
    """
    _require_bytes("record", record)
    _validate_session_id(session_id)
    _validate_keys(k_enc, k_mac)
    _validate_direction(expected_direction)

    if not isinstance(state, ReceiverState):
        raise RecordError("state must be a ReceiverState")

    minimum_record_length = HEADER_LENGTH + IV_LENGTH + TAG_LENGTH

    if len(record) < minimum_record_length:
        raise RecordError("Record is too short")

    header = record[:HEADER_LENGTH]
    parsed = _parse_header(header)

    if parsed["direction"] != expected_direction:
        raise RecordError("Record arrived in the wrong direction")

    if parsed["sequence"] != state.expected_sequence:
        raise RecordError("Unexpected sequence number")

    expected_total_length = (
        HEADER_LENGTH
        + IV_LENGTH
        + parsed["ciphertext_length"]
        + TAG_LENGTH
    )

    if len(record) != expected_total_length:
        raise RecordError("Record length does not match header length")

    iv_start = HEADER_LENGTH
    ciphertext_start = HEADER_LENGTH + IV_LENGTH
    ciphertext_end = ciphertext_start + parsed["ciphertext_length"]

    iv = record[iv_start:ciphertext_start]
    ciphertext = record[ciphertext_start:ciphertext_end]
    tag = record[ciphertext_end:]

    expected_iv = _build_iv(session_id, parsed["sequence"])

    if iv != expected_iv:
        raise RecordError("Record IV does not match session ID and sequence")

    # Critical Encrypt-then-MAC order:
    # Verify header || iv || ciphertext BEFORE decrypting ciphertext.
    _verify_tag(k_mac, header, iv, ciphertext, tag)

    plaintext = _aes_ctr_decrypt(k_enc, iv, ciphertext)

    if parsed["sequence"] == MAX_SEQUENCE:
        raise RecordError(
            "Sequence number exhausted; rekey before receiving another record"
        )

    state.expected_sequence += 1

    return parsed["message_type"], plaintext
```

## Example use

Create `test_secure_record.py` next to `secure_record.py`:

```python
from secure_record import (
    DIRECTION_GATEWAY_TO_NODE,
    DIRECTION_NODE_TO_GATEWAY,
    ReceiverState,
    SenderState,
    open_record,
    seal,
)


# Replace these with the Task 2 outputs:
session_id = bytes.fromhex("0011223344556677")

k_g2n_enc = bytes.fromhex("11" * 32)
k_g2n_mac = bytes.fromhex("22" * 32)

k_n2g_enc = bytes.fromhex("33" * 32)
k_n2g_mac = bytes.fromhex("44" * 32)


gateway_sender = SenderState()
node_receiver = ReceiverState()

record = seal(
    plaintext=b"hello from gateway",
    message_type=0x01,
    direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_id,
    k_enc=k_g2n_enc,
    k_mac=k_g2n_mac,
    state=gateway_sender,
)

message_type, plaintext = open_record(
    record=record,
    expected_direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_id,
    k_enc=k_g2n_enc,
    k_mac=k_g2n_mac,
    state=node_receiver,
)

print("Message type:", message_type)
print("Plaintext:", plaintext)
```

Run:

```bash
python3 test_secure_record.py
```

Expected:

```text
Message type: 1
Plaintext: b'hello from gateway'
```

## Directional usage

Use the Task 2 outputs this way:

| Traffic | `direction` / `expected_direction` | Encryption key | MAC key |
|---|---:|---|---|
| Gateway → node | `DIRECTION_GATEWAY_TO_NODE` | `K_g2n_enc` | `K_g2n_mac` |
| Node → gateway | `DIRECTION_NODE_TO_GATEWAY` | `K_n2g_enc` | `K_n2g_mac` |

For example, gateway sending:

```python
record = seal(
    plaintext=b"gateway command",
    message_type=0x01,
    direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_keys.session_id,
    k_enc=session_keys.k_g2n_enc,
    k_mac=session_keys.k_g2n_mac,
    state=gateway_to_node_sender_state,
)
```

Node receiving:

```python
message_type, plaintext = open_record(
    record=record,
    expected_direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_keys.session_id,
    k_enc=session_keys.k_g2n_enc,
    k_mac=session_keys.k_g2n_mac,
    state=node_from_gateway_receiver_state,
)
```

For the reverse direction, use only `K_n2g_enc`, `K_n2g_mac`, and `DIRECTION_NODE_TO_GATEWAY`.

## Required tests

Add these tests to demonstrate the required rejection behavior:

```python
from secure_record import RecordError


def must_reject(label, operation):
    try:
        operation()
    except RecordError:
        print("PASS:", label)
    else:
        raise AssertionError("FAIL: accepted " + label)
```

### Modified ciphertext

```python
bad_ciphertext = bytearray(record)
bad_ciphertext[-33] ^= 0x01  # Change a ciphertext byte before final 32-byte tag.

must_reject(
    "modified ciphertext",
    lambda: open_record(
        bytes(bad_ciphertext),
        DIRECTION_GATEWAY_TO_NODE,
        session_id,
        k_g2n_enc,
        k_g2n_mac,
        ReceiverState(),
    ),
)
```

### Modified header

```python
bad_header = bytearray(record)
bad_header [soatok](https://soatok.blog/2021/06/07/dead-ends-in-cryptanalysis-2-timing-side-channels/) ^= 0x01  # Change message_type byte in header.

must_reject(
    "modified header",
    lambda: open_record(
        bytes(bad_header),
        DIRECTION_GATEWAY_TO_NODE,
        session_id,
        k_g2n_enc,
        k_g2n_mac,
        ReceiverState(),
    ),
)
```

### Replay

Use the same receiver state twice:

```python
receiver = ReceiverState()

open_record(
    record,
    DIRECTION_GATEWAY_TO_NODE,
    session_id,
    k_g2n_enc,
    k_g2n_mac,
    receiver,
)

must_reject(
    "replayed sequence number",
    lambda: open_record(
        record,
        DIRECTION_GATEWAY_TO_NODE,
        session_id,
        k_g2n_enc,
        k_g2n_mac,
        receiver,
    ),
)
```

The first call advances `receiver.expected_sequence` from 0 to 1. The replayed record still claims sequence 0, so it is rejected.

### Wrong direction

```python
must_reject(
    "wrong direction",
    lambda: open_record(
        record,
        DIRECTION_NODE_TO_GATEWAY,
        session_id,
        k_g2n_enc,
        k_g2n_mac,
        ReceiverState(),
    ),
)
```

This rejects the record before decryption because the header direction does not match the expected inbound direction.

## Why this meets each requirement

| Requirement | Where implemented |
|---|---|
| Separate keys per direction | Caller supplies `K_g2n_enc/K_g2n_mac` or `K_n2g_enc/K_n2g_mac` |
| Start sequence at zero | `SenderState.next_sequence = 0`, `ReceiverState.expected_sequence = 0` |
| Never reuse IV under one key | IV is `session_id || sequence`; sender increments sequence after each record |
| Receiver expects next sequence | `parsed["sequence"] != state.expected_sequence` rejects |
| Verify HMAC before decrypting | `_verify_tag(...)` occurs before `_aes_ctr_decrypt(...)` |
| Reject modified header | Header is included in HMAC input |
| Reject modified ciphertext | Ciphertext is included in HMAC input |
| Reject replays | Reused sequence differs from expected next sequence |
| Reject wrong direction | `parsed["direction"] != expected_direction` rejects |
| No plaintext after errors | Decryption runs only after all validation and MAC verification pass |
| Constant-time MAC verification | `mac.verify(received_tag)` from `cryptography` |
| Authenticate IV | IV is included in HMAC input and checked against `session_id || sequence` |

The ordering is essential: CTR encryption alone is malleable, but HMAC authenticates the header, IV, and ciphertext. Decrypting only after successful HMAC verification prevents modified ciphertext from reaching application logic. HMAC is specifically intended to verify message integrity and authenticity, and the library’s `verify()` operation raises an exception when tags differ. [cryptography](https://cryptography.io/en/3.4.8/hazmat/primitives/mac/hmac.html)

# Question 

What does seal() and open_record() represent/do in this program?

# Response

`seal()` is the **sender-side record-protection function**: it takes a plaintext application message and turns it into one encrypted, authenticated record that can be sent to the peer.

`open_record()` is the **receiver-side record-processing function**: it takes that received record, verifies that it is valid and expected, then decrypts it and returns the plaintext only if every security check succeeds.

## Big picture

Task 2 creates a secure session and gives you keys such as:

```text
K_g2n_enc    gateway-to-node AES encryption key
K_g2n_mac    gateway-to-node HMAC key
K_n2g_enc    node-to-gateway AES encryption key
K_n2g_mac    node-to-gateway HMAC key
session_id   8-byte identifier used in the IV
```

Task 3 uses those values to protect each individual message after the handshake.

```text
Task 2:
Gateway and node authenticate each other and derive session keys.

Task 3:
Gateway and node use those session keys to protect application records.
```

For example, after Task 2 the gateway may need to send a command:

```text
READ notes.txt
```

The gateway should not send that plaintext directly. It calls `seal()` first.

```text
Gateway plaintext
      |
      v
seal()
      |
      v
Encrypted/authenticated record
      |
      v
Node receives record
      |
      v
open_record()
      |
      v
Verified plaintext
```

AES-CTR provides confidentiality, but it does not by itself provide authenticity or tamper detection. The HMAC in Task 3 is what detects modified records. NIST cautions that confidentiality-only block-cipher modes have significant vulnerabilities without authentication. [csrc.nist](https://csrc.nist.gov/Projects/block-cipher-techniques/bcm/authentication-for-confidentiality-modes)

## What `seal()` does

`seal()` represents the behavior of the **sender**.

For example, if the gateway is sending to the node:

```python
record = seal(
    plaintext=b'{"action":"READ","path":"notes.txt"}',
    message_type=0x01,
    direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_keys.session_id,
    k_enc=session_keys.k_g2n_enc,
    k_mac=session_keys.k_g2n_mac,
    state=gateway_sender_state,
)
```

It performs the following steps.

| Step | `seal()` action | Why it matters |
|---:|---|---|
| 1 | Reads the next outgoing sequence number, initially `0` | Identifies the record and prevents IV reuse |
| 2 | Creates the 15-byte header | Carries version, direction, sequence, type, and ciphertext length |
| 3 | Creates `iv = session_id || sequence` | Produces a unique AES-CTR IV for that direction/key |
| 4 | Encrypts plaintext with AES-256-CTR | Hides the plaintext |
| 5 | Computes HMAC over `header || iv || ciphertext` | Detects changes to all protected record fields |
| 6 | Builds `header || iv || ciphertext || tag` | Creates bytes that would be sent over a network |
| 7 | Increments the sender sequence number | Ensures the next record uses a new IV |

Conceptually:

```text
plaintext =
    b'{"action":"READ","path":"notes.txt"}'

header =
    version || direction || sequence || type || ciphertext_length

iv =
    session_id || sequence

ciphertext =
    AES-CTR-encrypt(K_enc, iv, plaintext)

tag =
    HMAC-SHA-256(K_mac, header || iv || ciphertext)

record =
    header || iv || ciphertext || tag
```

`seal()` returns only the protected binary `record`. It does **not** send it over a socket in your assignment; your test code can pass that returned byte string directly to `open_record()`.

## What `open_record()` does

`open_record()` represents the behavior of the **receiver**.

For example, the node receives a record created by the gateway:

```python
message_type, plaintext = open_record(
    record=record,
    expected_direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_keys.session_id,
    k_enc=session_keys.k_g2n_enc,
    k_mac=session_keys.k_g2n_mac,
    state=node_receiver_state,
)
```

It performs these steps in a security-critical order.

| Step | `open_record()` action | Rejects |
|---:|---|---|
| 1 | Checks the record has enough bytes for header, IV, and tag | Truncated records |
| 2 | Parses the header | Malformed version/direction/length fields |
| 3 | Checks direction equals expected inbound direction | Records from the wrong direction |
| 4 | Checks sequence equals exact expected sequence | Replays, skipped records, out-of-order records |
| 5 | Checks total record length matches header ciphertext length | Appended/truncated/inconsistent records |
| 6 | Reconstructs expected `session_id || sequence` IV | Modified or mismatched IV |
| 7 | Verifies HMAC over `header || iv || ciphertext` | Modified header, IV, ciphertext, or tag |
| 8 | Decrypts AES-CTR ciphertext only after HMAC passes | Releases no plaintext from invalid records |
| 9 | Advances receiver sequence state | Makes a second copy of the same record a replay |

The required order is:

```text
parse and validate
        ↓
verify HMAC
        ↓
decrypt
        ↓
return plaintext
```

It must **not** work like this:

```text
decrypt
        ↓
verify HMAC
```

The latter would temporarily produce attacker-controlled plaintext before authenticity is established. The `cryptography` documentation emphasizes that encryption alone does not establish message authenticity; a separate integrity mechanism such as HMAC is needed when using a non-authenticated encryption mode. [cryptography](https://cryptography.io/en/3.4.2/hazmat/primitives/symmetric-encryption.html)

## Sender and receiver example

Assume Task 2 produced these directional keys:

```python
gateway_to_node_sender = SenderState()
node_from_gateway_receiver = ReceiverState()

record = seal(
    plaintext=b"Open the valve",
    message_type=0x01,
    direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_keys.session_id,
    k_enc=session_keys.k_g2n_enc,
    k_mac=session_keys.k_g2n_mac,
    state=gateway_to_node_sender,
)

message_type, plaintext = open_record(
    record=record,
    expected_direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_keys.session_id,
    k_enc=session_keys.k_g2n_enc,
    k_mac=session_keys.k_g2n_mac,
    state=node_from_gateway_receiver,
)

print(message_type)  # 1
print(plaintext)     # b"Open the valve"
```

After this succeeds:

```text
gateway_to_node_sender.next_sequence        = 1
node_from_gateway_receiver.expected_sequence = 1
```

The next gateway-to-node record uses sequence `1`, not `0`.

## Why separate state exists

You need distinct sequence counters for each direction:

```python
gateway_to_node_sender = SenderState()
gateway_from_node_receiver = ReceiverState()

node_to_gateway_sender = SenderState()
node_from_gateway_receiver = ReceiverState()
```

They all begin at zero, but they track separate traffic streams.

```text
Gateway → Node:
  Gateway sender sequence: 0, 1, 2, ...
  Node receiver expected: 0, 1, 2, ...

Node → Gateway:
  Node sender sequence: 0, 1, 2, ...
  Gateway receiver expected: 0, 1, 2, ...
```

This is valid because each direction has different encryption and MAC keys:

```text
Gateway → Node:
  K_g2n_enc
  K_g2n_mac

Node → Gateway:
  K_n2g_enc
  K_n2g_mac
```

The same numerical sequence can appear in both directions without reusing an IV under the **same AES key**. For example:

```text
Gateway → Node, sequence 0:
  AES key = K_g2n_enc
  IV = session_id || 0

Node → Gateway, sequence 0:
  AES key = K_n2g_enc
  IV = session_id || 0
```

The IV is the same pattern, but the AES keys are different, so it is not an IV/key-pair reuse.

## Why the HMAC covers header and IV

The HMAC input is:

```python
header + iv + ciphertext
```

not just ciphertext.

That protects every important item:

```text
header:
  version
  direction
  sequence number
  message type
  ciphertext length

iv:
  session ID
  sequence-derived CTR initialization value

ciphertext:
  encrypted application data
```

If an attacker changes the header’s message type from, for example, `0x01` to `0x02`, the HMAC fails.

If an attacker changes the sequence number to bypass replay protection, the HMAC fails and the receiver also notices the unexpected sequence.

If an attacker changes the CTR IV, the HMAC fails.

If an attacker changes ciphertext bytes to try to alter `READ` into `DELE`, the HMAC fails before decryption occurs.

## Difference between the functions

| Function | Represents | Input | Output | Main security job |
|---|---|---|---|---|
| `seal()` | Sender: gateway or node | Plaintext and directional keys | Protected binary record | Encrypts and attaches authenticity protection |
| `open_record()` | Receiver: node or gateway | Protected binary record and directional keys | `(message_type, plaintext)` only after validation | Rejects invalid/replayed/wrong-direction records before exposing plaintext |

In short:

```text
seal()        = lock and sign a message for transport
open_record() = verify, unlock, and safely deliver a received message
```

The words “seal” and “open” are common names for these complementary operations. `seal()` creates a record that is confidential and authenticated; `open_record()` accepts it only when it passes the protocol’s authentication and sequencing rules.

# Prompt 

Can you give a single file to use for secure_record.py ?

# Response 

Yes. Save the following as **`secure_record.py`**. It implements the Task 3 Encrypt-then-MAC record layer with `seal()` and `open_record()`, AES-256-CTR, HMAC-SHA-256 verification before decryption, directional sequence state, replay protection, and constant-time library MAC verification.

It uses the `cryptography` package, which supplies the AES-CTR and HMAC primitives; `HMAC.verify()` raises `InvalidSignature` when the tag is invalid. [cryptography](https://cryptography.io/en/3.4.8/hazmat/primitives/mac/hmac.html)

```python
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
    direction = header [cryptography](https://cryptography.io/en/3.4.8/hazmat/primitives/mac/hmac.html)
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
```

## Run the self-test

```bash
source .venv/bin/activate
python3 secure_record.py
```

Expected output:

```text
PASS: valid gateway-to-node record opened successfully
PASS: modified header
PASS: modified ciphertext
PASS: wrong direction
PASS: replayed record
All secure_record.py self-tests passed.
```

## Use it with Task 2

When Task 2 returns session material, use its directional keys exactly like this:

```python
from secure_record import (
    DIRECTION_GATEWAY_TO_NODE,
    DIRECTION_NODE_TO_GATEWAY,
    ReceiverState,
    SenderState,
    open_record,
    seal,
)

gateway_to_node_sender = SenderState()
node_from_gateway_receiver = ReceiverState()

record = seal(
    plaintext=b'{"action":"READ","path":"notes.txt"}',
    message_type=0x01,
    direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_keys.session_id,
    k_enc=session_keys.k_g2n_enc,
    k_mac=session_keys.k_g2n_mac,
    state=gateway_to_node_sender,
)

message_type, plaintext = open_record(
    record=record,
    expected_direction=DIRECTION_GATEWAY_TO_NODE,
    session_id=session_keys.session_id,
    k_enc=session_keys.k_g2n_enc,
    k_mac=session_keys.k_g2n_mac,
    state=node_from_gateway_receiver,
)
```

For node-to-gateway traffic, create separate sender/receiver state and supply only:

```python
direction=DIRECTION_NODE_TO_GATEWAY
k_enc=session_keys.k_n2g_enc
k_mac=session_keys.k_n2g_mac
```

The code authenticates the header, IV, and ciphertext before it decrypts. That prevents AES-CTR’s ciphertext malleability from reaching the application layer, while the monotonically increasing per-direction sequence state prevents record replay and IV reuse under a directional key. HMAC is intended for integrity/authenticity checks, and the library’s verification API rejects an invalid tag. [cryptography](https://cryptography.io/en/3.4.8/hazmat/primitives/mac/hmac.html)

# Prompt

Task 4 — Adversarial tests and security note (25 points)
Write automated tests for at least:
1. valid handshake and bidirectional messages;
2. modified ciphertext;
3. modified authenticated header;
4. replayed record;
5. record reflected into the opposite direction;
6. incorrect RSA public key, invalid RSA-PSS transcript signature, or reflected handshake message.
Each test must assert a specific safe failure.

# Response

Create a separate `test_security.py` file that imports your Task 2 handshake module and `secure_record.py`, then runs six automated tests. Each negative test should use `assertRaises(...)` so it passes only when the code fails safely with `RecordError` or `HandshakeError`.

The `cryptography` library raises `InvalidSignature` for failed HMAC or asymmetric-signature checks; your wrappers should convert those to your assignment-specific `RecordError`/`HandshakeError` exceptions. [cryptography](https://cryptography.io/en/latest/exceptions/)

## Important import adjustment

The test file below assumes your Task 2 code is saved as:

```text
task2_handshake.py
```

and that it exposes:

```python
run_handshake
HandshakeError
```

It also assumes `run_handshake()` returns the dictionary from the prior code:

```python
{
    "transcript": ...,
    "node_signature": ...,
    "gateway_signature": ...,
    "gateway_rsa_public": ...,
    "node_rsa_public": ...,
    "gateway_keys": ...,
    "node_keys": ...,
}
```

Your Task 3 file should be:

```text
secure_record.py
```

with:

```python
seal
open_record
SenderState
ReceiverState
RecordError
DIRECTION_GATEWAY_TO_NODE
DIRECTION_NODE_TO_GATEWAY
```

## `test_security.py`

Copy this into a file named `test_security.py` in the same directory as `task2_handshake.py`, `secure_record.py`, and `ffdhe3072.pem`.

```python
#!/usr/bin/env python3
"""
test_security.py

Task 4 -- Adversarial tests and security note.

Run with:
    python3 -m unittest -v test_security.py

Required local files:
    task2_handshake.py
    secure_record.py
    ffdhe3072.pem
"""

import unittest

from task2_handshake import HandshakeError, run_handshake
from secure_record import (
    DIRECTION_GATEWAY_TO_NODE,
    DIRECTION_NODE_TO_GATEWAY,
    HEADER_LENGTH,
    IV_LENGTH,
    RecordError,
    ReceiverState,
    SenderState,
    open_record,
    seal,
)


MESSAGE_TYPE_COMMAND = 0x01
MESSAGE_TYPE_STATUS = 0x02


class Task4SecurityTests(unittest.TestCase):
    """
    Each test uses a fresh Task 2 session. This avoids accidental sharing
    of sequence state between tests.
    """

    def setUp(self):
        """
        Establish a valid authenticated Task 2 session before each test.

        The keys and session ID used below come from the Task 2 result.
        """
        self.handshake = run_handshake()

        self.session_id = self.handshake["gateway_keys"].session_id

        self.k_g2n_enc = self.handshake["gateway_keys"].k_g2n_enc
        self.k_g2n_mac = self.handshake["gateway_keys"].k_g2n_mac

        self.k_n2g_enc = self.handshake["gateway_keys"].k_n2g_enc
        self.k_n2g_mac = self.handshake["gateway_keys"].k_n2g_mac

    def make_gateway_to_node_record(self, plaintext=b"gateway command"):
        """
        Create a fresh, valid sequence-zero gateway-to-node record.
        """
        sender = SenderState()

        record = seal(
            plaintext=plaintext,
            message_type=MESSAGE_TYPE_COMMAND,
            direction=DIRECTION_GATEWAY_TO_NODE,
            session_id=self.session_id,
            k_enc=self.k_g2n_enc,
            k_mac=self.k_g2n_mac,
            state=sender,
        )

        self.assertEqual(sender.next_sequence, 1)
        return record

    # -----------------------------------------------------------------
    # Requirement 1:
    # Valid handshake and bidirectional messages.
    # -----------------------------------------------------------------

    def test_01_valid_handshake_and_bidirectional_messages(self):
        """
        Confirms:
        - Task 2 created the same keys at both endpoints.
        - Gateway -> node record opens successfully.
        - Node -> gateway record opens successfully.
        - Separate directional keys and independent sequence state work.
        """
        self.assertEqual(
            self.handshake["gateway_keys"],
            self.handshake["node_keys"],
        )

        gateway_to_node_sender = SenderState()
        node_from_gateway_receiver = ReceiverState()

        g2n_plaintext = b'{"action":"READ","path":"notes.txt"}'

        g2n_record = seal(
            plaintext=g2n_plaintext,
            message_type=MESSAGE_TYPE_COMMAND,
            direction=DIRECTION_GATEWAY_TO_NODE,
            session_id=self.session_id,
            k_enc=self.k_g2n_enc,
            k_mac=self.k_g2n_mac,
            state=gateway_to_node_sender,
        )

        message_type, recovered = open_record(
            record=g2n_record,
            expected_direction=DIRECTION_GATEWAY_TO_NODE,
            session_id=self.session_id,
            k_enc=self.k_g2n_enc,
            k_mac=self.k_g2n_mac,
            state=node_from_gateway_receiver,
        )

        self.assertEqual(message_type, MESSAGE_TYPE_COMMAND)
        self.assertEqual(recovered, g2n_plaintext)
        self.assertEqual(gateway_to_node_sender.next_sequence, 1)
        self.assertEqual(node_from_gateway_receiver.expected_sequence, 1)

        node_to_gateway_sender = SenderState()
        gateway_from_node_receiver = ReceiverState()

        n2g_plaintext = b'{"status":"OK","temperature":22}'

        n2g_record = seal(
            plaintext=n2g_plaintext,
            message_type=MESSAGE_TYPE_STATUS,
            direction=DIRECTION_NODE_TO_GATEWAY,
            session_id=self.session_id,
            k_enc=self.k_n2g_enc,
            k_mac=self.k_n2g_mac,
            state=node_to_gateway_sender,
        )

        message_type, recovered = open_record(
            record=n2g_record,
            expected_direction=DIRECTION_NODE_TO_GATEWAY,
            session_id=self.session_id,
            k_enc=self.k_n2g_enc,
            k_mac=self.k_n2g_mac,
            state=gateway_from_node_receiver,
        )

        self.assertEqual(message_type, MESSAGE_TYPE_STATUS)
        self.assertEqual(recovered, n2g_plaintext)
        self.assertEqual(node_to_gateway_sender.next_sequence, 1)
        self.assertEqual(gateway_from_node_receiver.expected_sequence, 1)

    # -----------------------------------------------------------------
    # Requirement 2:
    # Modified ciphertext.
    # -----------------------------------------------------------------

    def test_02_modified_ciphertext_rejected(self):
        """
        Flip a ciphertext bit while leaving the original tag unchanged.

        Expected safe failure:
            RecordError due to failed HMAC verification.

        The receiver must not return plaintext and must not advance its
        expected sequence after the rejection.
        """
        record = self.make_gateway_to_node_record(
            b'{"action":"READ","path":"notes.txt"}'
        )

        tampered = bytearray(record)

        ciphertext_start = HEADER_LENGTH + IV_LENGTH
        tampered[ciphertext_start] ^= 0x01

        receiver = ReceiverState()

        with self.assertRaisesRegex(
            RecordError,
            "HMAC verification failed",
        ):
            open_record(
                record=bytes(tampered),
                expected_direction=DIRECTION_GATEWAY_TO_NODE,
                session_id=self.session_id,
                k_enc=self.k_g2n_enc,
                k_mac=self.k_g2n_mac,
                state=receiver,
            )

        self.assertEqual(receiver.expected_sequence, 0)

    # -----------------------------------------------------------------
    # Requirement 3:
    # Modified authenticated header.
    # -----------------------------------------------------------------

    def test_03_modified_authenticated_header_rejected(self):
        """
        Change the header's message_type byte, which is byte 10:

            version:             byte 0
            direction:           byte 1
            sequence:            bytes 2..9
            message_type:        byte 10
            ciphertext length:   bytes 11..14

        Expected safe failure:
            RecordError due to failed HMAC verification.

        The header is included in HMAC(header || iv || ciphertext), so
        changing it invalidates the existing tag.
        """
        record = self.make_gateway_to_node_record(b"header integrity test")

        tampered = bytearray(record)
        message_type_offset = 10
        tampered[message_type_offset] ^= 0x01

        receiver = ReceiverState()

        with self.assertRaisesRegex(
            RecordError,
            "HMAC verification failed",
        ):
            open_record(
                record=bytes(tampered),
                expected_direction=DIRECTION_GATEWAY_TO_NODE,
                session_id=self.session_id,
                k_enc=self.k_g2n_enc,
                k_mac=self.k_g2n_mac,
                state=receiver,
            )

        self.assertEqual(receiver.expected_sequence, 0)

    # -----------------------------------------------------------------
    # Requirement 4:
    # Replayed record.
    # -----------------------------------------------------------------

    def test_04_replayed_record_rejected(self):
        """
        Open the exact same valid sequence-zero record twice.

        First open:
            Accepted and receiver advances expected sequence from 0 to 1.

        Second open:
            Rejected because record sequence 0 is not the expected
            next sequence 1.
        """
        record = self.make_gateway_to_node_record(b"replay test")

        receiver = ReceiverState()

        message_type, plaintext = open_record(
            record=record,
            expected_direction=DIRECTION_GATEWAY_TO_NODE,
            session_id=self.session_id,
            k_enc=self.k_g2n_enc,
            k_mac=self.k_g2n_mac,
            state=receiver,
        )

        self.assertEqual(message_type, MESSAGE_TYPE_COMMAND)
        self.assertEqual(plaintext, b"replay test")
        self.assertEqual(receiver.expected_sequence, 1)

        with self.assertRaisesRegex(
            RecordError,
            "not the expected next sequence",
        ):
            open_record(
                record=record,
                expected_direction=DIRECTION_GATEWAY_TO_NODE,
                session_id=self.session_id,
                k_enc=self.k_g2n_enc,
                k_mac=self.k_g2n_mac,
                state=receiver,
            )

        self.assertEqual(receiver.expected_sequence, 1)

    # -----------------------------------------------------------------
    # Requirement 5:
    # Record reflected into the opposite direction.
    # -----------------------------------------------------------------

    def test_05_reflected_record_rejected_in_opposite_direction(self):
        """
        Create a valid gateway-to-node record, then attempt to open it as
        though it were node-to-gateway traffic.

        Expected safe failure:
            RecordError because the header direction is gateway-to-node,
            not the gateway's expected node-to-gateway direction.

        The record would also fail HMAC if the code continued because
        node-to-gateway uses distinct K_n2g_mac, but direction is checked
        earlier and gives a specific safe failure.
        """
        record = self.make_gateway_to_node_record(b"reflection test")

        gateway_receiver = ReceiverState()

        with self.assertRaisesRegex(
            RecordError,
            "wrong direction",
        ):
            open_record(
                record=record,
                expected_direction=DIRECTION_NODE_TO_GATEWAY,
                session_id=self.session_id,
                k_enc=self.k_n2g_enc,
                k_mac=self.k_n2g_mac,
                state=gateway_receiver,
            )

        self.assertEqual(gateway_receiver.expected_sequence, 0)

    # -----------------------------------------------------------------
    # Requirement 6:
    # Incorrect RSA public key or invalid RSA-PSS transcript signature.
    # -----------------------------------------------------------------

    def test_06_invalid_handshake_signature_rejected(self):
        """
        Alter a node RSA-PSS signature while retaining the original
        transcript.

        Expected safe failure:
            HandshakeError due to RSA-PSS signature verification failure.

        This confirms an attacker cannot modify a transcript signature and
        still authenticate as the node.
        """
        transcript = self.handshake["transcript"]
        node_signature = self.handshake["node_signature"]
        node_public_key = self.handshake["node_rsa_public"]

        tampered_signature = bytearray(node_signature)
        tampered_signature[0] ^= 0x01

        # Import locally so the test explicitly exercises Task 2's verifier.
        from task2_handshake import verify_transcript_signature, ROLE_NODE

        with self.assertRaisesRegex(
            HandshakeError,
            "RSA-PSS signature verification failed",
        ):
            verify_transcript_signature(
                trusted_peer_public_key=node_public_key,
                expected_role=ROLE_NODE,
                transcript=transcript,
                signature=bytes(tampered_signature),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
```

## Run tests

From your `hw2` directory:

```bash
source .venv/bin/activate
python3 -m unittest -v test_security.py
```

A successful run should show six passing tests:

```text
test_01_valid_handshake_and_bidirectional_messages ... ok
test_02_modified_ciphertext_rejected ... ok
test_03_modified_authenticated_header_rejected ... ok
test_04_replayed_record_rejected ... ok
test_05_reflected_record_rejected_in_opposite_direction ... ok
test_06_invalid_handshake_signature_rejected ... ok

----------------------------------------------------------------------
Ran 6 tests in ...

OK
```

## What each test proves

| Test | Attack / scenario | Specific safe failure asserted |
|---|---|---|
| `test_01_valid_handshake_and_bidirectional_messages` | Normal handshake and messages in both directions | Correct plaintext returned; sender/receiver states advance to 1 |
| `test_02_modified_ciphertext_rejected` | One ciphertext bit is changed | `RecordError: HMAC verification failed`; no plaintext and receiver remains at sequence 0 |
| `test_03_modified_authenticated_header_rejected` | `message_type` header byte is changed | `RecordError: HMAC verification failed`; no plaintext and receiver remains at sequence 0 |
| `test_04_replayed_record_rejected` | Same sequence-zero record sent twice | `RecordError: Record sequence is not the expected next sequence` |
| `test_05_reflected_record_rejected_in_opposite_direction` | Gateway→node record delivered as node→gateway | `RecordError: Record is in the wrong direction` |
| `test_06_invalid_handshake_signature_rejected` | Node RSA-PSS signature is modified | `HandshakeError: RSA-PSS signature verification failed` |

## Security note for Task 4

You can include this concise note in your report:

> The record layer uses Encrypt-then-MAC: AES-256-CTR encrypts plaintext, while HMAC-SHA-256 authenticates the complete `header || iv || ciphertext` representation. The receiver verifies the HMAC before decrypting, so a modified header, IV, ciphertext, or tag causes rejection without releasing plaintext. Direction-specific encryption and MAC keys prevent a record from one traffic direction from being valid in the opposite direction. Per-direction sequence numbers begin at zero and must match exactly at the receiver; this prevents replay, skipped, and out-of-order records. The IV is constructed as `session_id || sequence`, and sender sequence numbers only advance, so an IV is never reused under a single directional AES key. The handshake binds identities, roles, nonces, and ephemeral DH public values into RSA-PSS-signed transcripts, preventing unauthenticated DH substitution and basic reflection attacks.
