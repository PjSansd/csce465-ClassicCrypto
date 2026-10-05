#!/usr/bin/env python3
"""
Task 4 adversarial tests.

Run from the hw2 project root:

    python3 -m unittest discover -s tests -v
"""

import unittest

from handshake import HandshakeError, run_handshake
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
    Every test starts from a fresh valid authenticated Task 2 session.

    This prevents sequence state, ephemeral DH values, nonces, and session
    keys from leaking between independent tests.
    """

    def setUp(self):
        """
        Create a valid Task 2 handshake.

        Expected run_handshake() return structure:

            {
                "transcript": ...,
                "node_signature": ...,
                "gateway_signature": ...,
                "gateway_rsa_public": ...,
                "node_rsa_public": ...,
                "gateway_keys": SessionKeys(...),
                "node_keys": SessionKeys(...),
            }
        """
        self.handshake = run_handshake()

        self.session_id = self.handshake["gateway_keys"].session_id

        self.k_g2n_enc = self.handshake["gateway_keys"].k_g2n_enc
        self.k_g2n_mac = self.handshake["gateway_keys"].k_g2n_mac

        self.k_n2g_enc = self.handshake["gateway_keys"].k_n2g_enc
        self.k_n2g_mac = self.handshake["gateway_keys"].k_n2g_mac

    def make_gateway_to_node_record(self, plaintext=b"gateway command"):
        """
        Return a valid sequence-zero gateway-to-node record.

        This creates a new sender state for each attack test so every record
        begins at sequence 0 and every test has independent state.
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

    def test_01_valid_handshake_and_bidirectional_messages(self):
        """
        Requirement 1:
        Valid authenticated handshake plus valid application records in both
        gateway->node and node->gateway directions.
        """
        self.assertEqual(
            self.handshake["gateway_keys"],
            self.handshake["node_keys"],
        )

        gateway_to_node_sender = SenderState()
        node_from_gateway_receiver = ReceiverState()

        gateway_message = b'{"action":"READ","path":"notes.txt"}'

        g2n_record = seal(
            plaintext=gateway_message,
            message_type=MESSAGE_TYPE_COMMAND,
            direction=DIRECTION_GATEWAY_TO_NODE,
            session_id=self.session_id,
            k_enc=self.k_g2n_enc,
            k_mac=self.k_g2n_mac,
            state=gateway_to_node_sender,
        )

        message_type, plaintext = open_record(
            record=g2n_record,
            expected_direction=DIRECTION_GATEWAY_TO_NODE,
            session_id=self.session_id,
            k_enc=self.k_g2n_enc,
            k_mac=self.k_g2n_mac,
            state=node_from_gateway_receiver,
        )

        self.assertEqual(message_type, MESSAGE_TYPE_COMMAND)
        self.assertEqual(plaintext, gateway_message)
        self.assertEqual(gateway_to_node_sender.next_sequence, 1)
        self.assertEqual(node_from_gateway_receiver.expected_sequence, 1)

        node_to_gateway_sender = SenderState()
        gateway_from_node_receiver = ReceiverState()

        node_message = b'{"status":"OK","temperature":22}'

        n2g_record = seal(
            plaintext=node_message,
            message_type=MESSAGE_TYPE_STATUS,
            direction=DIRECTION_NODE_TO_GATEWAY,
            session_id=self.session_id,
            k_enc=self.k_n2g_enc,
            k_mac=self.k_n2g_mac,
            state=node_to_gateway_sender,
        )

        message_type, plaintext = open_record(
            record=n2g_record,
            expected_direction=DIRECTION_NODE_TO_GATEWAY,
            session_id=self.session_id,
            k_enc=self.k_n2g_enc,
            k_mac=self.k_n2g_mac,
            state=gateway_from_node_receiver,
        )

        self.assertEqual(message_type, MESSAGE_TYPE_STATUS)
        self.assertEqual(plaintext, node_message)
        self.assertEqual(node_to_gateway_sender.next_sequence, 1)
        self.assertEqual(gateway_from_node_receiver.expected_sequence, 1)

    def test_02_modified_ciphertext_rejected(self):
        """
        Requirement 2:
        Flip a ciphertext bit but keep the original HMAC tag.

        Safe failure expected:
            RecordError: HMAC verification failed

        The receiver remains at expected sequence zero and returns no
        plaintext because HMAC verification occurs before decryption.
        """
        record = self.make_gateway_to_node_record(
            b'{"action":"READ","path":"notes.txt"}'
        )

        tampered_record = bytearray(record)

        ciphertext_start = HEADER_LENGTH + IV_LENGTH
        tampered_record[ciphertext_start] ^= 0x01

        receiver = ReceiverState()

        with self.assertRaisesRegex(
            RecordError,
            "HMAC verification failed",
        ):
            open_record(
                record=bytes(tampered_record),
                expected_direction=DIRECTION_GATEWAY_TO_NODE,
                session_id=self.session_id,
                k_enc=self.k_g2n_enc,
                k_mac=self.k_g2n_mac,
                state=receiver,
            )

        self.assertEqual(receiver.expected_sequence, 0)

    def test_03_modified_authenticated_header_rejected(self):
        """
        Requirement 3:
        Change the one-byte message_type in the authenticated header.

        Header layout:
            byte 0: version
            byte 1: direction
            bytes 2-9: sequence
            byte 10: message_type
            bytes 11-14: ciphertext length

        Because the HMAC covers header || IV || ciphertext, changing byte 10
        without making a new valid tag must cause HMAC failure.
        """
        record = self.make_gateway_to_node_record(b"header integrity test")

        tampered_record = bytearray(record)
        message_type_offset = 10
        tampered_record[message_type_offset] ^= 0x01

        receiver = ReceiverState()

        with self.assertRaisesRegex(
            RecordError,
            "HMAC verification failed",
        ):
            open_record(
                record=bytes(tampered_record),
                expected_direction=DIRECTION_GATEWAY_TO_NODE,
                session_id=self.session_id,
                k_enc=self.k_g2n_enc,
                k_mac=self.k_g2n_mac,
                state=receiver,
            )

        self.assertEqual(receiver.expected_sequence, 0)

    def test_04_replayed_record_rejected(self):
        """
        Requirement 4:
        Accept a valid sequence-zero record once, then send exactly the same
        record again.

        Safe failure expected:
            RecordError: Record sequence is not the expected next sequence
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

    def test_05_reflected_record_rejected(self):
        """
        Requirement 5:
        Create a valid gateway->node record and attempt to deliver it as
        node->gateway traffic.

        Safe failure expected:
            RecordError: Record is in the wrong direction

        The record also has the wrong directional key pair for node->gateway
        traffic. Direction is checked first for a clear rejection reason.
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

    def test_06_invalid_rsa_pss_signature_rejected(self):
        """
        Requirement 6:
        Alter a valid node RSA-PSS signature, then verify it against the
        unchanged transcript and configured node public key.

        Safe failure expected:
            HandshakeError: RSA-PSS signature verification failed
        """
        from handshake import ROLE_NODE, verify_transcript_signature

        transcript = self.handshake["transcript"]
        node_signature = self.handshake["node_signature"]
        node_public_key = self.handshake["node_rsa_public"]

        tampered_signature = bytearray(node_signature)
        tampered_signature[0] ^= 0x01

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
