"""Evaluate the captured packet's OTS operations, not Bitcoin chain authenticity.

This fixture-only reader supports SHA256, append and prepend. It deliberately
rejects other operations; it is not a public/general OpenTimestamps verifier.
Format reference (timestamp.py, op.py, notary.py):
https://github.com/opentimestamps/python-opentimestamps/tree/3af46432efc4a4c4e7bba439c1f49bce808eb3e5/opentimestamps/core
"""
import hashlib
import io
import socket
import unittest
from pathlib import Path
from unittest.mock import patch

PACKET = Path(__file__).resolve().parents[1] / 'docs/evidence/witness-2026-10-20-nenrin'
MAGIC = b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
BITCOIN = bytes.fromhex('0588960d73d71901')
HEIGHT = 972264
# A comparison target supplied by the packet author, NOT an authenticated header.
ROOT = bytes.fromhex('81b695d07d509468fab75fa9dc550808302bb6a7cf667a34058395b06d949653')[::-1]


def commitments(proof, record):
    """Return (height, computed digest) for Bitcoin leaves in this bounded fixture."""
    if len(proof) > 8192:
        raise ValueError('proof too large')
    stream = io.BytesIO(proof)

    def take(n):
        data = stream.read(n)
        if len(data) != n:
            raise ValueError('truncated proof')
        return data

    def integer():
        value = 0
        for shift in range(0, 35, 7):
            byte = take(1)[0]
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError('oversized integer')

    def blob():
        size = integer()
        if size > 4096:
            raise ValueError('oversized field')
        return take(size)

    if take(len(MAGIC)) != MAGIC or integer() != 1 or take(1) != b'\x08':
        raise ValueError('unsupported header')
    digest = take(32)
    if digest != hashlib.sha256(record).digest():
        raise ValueError('record digest mismatch')
    results = []
    budget = 512

    def node(message, depth=0):
        nonlocal budget
        if depth > 128 or len(message) > 4096:
            raise ValueError('fixture limit exceeded')
        while True:
            budget -= 1
            if budget < 0:
                raise ValueError('too many operations')
            tag = take(1)[0]
            more = tag == 255
            if more:
                tag = take(1)[0]
            if tag == 0:
                kind, payload = take(8), blob()
                if kind == BITCOIN:
                    height = 0
                    for i, byte in enumerate(payload):
                        if i >= 5:
                            raise ValueError('oversized height')
                        height |= (byte & 127) << (7 * i)
                        if not byte & 128:
                            if i != len(payload) - 1:
                                raise ValueError('trailing height bytes')
                            results.append((height, message))
                            break
                    else:
                        raise ValueError('truncated height')
                # Other attestations are opaque, length-delimited assertions.
            elif tag == 8:
                node(hashlib.sha256(message).digest(), depth + 1)
            elif tag in (240, 241):
                operand = blob()
                if not operand:
                    raise ValueError('empty operand')
                node(message + operand if tag == 240 else operand + message, depth + 1)
            else:
                raise ValueError('unsupported operation')
            if not more:
                return

    node(digest)
    if stream.read(1):
        raise ValueError('trailing proof bytes')
    return results


class NenrinOTSOperationsTests(unittest.TestCase):
    def setUp(self):
        self.proof = (PACKET / 'jidec-127.txt.ots').read_bytes()
        self.record = (PACKET / 'jidec-127.txt').read_bytes()

    def test_captured_operations_reach_reported_root_offline(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            self.assertEqual(commitments(self.proof, self.record), [(HEIGHT, ROOT)])

    def test_changed_operand_keeps_header_and_attestation_but_changes_root(self):
        damaged = bytearray(self.proof)
        # First append operand follows magic, version, hash tag, digest, op and length.
        offset = len(MAGIC) + 2 + 32 + 2
        self.assertEqual(self.proof[offset - 2:offset], b'\xf0\x10')
        damaged[offset] ^= 1
        self.assertEqual(damaged[:offset], self.proof[:offset])
        self.assertIn(BITCOIN + bytes.fromhex('03e8ab3b'), damaged)
        actual = commitments(bytes(damaged), self.record)
        self.assertEqual([height for height, _ in actual], [HEIGHT])
        self.assertNotEqual(actual, [(HEIGHT, ROOT)])

    def test_changed_record_rejected_before_operations(self):
        with self.assertRaisesRegex(ValueError, 'record digest mismatch'):
            commitments(self.proof, self.record + b'x')

    def test_small_append_prepend_hash_and_branch_controls(self):
        record = b'fixture'
        digest = hashlib.sha256(record).digest()
        header = MAGIC + b'\x01\x08' + digest
        leaf = b'\x00' + BITCOIN + b'\x01\x01'
        # Two siblings both start from the same digest, not the previous result.
        proof = header + b'\xff\xf0\x01a\x08' + leaf + b'\xf1\x01b\x08' + leaf
        self.assertEqual(commitments(proof, record), [
            (1, hashlib.sha256(digest + b'a').digest()),
            (1, hashlib.sha256(b'b' + digest).digest()),
        ])

    def test_truncated_trailing_and_unknown_operation_refused(self):
        unknown = bytearray(self.proof)
        unknown[len(MAGIC) + 2 + 32] = 0xfe
        for proof in (self.proof[:-1], self.proof + b'x', bytes(unknown)):
            with self.subTest(proof_length=len(proof)):
                with self.assertRaises(ValueError):
                    commitments(proof, self.record)


if __name__ == '__main__':
    unittest.main()
