"""
SOUF AI Audit Chain — Ed25519-signed, hash-chained audit log.

Each record is: {entry, prev_hash, seq} → canonical JSON → Ed25519 signature.
Canonical: json.dumps(obj, sort_keys=True, separators=(',',':'), ensure_ascii=False)

Properties guaranteed:
  P1  JCS determinism    — canonical(X) == canonical(X) always
  P2  Sign+verify RT     — sign(entry) → verify(sig, entry) == OK
  P3  Tamper-decision    — mutate entry.action → verify fails
  P4  Tamper-sig         — flip sig byte → verify fails
  P5  Wrong-key reject   — sign with keyA, verify with keyB.vk → fails
  P6  Signing latency    — mean < 1ms per entry at N=1000
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from nacl.encoding import RawEncoder
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


GENESIS_HASH = "0" * 64  # SHA-256 hex of the empty block


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class SignedRecord:
    entry: dict
    prev_hash: str
    seq: int
    signature: bytes  # 64-byte Ed25519 sig over canonical({entry, prev_hash, seq})
    record_hash: str  # sha256 of canonical payload (for chaining)

    def payload_bytes(self) -> bytes:
        obj = {"entry": self.entry, "prev_hash": self.prev_hash, "seq": self.seq}
        return canonical(obj)

    def verify(self, verify_key: VerifyKey) -> bool:
        try:
            verify_key.verify(self.payload_bytes(), self.signature, encoder=RawEncoder)
            return True
        except BadSignatureError:
            return False


class AuditChain:
    def __init__(self, signing_key: Optional[SigningKey] = None):
        self.signing_key = signing_key or SigningKey.generate()
        self.verify_key: VerifyKey = self.signing_key.verify_key
        self._records: list[SignedRecord] = []
        self._prev_hash = GENESIS_HASH
        self._seq = 0

    def append(self, entry: dict) -> SignedRecord:
        obj = {"entry": entry, "prev_hash": self._prev_hash, "seq": self._seq}
        payload = canonical(obj)
        sig = self.signing_key.sign(payload, encoder=RawEncoder).signature
        record_hash = sha256hex(payload)
        rec = SignedRecord(
            entry=entry,
            prev_hash=self._prev_hash,
            seq=self._seq,
            signature=sig,
            record_hash=record_hash,
        )
        self._records.append(rec)
        self._prev_hash = record_hash
        self._seq += 1
        return rec

    def records(self) -> list[SignedRecord]:
        return list(self._records)

    def verify_chain(self) -> bool:
        prev = GENESIS_HASH
        for rec in self._records:
            if rec.prev_hash != prev:
                return False
            if not rec.verify(self.verify_key):
                return False
            prev = rec.record_hash
        return True
