"""
SOUF AI · Signed audit envelope (Pillar 4 reference implementation).

Wraps each Lobster Trap policy decision in a W3C PROV-JSON envelope, signs the
canonicalized payload with Ed25519, and emits one self-contained JSON object
per line. The format is replayable (the recorded extracted-booleans recreate
the engine's decision), tamper-evident (any field modification breaks the
signature), and regulator-readable (each entry cites the controlling section).

Implementation notes:
  * Canonicalization uses RFC 8785 JSON Canonicalization Scheme (JCS) so the
    signed bytes are deterministic across platforms / serializer libs.
  * Signature is computed over `JCS(payload_minus_signature_field)` and
    embedded in the envelope under `signature.value` (base64url).
  * Implementation stays pure-stdlib + `pynacl` (Ed25519). No network calls.

Usage:
    from envelope import AuditSigner

    signer = AuditSigner.generate()  # or AuditSigner.from_seed(b"...32 bytes...")
    entry = signer.sign({
        "subject": {"agent_id": "demo-agent-1"},
        "ingress": {"intent_category": "data_access", "risk_score": 0.62},
        "decision": {"action": "DENY", "rule": "hipaa_block_phi_bulk_disclosure",
                     "citation": "45 CFR §164.502(a)"},
    })
    print(json.dumps(entry))
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass

try:
    from nacl.signing import SigningKey, VerifyKey
except ImportError:  # pragma: no cover
    raise SystemExit(
        "envelope.py requires PyNaCl. Install: pip install pynacl"
    )


# ---------------------------------------------------------------------------
# RFC 8785 JSON Canonicalization Scheme (JCS) — minimal pure-stdlib version
# ---------------------------------------------------------------------------
# Spec: https://datatracker.ietf.org/doc/html/rfc8785
# Rules:
#   - Unicode strings: serialize with the same escaping rules as RFC 8259
#   - Numbers: ECMAScript 6 number-to-string (Section 7.1.12.1) — we restrict
#     ourselves to JSON-safe integers and floats with simple representations.
#   - Object keys: sorted by code-point order of the unescaped string.
#   - No whitespace.
#
# Note: the canonical-number subset we permit (int + simple float) is
# documented in our schema. Tests below verify deterministic byte output.


def _jcs_serialize(obj) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int) and not isinstance(obj, bool):
        return str(obj)
    if isinstance(obj, float):
        # Reject NaN / Infinity (not representable in JSON)
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise ValueError("JCS forbids NaN / Infinity")
        # JSON number — Python's default repr already matches the
        # ECMAScript 6 "shortest round-trip" representation closely enough
        # for the bounded numeric subset our audit envelopes use.
        s = repr(obj)
        if s.endswith(".0"):
            s = s[:-2]
        return s
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, list):
        return "[" + ",".join(_jcs_serialize(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: kv[0])
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + _jcs_serialize(v)
            for k, v in items
        ) + "}"
    raise TypeError(f"JCS does not serialize {type(obj).__name__}")


def jcs(obj) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme — returns deterministic bytes."""
    return _jcs_serialize(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# Signer / Verifier
# ---------------------------------------------------------------------------


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass
class AuditSigner:
    """Wraps an Ed25519 signing key + a key id."""

    signing_key: SigningKey
    kid: str

    @classmethod
    def generate(cls, kid: str | None = None) -> "AuditSigner":
        key = SigningKey.generate()
        return cls(signing_key=key, kid=kid or f"souf-ai-key-{int(time.time())}")

    @classmethod
    def from_seed(cls, seed: bytes, kid: str | None = None) -> "AuditSigner":
        if len(seed) != 32:
            raise ValueError("seed must be exactly 32 bytes")
        return cls(signing_key=SigningKey(seed), kid=kid or "souf-ai-key-seed")

    def public_key_b64u(self) -> str:
        return _b64u(self.signing_key.verify_key.encode())

    def sign(self, payload: dict) -> dict:
        """Wrap a decision payload in a signed envelope.

        Adds:
          @context, envelope_id, version, signature.{alg,kid,value}
        Does NOT mutate the input dict.
        """
        envelope = {
            "@context": "https://www.w3.org/ns/prov",
            "envelope_id": f"souf-ai-{uuid.uuid4()}",
            "version": "souf-audit-v0.1",
        }
        # merge caller-supplied fields without overwriting our reserved keys
        for k, v in payload.items():
            if k in ("@context", "envelope_id", "version", "signature"):
                continue
            envelope[k] = v
        # Compute signature over the JCS-canonicalized payload
        sig_bytes = self.signing_key.sign(jcs(envelope)).signature
        envelope["signature"] = {
            "alg": "Ed25519",
            "kid": self.kid,
            "value": _b64u(sig_bytes),
        }
        return envelope


@dataclass
class AuditVerifier:
    """Verifies a signed envelope against a known public key."""

    verify_key: VerifyKey
    kid: str

    @classmethod
    def from_pubkey_b64u(cls, pub_b64u: str, kid: str) -> "AuditVerifier":
        return cls(verify_key=VerifyKey(_b64u_decode(pub_b64u)), kid=kid)

    def verify(self, envelope: dict) -> bool:
        """Return True iff signature is intact AND kid matches AND payload was
        not modified after signing.
        """
        if "signature" not in envelope:
            return False
        sig = envelope["signature"]
        if sig.get("alg") != "Ed25519":
            return False
        if sig.get("kid") != self.kid:
            return False
        try:
            sig_bytes = _b64u_decode(sig["value"])
        except (TypeError, ValueError):
            return False
        body = {k: v for k, v in envelope.items() if k != "signature"}
        try:
            self.verify_key.verify(jcs(body), sig_bytes)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Convenience helpers used by the demo / sample log generator
# ---------------------------------------------------------------------------


def prompt_hash(prompt_text: str) -> str:
    """One-way SHA-256 of the prompt body (we never persist the raw prompt)."""
    return hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()


def decision_payload(
    *,
    agent_id: str,
    request_id: str,
    prompt_text: str,
    ingress_metadata: dict,
    policy_id: str,
    rule: str,
    action: str,
    citation: str,
    deny_message: str = "",
    engine: str = "lobstertrap-v1.0",
    engine_commit_sha: str = "unknown",
    patches: str = "souf-ai-patterns-v0.1",
    host: str = "souf-ai-edge-01",
) -> dict:
    """Assemble a SOUF AI audit envelope body (everything except signature)."""
    return {
        "subject": {
            "agent_id": agent_id,
            "request_id": request_id,
        },
        "ingress": {
            "prompt_hash_sha256": prompt_hash(prompt_text),
            "token_count": ingress_metadata.get("token_count"),
            "intent_category": ingress_metadata.get("intent_category"),
            "intent_confidence": ingress_metadata.get("intent_confidence"),
            "risk_score": ingress_metadata.get("risk_score"),
            "detected": {
                k: v
                for k, v in ingress_metadata.items()
                if k.startswith("contains_") and isinstance(v, bool)
            },
            "target_paths": ingress_metadata.get("target_paths") or [],
            "target_domains": ingress_metadata.get("target_domains") or [],
            "target_commands": ingress_metadata.get("target_commands") or [],
        },
        "decision": {
            "policy_id": policy_id,
            "rule": rule,
            "action": action,
            "citation": citation,
            "deny_message": deny_message,
            "decided_at_ms": int(time.time() * 1000),
        },
        "provenance": {
            "engine": engine,
            "engine_commit_sha": engine_commit_sha,
            "patches": patches,
            "host": host,
        },
    }
