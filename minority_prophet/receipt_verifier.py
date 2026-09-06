"""Fail-closed reference verifier for signed evidence receipts.

This is an intentionally small local reference.  It uses operator-managed HMAC
keys so the complete path can be exercised without a vendor account.  A
production cross-organization deployment should replace it with asymmetric
signatures, workload identity, or a trust-service callback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping

from .adapter_acp import AttestationVerifier
from .evidence_audit import canonical_json_bytes


RECEIPT_SCHEMA = "minority-prophet.signed-evidence-receipt.v1"


def _unsigned_envelope(envelope: dict) -> dict:
    value = json.loads(canonical_json_bytes(envelope).decode("utf-8"))
    attest = value.get("attest")
    if isinstance(attest, dict):
        attest.pop("sig", None)
    return value


def sign_receipt_envelope(envelope: dict, key: bytes) -> dict:
    """Return a copy bearing an HMAC over the complete evidence envelope."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("receipt key must contain at least 32 bytes")
    value = _unsigned_envelope(envelope)
    attest = value.setdefault("attest", {})
    attest["sig"] = "hmac-sha256:" + hmac.new(
        key, canonical_json_bytes(value), hashlib.sha256
    ).hexdigest()
    return value


class SignedReceiptVerifier(AttestationVerifier):
    """Authenticate receipts and fail closed on manufactured independence.

    Each trusted issuer has a key and a control domain.  A fresh root receipt
    must name a stable ``root_id``.  Repeated use of that root is accepted only
    when the new claim explicitly derives from an already accepted claim in
    the same family.  It can therefore add an echo, but never another root.

    The verifier is stateful for one case/evidence batch.  Use a separate
    instance per decision subject; callers must not share it between cases.
    """

    def __init__(self, issuer_keys: Mapping[str, bytes],
                 issuer_control_domains: Mapping[str, str]) -> None:
        self._keys = dict(issuer_keys)
        self._domains = dict(issuer_control_domains)
        if set(self._keys) != set(self._domains):
            raise ValueError("issuer keys and control domains must name the same issuers")
        if not self._keys:
            raise ValueError("at least one trusted receipt issuer is required")
        if any(not isinstance(key, bytes) or len(key) < 32 for key in self._keys.values()):
            raise ValueError("every receipt key must contain at least 32 bytes")
        if any(not domain for domain in self._domains.values()):
            raise ValueError("every receipt issuer needs a control domain")
        self._claims: dict[str, tuple[str, int, object, str]] = {}
        self._roots: dict[str, str] = {}

    def verify(self, env: dict) -> str:
        try:
            claim_id = env["claim_id"]
            assertion = env["assertion"]
            attest = env["attest"]
            issuer = attest["issuer"]
            schema = attest["schema"]
            root_id = attest["root_id"]
            signature = attest["sig"]
            subject = attest["subject"]
        except (KeyError, TypeError):
            return "invalid"
        if not all(isinstance(item, str) and item for item in
                   (claim_id, issuer, schema, root_id, signature, subject)):
            return "invalid"
        if schema != RECEIPT_SCHEMA or issuer not in self._keys:
            return "invalid"
        if attest.get("control_domain") != self._domains[issuer]:
            return "invalid"
        if not signature.startswith("hmac-sha256:"):
            return "invalid"
        expected = hmac.new(
            self._keys[issuer], canonical_json_bytes(_unsigned_envelope(env)),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature.removeprefix("hmac-sha256:"), expected):
            return "invalid"

        prior = self._claims.get(claim_id)
        record = (root_id, assertion, subject, self._domains[issuer])
        if prior is not None:
            if prior != record:
                return "invalid"
            return "derived" if attest.get("derived_from") else "root"

        parent_id = attest.get("derived_from")
        canonical_root = self._roots.get(root_id)
        if canonical_root is None:
            if parent_id is not None:
                return "invalid"
            self._roots[root_id] = claim_id
            self._claims[claim_id] = record
            return "root"

        # A repeated root without a declared, already verified parent is a
        # manufactured vote.  Quarantine it instead of guessing a lineage.
        if not isinstance(parent_id, str) or parent_id not in self._claims:
            return "invalid"
        parent_root, parent_assertion, parent_subject, _parent_domain = self._claims[parent_id]
        if (parent_root != root_id or parent_assertion != assertion or
                parent_subject != subject):
            return "invalid"
        self._claims[claim_id] = record
        return "derived"
