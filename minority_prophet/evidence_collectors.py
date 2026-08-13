"""Concrete, constrained collectors for the provider-neutral evidence router."""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from .evidence_audit import EvidenceRoutingError, canonical_json_bytes
from .evidence_router import (
    CollectedEvidence,
    CollectorDescriptor,
    EvidenceCollectionResult,
    EvidenceDispatch,
)


class HumanQueueCollector:
    """Persist a human handoff without fabricating a human decision."""

    def __init__(self, descriptor: CollectorDescriptor, ledger: object) -> None:
        self.descriptor = descriptor
        self.ledger = ledger

    def collect(self, dispatch: EvidenceDispatch) -> EvidenceCollectionResult:
        if self.descriptor.collector_kind != "human":
            raise EvidenceRoutingError("human queue requires a human descriptor")
        self.ledger.enqueue_human_review(dispatch)
        return EvidenceCollectionResult(
            dispatch.dispatch_id,
            dispatch.challenge_id,
            self.descriptor.collector_id,
            "needs_human",
        )


class HttpEpistemicCollector:
    """Call a bound read-only epistemic service and return its receipt.

    The packet and proposal callbacks are application-owned.  The adapter sends
    them directly over the configured transport; no model reconstructs or
    rewrites the packet.  Remote hosts are denied unless explicitly opted in.
    """

    def __init__(
        self,
        descriptor: CollectorDescriptor,
        endpoint: str,
        packet_for: Callable[[EvidenceDispatch], dict],
        proposal_for: Callable[[EvidenceDispatch], dict],
        *,
        bearer_token: str,
        timeout_seconds: float = 10.0,
        allow_remote: bool = False,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise EvidenceRoutingError("epistemic endpoint must be an HTTP(S) URL")
        if (not allow_remote and
                parsed.hostname not in {"127.0.0.1", "localhost", "::1"}):
            raise EvidenceRoutingError("remote epistemic endpoints require opt-in")
        if not bearer_token:
            raise EvidenceRoutingError("epistemic service bearer token is required")
        self.descriptor = descriptor
        self.endpoint = endpoint
        self.packet_for = packet_for
        self.proposal_for = proposal_for
        self.bearer_token = bearer_token
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes

    def collect(self, dispatch: EvidenceDispatch) -> EvidenceCollectionResult:
        if self.descriptor.collector_kind != "epistemic_service":
            raise EvidenceRoutingError(
                "HTTP epistemic collector requires an epistemic_service descriptor"
            )
        request_body = {
            "schema": "mp-provenance-service-request.v1",
            "challenge_id": dispatch.challenge_id,
            "dispatch_id": dispatch.dispatch_id,
            "action_digest": dispatch.action_digest,
            "decision_subject": dispatch.decision_subject,
            "packet": self.packet_for(dispatch),
            "proposal": self.proposal_for(dispatch),
            "grants_protected_action_authority": False,
        }
        request = urllib.request.Request(
            self.endpoint,
            data=canonical_json_bytes(request_body),
            method="POST",
            headers={
                "authorization": f"Bearer {self.bearer_token}",
                "content-type": "application/json",
                "accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise EvidenceRoutingError("epistemic service request failed") from exc
        if len(raw) > self.max_response_bytes:
            raise EvidenceRoutingError("epistemic service response exceeded limit")
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceRoutingError("epistemic service returned invalid JSON") from exc
        expected = {
            "schema": "mp-provenance-service-response.v1",
            "challenge_id": dispatch.challenge_id,
            "dispatch_id": dispatch.dispatch_id,
            "action_digest": dispatch.action_digest,
            "decision_subject": dispatch.decision_subject,
            "output_role": "verification_artifact",
            "grants_protected_action_authority": False,
        }
        if not isinstance(parsed, dict):
            raise EvidenceRoutingError("epistemic service response must be an object")
        for key, value in expected.items():
            if parsed.get(key) != value:
                raise EvidenceRoutingError(f"epistemic service substituted {key}")
        receipt = parsed.get("receipt")
        forbidden = {
            "assertion", "answer", "correct_answer", "ground_truth",
            "recommended_answer",
        }
        if (
            not isinstance(receipt, dict)
            or receipt.get("schema") != "mp-provenance-receipt.v1"
            or receipt.get("answer_included") is not False
            or receipt.get("ground_truth_included") is not False
            or forbidden.intersection(receipt)
        ):
            raise EvidenceRoutingError("epistemic receipt is invalid")
        items = tuple(
            CollectedEvidence(
                requirement.requirement_id,
                requirement.accepted_kinds[0],
                {
                    **receipt,
                    "attest": {
                        "origin": self.descriptor.collector_id,
                        "subject": dispatch.decision_subject,
                        "evidence_kind": requirement.accepted_kinds[0],
                    },
                },
            )
            for requirement in dispatch.requirements
        )
        return EvidenceCollectionResult(
            dispatch.dispatch_id,
            dispatch.challenge_id,
            self.descriptor.collector_id,
            "completed",
            items,
        )


class ConstrainedSubprocessCollector:
    """Run one fixed, hashed command via JSON stdin/stdout and no shell."""

    def __init__(
        self,
        descriptor: CollectorDescriptor,
        command: tuple[str, ...],
        expected_file_sha256: dict[str, str],
        *,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 2_000_000,
        environment: dict[str, str] | None = None,
    ) -> None:
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise EvidenceRoutingError("program command must be a fixed non-empty tuple")
        if not Path(command[0]).is_absolute():
            raise EvidenceRoutingError("program executable path must be absolute")
        if not expected_file_sha256:
            raise EvidenceRoutingError("program files must be pinned by SHA-256")
        self.descriptor = descriptor
        self.command = command
        self.expected_file_sha256 = dict(expected_file_sha256)
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.environment = dict(environment or {})

    def _verify_files(self) -> None:
        for name, expected in self.expected_file_sha256.items():
            path = Path(name)
            if not path.is_absolute() or not path.is_file():
                raise EvidenceRoutingError("pinned program file is unavailable")
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if not hmac_compare(actual, expected):
                raise EvidenceRoutingError("pinned program file digest changed")

    def collect(self, dispatch: EvidenceDispatch) -> EvidenceCollectionResult:
        if self.descriptor.collector_kind != "program":
            raise EvidenceRoutingError("subprocess collector requires program descriptor")
        self._verify_files()
        payload = canonical_json_bytes({
            "schema": "minority-prophet.program-dispatch.v1",
            "dispatch": dispatch.to_dict(),
            "grants_protected_action_authority": False,
        })
        try:
            completed = subprocess.run(
                self.command,
                input=payload,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
                cwd=str(Path(self.command[0]).parent),
                env=self.environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvidenceRoutingError("constrained program failed to run") from exc
        if completed.returncode != 0:
            raise EvidenceRoutingError("constrained program returned a failure status")
        if len(completed.stdout) > self.max_response_bytes:
            raise EvidenceRoutingError("constrained program response exceeded limit")
        try:
            value = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceRoutingError("constrained program returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise EvidenceRoutingError("constrained program response must be an object")
        items = tuple(
            CollectedEvidence(
                item["requirement_id"], item["evidence_kind"], item["envelope"]
            )
            for item in value.get("items", [])
        )
        return EvidenceCollectionResult(
            dispatch.dispatch_id,
            dispatch.challenge_id,
            self.descriptor.collector_id,
            value.get("status", "failed"),
            items,
            {"program_response_schema": value.get("schema")},
        )


def hmac_compare(actual: str, expected: str) -> bool:
    """Constant-time text comparison without accepting non-string digests."""
    if not isinstance(expected, str):
        return False
    return hmac.compare_digest(actual, expected)
