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


class HttpEvidenceCollector:
    """Call any service implementing the neutral evidence-collector contract.

    The Gate owns transport safety and exact dispatch binding. The configured
    service owns its domain payload and evidence schema. Remote hosts are
    denied unless explicitly opted in; remote plaintext HTTP is always denied.
    """

    def __init__(
        self,
        descriptor: CollectorDescriptor,
        endpoint: str,
        input_for: Callable[[EvidenceDispatch], dict],
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
            raise EvidenceRoutingError("remote evidence endpoints require opt-in")
        if (allow_remote and parsed.scheme != "https" and
                parsed.hostname not in {"127.0.0.1", "localhost", "::1"}):
            raise EvidenceRoutingError("remote evidence endpoints require HTTPS")
        if not bearer_token:
            raise EvidenceRoutingError("evidence service bearer token is required")
        self.descriptor = descriptor
        self.endpoint = endpoint
        self.input_for = input_for
        self.bearer_token = bearer_token
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes

    def collect(self, dispatch: EvidenceDispatch) -> EvidenceCollectionResult:
        service_input = self.input_for(dispatch)
        if not isinstance(service_input, dict):
            raise EvidenceRoutingError("evidence service input must be an object")
        request_body = {
            "schema": "evidence-collector.request.v1",
            "dispatch": dispatch.to_dict(),
            "input": service_input,
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
            # The constructor rejects non-HTTP(S) schemes and requires explicit
            # opt-in plus TLS for remote hosts, so file:// cannot reach urlopen.
            with urllib.request.urlopen(  # nosemgrep: dynamic-urllib-use-detected
                request, timeout=self.timeout_seconds
            ) as response:
                raw = response.read(self.max_response_bytes + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise EvidenceRoutingError("evidence service request failed") from exc
        if len(raw) > self.max_response_bytes:
            raise EvidenceRoutingError("evidence service response exceeded limit")
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceRoutingError("evidence service returned invalid JSON") from exc
        expected = {
            "schema": "evidence-collector.response.v1",
            "challenge_id": dispatch.challenge_id,
            "dispatch_id": dispatch.dispatch_id,
            "collector_id": self.descriptor.collector_id,
            "grants_protected_action_authority": False,
        }
        if not isinstance(parsed, dict):
            raise EvidenceRoutingError("evidence service response must be an object")
        for key, value in expected.items():
            if parsed.get(key) != value:
                raise EvidenceRoutingError(f"evidence service substituted {key}")
        raw_items = parsed.get("items")
        if not isinstance(raw_items, list):
            raise EvidenceRoutingError("evidence service items must be an array")
        try:
            items = tuple(
                CollectedEvidence(
                    item["requirement_id"],
                    item["evidence_kind"],
                    item["envelope"],
                )
                for item in raw_items
            )
        except (KeyError, TypeError) as exc:
            raise EvidenceRoutingError("evidence service item is invalid") from exc
        diagnostics = parsed.get("diagnostics", {})
        if not isinstance(diagnostics, dict):
            raise EvidenceRoutingError("evidence service diagnostics must be an object")
        return EvidenceCollectionResult(
            dispatch.dispatch_id,
            dispatch.challenge_id,
            self.descriptor.collector_id,
            parsed.get("status", "failed"),
            items,
            diagnostics,
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
