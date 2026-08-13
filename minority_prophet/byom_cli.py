"""Safe file/pipe harness for adversarial Minority Prophet evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from .adapter_acp import AttestationVerifier
from .gate import decide


class LabDeclaredVerifier(AttestationVerifier):
    """Non-production verifier for the BYOM laboratory only.

    Testers explicitly label each envelope's ``mp_test_verdict`` as root,
    derived, or invalid. This lets them attack MP lineage and aggregation while
    making no false claim that unsigned input was authenticated.
    """

    def verify(self, env: dict) -> str:
        verdict = env.get("mp_test_verdict", "invalid")
        return verdict if verdict in {"root", "derived", "invalid"} else "invalid"


def _read_json(path: str):
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError as document_error:
        values = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {number}: {exc.msg}") from exc
        if not values:
            raise ValueError(f"input is neither JSON nor JSONL: {document_error.msg}")
        return values


def _policy(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("policy must be a JSON object")
    allowed = {
        "decision_subject", "proceed_side", "min_flip_budget",
        "abstain_margin", "unbound_root_weight", "freshness",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError("unknown policy fields: " + ", ".join(unknown))
    subject = raw.get("decision_subject")
    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("policy.decision_subject must be a non-empty string")
    return {
        "decision_subject": subject,
        "proceed_side": raw.get("proceed_side", 1),
        "min_flip_budget": raw.get("min_flip_budget", 1.0),
        "abstain_margin": raw.get("abstain_margin", 0.0),
        "unbound_root_weight": raw.get("unbound_root_weight", 0.0),
        "freshness": raw.get("freshness", None),
    }


def evaluate(envelopes: object, policy: dict) -> dict:
    if not isinstance(envelopes, list):
        raise ValueError("evidence must be a JSON array or JSONL objects")
    if any(not isinstance(item, dict) for item in envelopes):
        raise ValueError("every evidence item must be a JSON object")
    decision = decide(envelopes, LabDeclaredVerifier(), **_policy(policy))
    diagnostics = decision.diagnostics
    return {
        "schema": "minority-prophet.byom-result.v1",
        "mode": "simulation",
        "runtime_effects": 0,
        "outcome": decision.action,
        "decision": decision.decision,
        "flip_budget": decision.flip_budget,
        "confidence": decision.confidence,
        "roots_for": decision.roots_for,
        "roots_against": decision.roots_against,
        "conversions_to_reverse": decision.conversions_to_reverse,
        "evidence_items_received": len(envelopes),
        "quarantined": diagnostics.get("quarantined", 0),
        "unattested_singletons": diagnostics.get("unattested_singletons", 0),
        "exclusions": diagnostics.get("exclusions", {}),
        "reason": diagnostics.get("reason"),
        "warnings": [
            "LAB ONLY: mp_test_verdict is tester-declared, not authenticated",
            "Simulation never invokes a real runtime",
        ],
    }


def feedback(result: dict, evidence: object, policy: object) -> dict:
    canonical = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return {
        "schema": "minority-prophet.byom-feedback.v1",
        "result": result,
        "input_fingerprints": {
            "evidence_sha256": hashlib.sha256(canonical(evidence)).hexdigest(),
            "policy_sha256": hashlib.sha256(canonical(policy)).hexdigest(),
        },
        "privacy": "Raw evidence and policy are intentionally omitted",
        "tester_notes": "",
        "reproduction": "mp-gate evaluate --evidence YOUR_FILE --policy YOUR_POLICY",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="mp-gate",
        description="Bring your own messy evidence to the Minority Prophet lab.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = sub.add_parser("evaluate", help="evaluate JSON/JSONL safely")
    evaluate_parser.add_argument("--evidence", required=True, help="path or - for stdin")
    evaluate_parser.add_argument("--policy", required=True, help="policy JSON path")
    evaluate_parser.add_argument("--feedback", help="write privacy-safe feedback JSON")
    args = parser.parse_args(argv)
    try:
        evidence = _read_json(args.evidence)
        policy = _read_json(args.policy)
        result = evaluate(evidence, policy)
        rendered = json.dumps(result, indent=2, sort_keys=True)
        print(rendered)
        if args.feedback:
            Path(args.feedback).write_text(
                json.dumps(feedback(result, evidence, policy), indent=2,
                           sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({
            "schema": "minority-prophet.byom-error.v1",
            "error": type(exc).__name__, "message": str(exc),
            "runtime_effects": 0,
        }), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
