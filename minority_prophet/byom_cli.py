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


def feedback(result: dict, evidence: object, policy: object,
             command: str = "evaluate") -> dict:
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
        "reproduction": f"mp-gate {command} --evidence YOUR_FILE --policy YOUR_POLICY",
    }


ATTACK_INVARIANTS = (
    "Adding only derived copies must not create an independent root",
    "Invalid or malformed evidence must not create permission",
    "Evidence for another subject must not authorize this subject",
    "No verifiable evidence, ties, and thin margins must not proceed",
    "Simulation must always report zero runtime effects",
)


def attack(envelopes: object, policy: dict) -> dict:
    """Evaluate one adversarial case and state the contract being attacked."""
    result = evaluate(envelopes, policy)
    return dict(result, mode="attack", attack_contract={
        "goal": "Find a crash, unsafe proceed, copy-amplification, or inconsistency",
        "invariants": list(ATTACK_INVARIANTS),
        "success_criteria": (
            "Provide a minimal reproducible input when an invariant is violated"
        ),
    })


def _actual_outcome(value: object) -> str:
    aliases = {
        "allow": "proceed", "allowed": "proceed", "executed": "proceed",
        "deny": "block", "denied": "block", "prevented": "block",
        "review": "escalate", "human": "escalate",
    }
    normalized = str(value).strip().lower()
    normalized = aliases.get(normalized, normalized)
    if normalized not in {"proceed", "block", "escalate", "request_evidence"}:
        raise ValueError(f"unknown actual_outcome: {value!r}")
    return normalized


def shadow(events: object, policy: dict) -> dict:
    """Compare recorded workflow outcomes with MP without controlling anything."""
    if not isinstance(events, list) or any(not isinstance(item, dict) for item in events):
        raise ValueError("shadow events must be a JSON array or JSONL objects")
    comparisons = []
    counts = {"matches": 0, "disagreements": 0, "mp_more_cautious": 0,
              "actual_more_cautious": 0}
    caution = {"proceed": 0, "request_evidence": 1, "escalate": 2, "block": 3}
    for index, event in enumerate(events, 1):
        event_id = event.get("event_id")
        subject = event.get("decision_subject")
        evidence = event.get("evidence")
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError(f"shadow event {index} needs a non-empty event_id")
        if not isinstance(subject, str) or not subject.strip():
            raise ValueError(f"shadow event {event_id} needs decision_subject")
        actual = _actual_outcome(event.get("actual_outcome"))
        event_policy = dict(policy, decision_subject=subject)
        simulated = evaluate(evidence, event_policy)
        mp_outcome = simulated["outcome"]
        if actual == mp_outcome:
            relationship = "match"
            counts["matches"] += 1
        elif caution[mp_outcome] > caution[actual]:
            relationship = "mp_more_cautious"
            counts["mp_more_cautious"] += 1
            counts["disagreements"] += 1
        else:
            relationship = "actual_more_cautious"
            counts["actual_more_cautious"] += 1
            counts["disagreements"] += 1
        comparisons.append({
            "event_id": event_id,
            "actual_outcome": actual,
            "mp_outcome": mp_outcome,
            "relationship": relationship,
            "roots_for": simulated["roots_for"],
            "roots_against": simulated["roots_against"],
            "quarantined": simulated["quarantined"],
            "reason": simulated["reason"],
            "value_observation": (
                "MP would have asked for more caution"
                if relationship == "mp_more_cautious" else
                "Existing workflow was more cautious"
                if relationship == "actual_more_cautious" else
                "MP and the existing workflow agreed"
            ),
        })
    return {
        "schema": "minority-prophet.shadow-report.v1",
        "mode": "shadow",
        "runtime_effects": 0,
        "events_observed": len(events),
        "summary": counts,
        "comparisons": comparisons,
        "warnings": [
            "Shadow mode observes copies of events and has no runtime authority",
            "LAB ONLY: mp_test_verdict is tester-declared, not authenticated",
        ],
    }


def shadow_feedback(report: dict, events: object, policy: object) -> dict:
    safe_report = dict(report)
    safe_report["comparisons"] = [
        dict(item, event_id_sha256=hashlib.sha256(
            item["event_id"].encode("utf-8")
        ).hexdigest())
        for item in report["comparisons"]
    ]
    for item in safe_report["comparisons"]:
        del item["event_id"]
    safe = feedback(safe_report, events, policy)
    safe["schema"] = "minority-prophet.shadow-feedback.v1"
    safe["input_fingerprints"]["events_sha256"] = safe["input_fingerprints"].pop(
        "evidence_sha256"
    )
    safe["reproduction"] = "mp-gate shadow --events YOUR_EVENTS --policy YOUR_POLICY"
    return safe


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="mp-gate",
        description="Bring your own messy evidence to the Minority Prophet lab.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    def evidence_arguments(command_parser):
        command_parser.add_argument("--evidence", required=True,
                                    help="path or - for stdin")
        command_parser.add_argument("--policy", required=True, help="policy JSON path")
        command_parser.add_argument("--feedback",
                                    help="write privacy-safe feedback JSON")

    evaluate_parser = sub.add_parser("evaluate", help="evaluate JSON/JSONL safely")
    evidence_arguments(evaluate_parser)
    attack_parser = sub.add_parser("attack", help="run an agent-generated attack case")
    evidence_arguments(attack_parser)
    shadow_parser = sub.add_parser(
        "shadow", help="compare copied workflow events without controlling them"
    )
    shadow_parser.add_argument("--events", required=True, help="path or - for stdin")
    shadow_parser.add_argument("--policy", required=True, help="base policy JSON path")
    shadow_parser.add_argument("--report", help="write the full local shadow report")
    shadow_parser.add_argument("--feedback", help="write privacy-safe feedback JSON")
    args = parser.parse_args(argv)
    try:
        policy = _read_json(args.policy)
        if args.command == "shadow":
            evidence = _read_json(args.events)
            result = shadow(evidence, policy)
            if args.report:
                Path(args.report).write_text(
                    json.dumps(result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
        else:
            evidence = _read_json(args.evidence)
            result = attack(evidence, policy) if args.command == "attack" else evaluate(
                evidence, policy
            )
        rendered = json.dumps(result, indent=2, sort_keys=True)
        print(rendered)
        if args.feedback:
            Path(args.feedback).write_text(
                json.dumps(
                    shadow_feedback(result, evidence, policy)
                    if args.command == "shadow" else feedback(
                        result, evidence, policy, command=args.command
                    ),
                    indent=2,
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
