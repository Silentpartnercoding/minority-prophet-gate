import unittest

from minority_prophet import (
    CallbackEvidenceCollector,
    CallbackVerifier,
    CandidateEvidenceBridge,
    CollectionAuthorization,
    CollectorDescriptor,
    CollectorRoute,
    CollectedEvidence,
    DeterministicDecision,
    EvidenceAuditLog,
    EvidenceCollectionResult,
    EvidenceControlPlane,
    EvidenceControlPolicy,
    EvidenceRequestPolicy,
    EvidenceRequirement,
    EvidenceRouter,
    RuntimeAction,
    RuntimeBoundaryError,
    RuntimeReceipt,
    TrustAllVerifier,
    VerifiedEvidenceBatch,
)


SUBJECT = "deployment:demo"
ROUTE = CollectorRoute(
    "local-tests", "program", "tests.run", "candidate_evidence",
    ("repository.read", "tests.run"), requires_independence=True,
)
REQUESTS = EvidenceRequestPolicy((EvidenceRequirement(
    "fresh-tests", "fresh test receipts for the frozen action", ROUTE,
    ("test.receipt",),
),), max_rounds=2, max_evidence_items_per_round=4)


class Authorizer:
    def authorize(self, dispatch, collector):
        return CollectionAuthorization(
            "permit:" + dispatch.dispatch_id, dispatch.dispatch_id,
            dispatch.challenge_id, collector.collector_id,
            dispatch.route.allowed_actions,
        )


def verifier():
    return CallbackVerifier(lambda envelope: (
        "root" if (envelope.get("attest") or {}).get("signed_by") == "trusted-ci"
        else "invalid"
    ))


class Runtime:
    def __init__(self):
        self.effects = 0

    def prepare(self, action):
        return action

    def execute_once(self, action):
        self.effects += 1
        return RuntimeReceipt(action.action_id, action.idempotency_key, "succeeded", 1)

    def prevent(self, action, reason):
        return RuntimeReceipt(action.action_id, action.idempotency_key, "prevented", 0,
                              diagnostics={"reason": reason})


def action():
    return RuntimeAction("deploy-1", "deploy", "staging", "sha256:payload", "once-1")


def policy(primary=None):
    return EvidenceControlPolicy(
        primary or DeterministicDecision(
            "review", "deployment needs evidence", policy_id="deploy-v1"
        ),
        REQUESTS, SUBJECT, "agent:requester",
    )


def router(assertion="SAFE", *, invalid_binding=False, invalid_signature=False):
    descriptor = CollectorDescriptor(
        "runner:independent", "program", ("tests.run",), "ci:independent"
    )

    def collect(dispatch):
        subject = "deployment:other" if invalid_binding else dispatch.decision_subject
        envelope = {
            "claim_id": "fresh-test-1", "agent": "runner", "assertion": assertion,
            "attest": {
                "origin": "test-run", "subject": subject,
                "evidence_kind": "test.receipt",
                "signed_by": "unknown" if invalid_signature else "trusted-ci",
            },
        }
        item = CollectedEvidence("fresh-tests", "test.receipt", envelope)
        return EvidenceCollectionResult(
            dispatch.dispatch_id, dispatch.challenge_id, descriptor.collector_id,
            "completed", (item,),
        )

    audit = EvidenceAuditLog(clock=lambda: "2026-08-13T00:00:00Z")
    return EvidenceRouter(
        {ROUTE.route_id: CallbackEvidenceCollector(descriptor, collect)},
        Authorizer(), audit,
    )


class ControlPlaneTests(unittest.TestCase):
    def test_missing_evidence_is_collected_then_effect_runs_once(self):
        evidence_router = router()
        runtime = Runtime()
        plane = EvidenceControlPlane(evidence_router, CandidateEvidenceBridge(verifier()))

        outcome = plane.run(
            action(), policy(), VerifiedEvidenceBatch((), TrustAllVerifier()), runtime
        )

        self.assertEqual(outcome.decision.action, "proceed")
        self.assertEqual(outcome.collection_rounds, 1)
        self.assertEqual(runtime.effects, 1)
        self.assertEqual(outcome.receipt.status, "succeeded")
        self.assertIn("evidence_verified", outcome.transitions)
        self.assertEqual(evidence_router.audit_log.events[-1].event_type,
                         "gate_reassessed")

    def test_contradicting_evidence_blocks_and_never_executes(self):
        runtime = Runtime()
        outcome = EvidenceControlPlane(router("UNSAFE"), CandidateEvidenceBridge(verifier())).run(
            action(), policy(), VerifiedEvidenceBatch((), TrustAllVerifier()), runtime
        )
        self.assertEqual(outcome.decision.action, "block")
        self.assertEqual(runtime.effects, 0)
        self.assertEqual(outcome.receipt.status, "prevented")

    def test_wrong_subject_never_becomes_permission_and_exhausts_to_human(self):
        runtime = Runtime()
        outcome = EvidenceControlPlane(
            router(invalid_binding=True), CandidateEvidenceBridge(verifier())
        ).run(
            action(), policy(), VerifiedEvidenceBatch((), TrustAllVerifier()), runtime
        )
        self.assertEqual(outcome.decision.action, "escalate")
        self.assertEqual(outcome.collection_rounds, 2)
        self.assertEqual(runtime.effects, 0)

    def test_unverified_evidence_never_becomes_permission(self):
        runtime = Runtime()
        outcome = EvidenceControlPlane(
            router(invalid_signature=True), CandidateEvidenceBridge(verifier())
        ).run(action(), policy(), VerifiedEvidenceBatch((), verifier()), runtime)
        self.assertEqual(outcome.decision.action, "escalate")
        self.assertEqual(runtime.effects, 0)

    def test_new_evidence_cannot_erase_prior_opposing_evidence(self):
        runtime = Runtime()
        prior = {
            "claim_id": "prior-unsafe", "agent": "prior-ci",
            "assertion": "UNSAFE",
            "attest": {"origin": "prior-test", "subject": SUBJECT,
                       "signed_by": "trusted-ci"},
        }
        outcome = EvidenceControlPlane(
            router("SAFE"), CandidateEvidenceBridge(verifier())
        ).run(action(), policy(), VerifiedEvidenceBatch((prior,), verifier()), runtime)
        self.assertNotEqual(outcome.decision.action, "proceed")
        self.assertEqual(runtime.effects, 0)

    def test_deterministic_deny_does_not_dispatch_collection(self):
        evidence_router = router()
        runtime = Runtime()
        denied = DeterministicDecision(
            "deny", "outside scope", evidence_sensitive=True, policy_id="deploy-v1"
        )
        outcome = EvidenceControlPlane(
            evidence_router, CandidateEvidenceBridge(verifier())
        ).run(
            action(), policy(denied), VerifiedEvidenceBatch((), TrustAllVerifier()), runtime
        )
        self.assertEqual(outcome.decision.action, "block")
        self.assertEqual(outcome.collection_rounds, 0)
        self.assertEqual(evidence_router.audit_log.events, ())
        self.assertEqual(runtime.effects, 0)

    def test_downstream_receives_only_final_decision(self):
        runtime = Runtime()
        outcome = EvidenceControlPlane(router(), CandidateEvidenceBridge(verifier())).run(
            action(), policy(), VerifiedEvidenceBatch((), TrustAllVerifier()), runtime
        )
        self.assertNotEqual(outcome.decision.action, "request_evidence")
        self.assertEqual(runtime.effects, 1)

    def test_replaying_same_action_does_not_repeat_effect(self):
        runtime = Runtime()
        plane = EvidenceControlPlane(router(), CandidateEvidenceBridge(verifier()))
        first = plane.run(
            action(), policy(), VerifiedEvidenceBatch((), verifier()), runtime
        )
        second = plane.run(
            action(), policy(), VerifiedEvidenceBatch((), verifier()), runtime
        )
        self.assertEqual(first.receipt, second.receipt)
        self.assertEqual(runtime.effects, 1)

    def test_replay_cannot_substitute_policy(self):
        runtime = Runtime()
        plane = EvidenceControlPlane(router(), CandidateEvidenceBridge(verifier()))
        plane.run(action(), policy(), VerifiedEvidenceBatch((), verifier()), runtime)
        changed = DeterministicDecision(
            "deny", "different policy", evidence_sensitive=True, policy_id="deploy-v2"
        )
        with self.assertRaisesRegex(RuntimeBoundaryError, "action or policy"):
            plane.run(
                action(), policy(changed), VerifiedEvidenceBatch((), verifier()), runtime
            )
        self.assertEqual(runtime.effects, 1)


if __name__ == "__main__":
    unittest.main()
