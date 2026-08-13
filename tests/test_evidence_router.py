"""Vendor-neutral evidence routing, authorization, and durable audit tests."""

import json
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from minority_prophet import (
    CallbackEvidenceCollector,
    CollectedEvidence,
    CollectionAuthorization,
    CollectorDescriptor,
    CollectorRoute,
    DeterministicDecision,
    EvidenceAuditLog,
    EvidenceCollectionResult,
    EvidenceRequestPolicy,
    EvidenceRequirement,
    EvidenceRouter,
    EvidenceRoutingError,
    TrustAllVerifier,
    issue_evidence_request,
    selective_decide,
)
from minority_prophet.adapter_acp import CallbackVerifier

ACTION = "sha256:exact-action"
SUBJECT = "job:123"
POLICY_ID = "evidence-routing-v1"
REQUESTER_DOMAIN = "control:requesting-agent"


ROUTES = {
    "agent": CollectorRoute(
        "agent-artifacts", "requesting_agent", "artifact.collection",
        "candidate_evidence",
        ("repository.read", "test.run"),
    ),
    "mp": CollectorRoute(
        "epistemic-analysis", "epistemic_service", "provenance.analysis",
        "verification_artifact",
        ("evidence.read", "provenance.analyze"), requires_independence=True,
    ),
    "human": CollectorRoute(
        "human-review", "human", "judgment.review", "human_handoff",
        ("review.submit",),
    ),
    "program": CollectorRoute(
        "external-program", "program", "artifact.verify", "candidate_evidence",
        ("artifact.read",),
        requires_independence=True,
    ),
}


def requirement(name, route, kind):
    return EvidenceRequirement(
        name, f"Collect {name} evidence for this action", route, (kind,)
    )


REQUIREMENTS = (
    requirement("test-receipt", ROUTES["agent"], "test.receipt"),
    requirement("lineage-map", ROUTES["mp"], "provenance.receipt"),
    requirement("owner-judgment", ROUTES["human"], "human.decision"),
    requirement("artifact-proof", ROUTES["program"], "artifact.proof"),
)


def request(requirements=REQUIREMENTS, *, max_items=20):
    return issue_evidence_request(
        EvidenceRequestPolicy(
            tuple(requirements), max_rounds=2,
            max_evidence_items_per_round=max_items,
        ),
        action_digest=ACTION,
        decision_subject=SUBJECT,
        policy_id=POLICY_ID,
        reason_code="missing_verifiable_evidence",
    )


class BoundAuthorizer:
    def __init__(self, allow=True):
        self.allow = allow
        self.calls = []

    def authorize(self, dispatch, collector):
        self.calls.append((dispatch.dispatch_id, collector.collector_id))
        if not self.allow:
            return None
        return CollectionAuthorization(
            authorization_id=f"auth:{dispatch.dispatch_id}",
            dispatch_id=dispatch.dispatch_id,
            challenge_id=dispatch.challenge_id,
            collector_id=collector.collector_id,
            allowed_actions=dispatch.route.allowed_actions,
        )


def descriptor(route, collector_id, domain):
    return CollectorDescriptor(
        collector_id, route.collector_kind, (route.capability,), domain
    )


def completed_collector(route, collector_id, domain, *, marker="do-not-log"):
    desc = descriptor(route, collector_id, domain)

    def collect(dispatch):
        if route.output_role == "human_handoff":
            return EvidenceCollectionResult(
                dispatch.dispatch_id, dispatch.challenge_id,
                collector_id, "needs_human",
            )
        items = tuple(
            CollectedEvidence(
                req.requirement_id,
                req.accepted_kinds[0],
                ({
                    "claim_id": f"claim:{req.requirement_id}",
                    "assertion": "SAFE",
                    "evidence_kind": req.accepted_kinds[0],
                    "private_marker": marker,
                    "attest": {
                        "origin": collector_id,
                        "subject": dispatch.decision_subject,
                        "evidence_kind": req.accepted_kinds[0],
                    },
                } if route.output_role == "candidate_evidence" else {
                    "schema": "epistemic-verification-artifact.v1",
                    "status": "ACCEPTED",
                    "input_digest": dispatch.action_digest,
                    "private_marker": marker,
                    "attest": {
                        "origin": collector_id,
                        "subject": dispatch.decision_subject,
                        "evidence_kind": req.accepted_kinds[0],
                    },
                }),
            )
            for req in dispatch.requirements
        )
        return EvidenceCollectionResult(
            dispatch.dispatch_id, dispatch.challenge_id,
            collector_id, "completed", items,
        )

    return CallbackEvidenceCollector(desc, collect)


def collector_map():
    return {
        ROUTES["agent"].route_id: completed_collector(
            ROUTES["agent"], "agent:original", REQUESTER_DOMAIN
        ),
        ROUTES["mp"].route_id: completed_collector(
            ROUTES["mp"], "service:epistemic", "control:epistemic-service"
        ),
        ROUTES["human"].route_id: completed_collector(
            ROUTES["human"], "queue:human", "control:human-review"
        ),
        ROUTES["program"].route_id: completed_collector(
            ROUTES["program"], "program:verifier", "control:external-verifier"
        ),
    }


class EvidenceRouterTests(unittest.TestCase):
    def test_gate_to_agent_and_epistemic_service_and_back_to_gate(self):
        selected_requirements = (REQUIREMENTS[0], REQUIREMENTS[1])
        policy = EvidenceRequestPolicy(
            selected_requirements, max_rounds=2,
            max_evidence_items_per_round=4,
        )
        primary = DeterministicDecision(
            "review", "fresh evidence required", policy_id=POLICY_ID
        )
        first = selective_decide(
            primary, [], TrustAllVerifier(), decision_subject=SUBJECT,
            action_digest=ACTION, evidence_request_policy=policy,
        )
        self.assertEqual(first.action, "request_evidence")

        audit = EvidenceAuditLog()
        configured = collector_map()
        router = EvidenceRouter(
            {
                ROUTES["agent"].route_id: configured[ROUTES["agent"].route_id],
                ROUTES["mp"].route_id: configured[ROUTES["mp"].route_id],
            },
            BoundAuthorizer(), audit,
        )
        results = router.collect(
            first.evidence_request, requester_control_domain=REQUESTER_DOMAIN
        )
        agent_result = next(
            result for result in results if result.collector_id == "agent:original"
        )
        epistemic_result = next(
            result for result in results if result.collector_id == "service:epistemic"
        )
        provenance_receipt = epistemic_result.envelopes[0]
        self.assertNotIn("assertion", provenance_receipt)
        self.assertEqual(provenance_receipt["status"], "ACCEPTED")

        # The epistemic service is verifier input, not a second SAFE vote. It
        # qualifies the agent's returned receipt as a root; only that claim is
        # submitted to Gate aggregation.
        verifier = CallbackVerifier(lambda envelope: (
            "root" if provenance_receipt["input_digest"] == ACTION else "invalid"
        ))
        final = selective_decide(
            primary, agent_result.envelopes, verifier, decision_subject=SUBJECT,
            action_digest=ACTION, evidence_request_policy=policy,
            prior_evidence_request=first.evidence_request,
        )
        router.record_gate_decision(first.evidence_request, final)

        self.assertEqual((final.action, final.route), ("proceed", "evidence"))
        self.assertEqual(
            {result.collector_id for result in results},
            {"agent:original", "service:epistemic"},
        )
        self.assertEqual(audit.events[-1].event_type, "gate_reassessed")
        self.assertEqual(audit.events[-1].details["action"], "proceed")

    def test_policy_routes_to_agent_epistemic_service_human_and_program(self):
        audit = EvidenceAuditLog(clock=lambda: "2026-08-13T00:00:00Z")
        router = EvidenceRouter(collector_map(), BoundAuthorizer(), audit)

        challenge = request()
        dispatches = router.plan(
            challenge, requester_control_domain=REQUESTER_DOMAIN
        )
        results = tuple(router.dispatch(dispatch) for dispatch in dispatches)

        self.assertEqual(len(results), 4)
        self.assertEqual(
            sum(dispatch.max_evidence_items for dispatch in dispatches),
            challenge.max_evidence_items,
        )
        self.assertEqual(
            sorted(result.status for result in results),
            ["completed", "completed", "completed", "needs_human"],
        )
        self.assertEqual(
            {event.route_id for event in audit.events if event.event_type == "route_planned"},
            {route.route_id for route in ROUTES.values()},
        )
        self.assertEqual(
            [event.sequence for event in audit.events], list(range(len(audit.events)))
        )
        self.assertFalse(any(
            event.details.get("grants_protected_action_authority") is True
            for event in audit.events
        ))

        # Raw evidence and its private marker are never copied into the log.
        rendered = json.dumps([event.to_dict() for event in audit.events])
        self.assertNotIn("do-not-log", rendered)
        self.assertNotIn('"assertion": "SAFE"', rendered)

    def test_router_is_vendor_neutral_and_selects_by_route_capability(self):
        route = CollectorRoute(
            "any-compatible-service", "epistemic_service", "provenance.analysis",
            "verification_artifact",
            ("evidence.read",),
        )
        req = requirement("lineage", route, "provenance.receipt")
        compatible = completed_collector(
            route, "service:not-hardcoded", "control:compatible-service"
        )
        router = EvidenceRouter(
            {route.route_id: compatible}, BoundAuthorizer(), EvidenceAuditLog()
        )
        result = router.collect(
            request((req,)), requester_control_domain=REQUESTER_DOMAIN
        )[0]
        self.assertEqual(result.collector_id, "service:not-hardcoded")

    def test_requesting_agent_route_requires_the_original_control_domain(self):
        req = request((REQUIREMENTS[0],))
        wrong = completed_collector(
            ROUTES["agent"], "agent:substituted", "control:someone-else"
        )
        router = EvidenceRouter(
            {ROUTES["agent"].route_id: wrong}, BoundAuthorizer(), EvidenceAuditLog()
        )
        dispatch = router.plan(req, requester_control_domain=REQUESTER_DOMAIN)[0]
        with self.assertRaisesRegex(EvidenceRoutingError, "substituted"):
            router.dispatch(dispatch)

    def test_independence_required_route_rejects_requester_control_domain(self):
        req = request((REQUIREMENTS[1],))
        conflicted = completed_collector(
            ROUTES["mp"], "service:conflicted", REQUESTER_DOMAIN
        )
        router = EvidenceRouter(
            {ROUTES["mp"].route_id: conflicted},
            BoundAuthorizer(), EvidenceAuditLog(),
        )
        dispatch = router.plan(req, requester_control_domain=REQUESTER_DOMAIN)[0]
        with self.assertRaisesRegex(EvidenceRoutingError, "not independent"):
            router.dispatch(dispatch)

    def test_collector_kind_and_capability_are_enforced(self):
        req = request((REQUIREMENTS[1],))
        for changed, message in (
            (CollectorDescriptor("wrong", "program", ("provenance.analysis",),
                                 "control:other"), "kind"),
            (CollectorDescriptor("wrong", "epistemic_service", ("other.capability",),
                                 "control:other"), "capability"),
        ):
            adapter = CallbackEvidenceCollector(changed, lambda dispatch: None)
            router = EvidenceRouter(
                {ROUTES["mp"].route_id: adapter},
                BoundAuthorizer(), EvidenceAuditLog(),
            )
            dispatch = router.plan(req, requester_control_domain=REQUESTER_DOMAIN)[0]
            with self.subTest(message=message), self.assertRaisesRegex(
                    EvidenceRoutingError, message):
                router.dispatch(dispatch)

    def test_separate_collection_authority_is_required_and_bound(self):
        req = request((REQUIREMENTS[0],))
        called = []
        adapter = completed_collector(
            ROUTES["agent"], "agent:original", REQUESTER_DOMAIN
        )
        original = adapter.callback
        adapter.callback = lambda dispatch: called.append(dispatch.dispatch_id) or original(dispatch)
        audit = EvidenceAuditLog()
        router = EvidenceRouter(
            {ROUTES["agent"].route_id: adapter}, BoundAuthorizer(False), audit
        )
        dispatch = router.plan(req, requester_control_domain=REQUESTER_DOMAIN)[0]
        with self.assertRaisesRegex(EvidenceRoutingError, "not authorized"):
            router.dispatch(dispatch)
        self.assertEqual(called, [])
        self.assertTrue(audit.has("dispatch_denied", dispatch.dispatch_id))

    def test_dispatch_is_bound_and_cannot_be_modified(self):
        router = EvidenceRouter(collector_map(), BoundAuthorizer(), EvidenceAuditLog())
        dispatch = router.plan(
            request((REQUIREMENTS[0],)), requester_control_domain=REQUESTER_DOMAIN
        )[0]
        modified = replace(dispatch, action_digest="sha256:other")
        with self.assertRaisesRegex(EvidenceRoutingError, "integrity"):
            router.dispatch(modified)

    def test_authorization_cannot_expand_or_substitute_collection_actions(self):
        class OverbroadAuthorizer:
            def authorize(self, dispatch, collector):
                return CollectionAuthorization(
                    "auth:overbroad", dispatch.dispatch_id, dispatch.challenge_id,
                    collector.collector_id,
                    dispatch.route.allowed_actions + ("protected.execute",),
                )

        route = ROUTES["agent"]
        router = EvidenceRouter(
            {route.route_id: completed_collector(
                route, "agent:original", REQUESTER_DOMAIN
            )},
            OverbroadAuthorizer(), EvidenceAuditLog(),
        )
        dispatch = router.plan(
            request((REQUIREMENTS[0],)), requester_control_domain=REQUESTER_DOMAIN
        )[0]
        with self.assertRaisesRegex(EvidenceRoutingError, "allowed_actions"):
            router.dispatch(dispatch)

    def test_failed_or_crashed_dispatch_is_not_silently_reexecuted(self):
        calls = []
        route = ROUTES["agent"]
        desc = descriptor(route, "agent:original", REQUESTER_DOMAIN)

        def crash(dispatch):
            calls.append(dispatch.dispatch_id)
            raise ConnectionError("response lost")

        audit = EvidenceAuditLog()
        router = EvidenceRouter(
            {route.route_id: CallbackEvidenceCollector(desc, crash)},
            BoundAuthorizer(), audit,
        )
        dispatch = router.plan(
            request((REQUIREMENTS[0],)), requester_control_domain=REQUESTER_DOMAIN
        )[0]
        with self.assertRaises(EvidenceRoutingError):
            router.dispatch(dispatch)
        with self.assertRaisesRegex(EvidenceRoutingError, "terminal"):
            router.dispatch(dispatch)
        self.assertEqual(len(calls), 1)
        self.assertTrue(audit.has("dispatch_started", dispatch.dispatch_id))
        self.assertTrue(audit.has("collection_failed", dispatch.dispatch_id))

    def test_completed_result_must_cover_requirements_with_allowed_kinds(self):
        route = ROUTES["agent"]
        req = request((REQUIREMENTS[0],))
        desc = descriptor(route, "agent:original", REQUESTER_DOMAIN)

        def invalid(dispatch):
            item = CollectedEvidence(
                "test-receipt", "self.assertion",
                {"claim_id": "bad", "assertion": "SAFE"},
            )
            return EvidenceCollectionResult(
                dispatch.dispatch_id, dispatch.challenge_id,
                desc.collector_id, "completed", (item,),
            )

        router = EvidenceRouter(
            {route.route_id: CallbackEvidenceCollector(desc, invalid)},
            BoundAuthorizer(), EvidenceAuditLog(),
        )
        dispatch = router.plan(req, requester_control_domain=REQUESTER_DOMAIN)[0]
        with self.assertRaisesRegex(EvidenceRoutingError, "disallowed evidence kind"):
            router.dispatch(dispatch)

    def test_evidence_kind_must_be_inside_the_attested_envelope(self):
        route = ROUTES["agent"]
        desc = descriptor(route, "agent:original", REQUESTER_DOMAIN)

        def relabeled(dispatch):
            item = CollectedEvidence(
                "test-receipt", "test.receipt",
                {
                    "claim_id": "claim:relabeled", "assertion": "SAFE",
                    "attest": {
                        "origin": "agent:original", "subject": SUBJECT,
                        "evidence_kind": "self.assertion",
                    },
                },
            )
            return EvidenceCollectionResult(
                dispatch.dispatch_id, dispatch.challenge_id,
                desc.collector_id, "completed", (item,),
            )

        router = EvidenceRouter(
            {route.route_id: CallbackEvidenceCollector(desc, relabeled)},
            BoundAuthorizer(), EvidenceAuditLog(),
        )
        dispatch = router.plan(
            request((REQUIREMENTS[0],)), requester_control_domain=REQUESTER_DOMAIN
        )[0]
        with self.assertRaisesRegex(EvidenceRoutingError, "attested envelope"):
            router.dispatch(dispatch)

    def test_evidence_mutation_after_collection_is_detected_before_handback(self):
        route = ROUTES["agent"]
        router = EvidenceRouter(
            {route.route_id: completed_collector(
                route, "agent:original", REQUESTER_DOMAIN
            )},
            BoundAuthorizer(), EvidenceAuditLog(),
        )
        result = router.collect(
            request((REQUIREMENTS[0],)), requester_control_domain=REQUESTER_DOMAIN
        )[0]
        result.items[0].envelope["assertion"] = "UNSAFE"
        with self.assertRaisesRegex(EvidenceRoutingError, "mutated"):
            _ = result.envelopes

    def test_collection_item_cap_is_enforced_by_router(self):
        route = ROUTES["agent"]
        req = request((REQUIREMENTS[0],), max_items=1)
        desc = descriptor(route, "agent:original", REQUESTER_DOMAIN)

        def oversized(dispatch):
            items = tuple(
                CollectedEvidence(
                    "test-receipt", "test.receipt",
                    {"claim_id": f"claim:{index}", "assertion": "SAFE"},
                ) for index in range(2)
            )
            return EvidenceCollectionResult(
                dispatch.dispatch_id, dispatch.challenge_id,
                desc.collector_id, "completed", items,
            )

        router = EvidenceRouter(
            {route.route_id: CallbackEvidenceCollector(desc, oversized)},
            BoundAuthorizer(), EvidenceAuditLog(),
        )
        dispatch = router.plan(req, requester_control_domain=REQUESTER_DOMAIN)[0]
        with self.assertRaisesRegex(EvidenceRoutingError, "item cap"):
            router.dispatch(dispatch)

    def test_human_adapter_can_return_needs_human_without_fabricating_evidence(self):
        route = ROUTES["human"]
        desc = descriptor(route, "queue:human", "control:human-review")

        def queue(dispatch):
            return EvidenceCollectionResult(
                dispatch.dispatch_id, dispatch.challenge_id,
                desc.collector_id, "needs_human",
            )

        router = EvidenceRouter(
            {route.route_id: CallbackEvidenceCollector(desc, queue)},
            BoundAuthorizer(), EvidenceAuditLog(),
        )
        result = router.collect(
            request((REQUIREMENTS[2],)),
            requester_control_domain=REQUESTER_DOMAIN,
        )[0]
        self.assertEqual(result.status, "needs_human")
        self.assertEqual(result.items, ())

    def test_final_gate_handback_is_recorded_once_without_evidence_body(self):
        audit = EvidenceAuditLog()
        router = EvidenceRouter(collector_map(), BoundAuthorizer(), audit)
        challenge = request((REQUIREMENTS[0],))
        router.collect(challenge, requester_control_domain=REQUESTER_DOMAIN)
        router.record_gate_decision(
            challenge, SimpleNamespace(
                action="proceed", route="evidence",
                diagnostics={"returned_for_challenge_id": challenge.challenge_id},
            )
        )
        event = audit.events[-1]
        self.assertEqual(event.event_type, "gate_reassessed")
        self.assertEqual(event.details["action"], "proceed")
        with self.assertRaisesRegex(EvidenceRoutingError, "already recorded"):
            router.record_gate_decision(
                challenge, SimpleNamespace(
                    action="block", route="evidence",
                    diagnostics={"returned_for_challenge_id": challenge.challenge_id},
                )
            )

    def test_unbound_gate_outcome_cannot_be_written_to_a_challenge_log(self):
        router = EvidenceRouter(collector_map(), BoundAuthorizer(), EvidenceAuditLog())
        challenge = request((REQUIREMENTS[0],))
        with self.assertRaisesRegex(EvidenceRoutingError, "not bound"):
            router.record_gate_decision(
                challenge,
                SimpleNamespace(action="proceed", route="evidence", diagnostics={}),
            )


class EvidenceAuditLogTests(unittest.TestCase):
    def test_jsonl_log_survives_restart_and_verifies_hash_chain(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence-audit.jsonl"
            log = EvidenceAuditLog(path, clock=lambda: "2026-08-13T00:00:00Z")
            first = log.append("challenge_issued", "challenge:1", details={"round": 1})
            second = log.append("route_planned", "challenge:1",
                                dispatch_id="dispatch:1", route_id="program")

            loaded = EvidenceAuditLog(path)
            self.assertEqual(loaded.events, (first, second))
            self.assertEqual(second.previous_event_hash, first.event_hash)

    def test_tampered_jsonl_log_fails_closed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence-audit.jsonl"
            log = EvidenceAuditLog(path, clock=lambda: "2026-08-13T00:00:00Z")
            log.append("challenge_issued", "challenge:1", details={"round": 1})
            raw = json.loads(path.read_text())
            raw["details"]["round"] = 999
            path.write_text(json.dumps(raw) + "\n")
            with self.assertRaisesRegex(EvidenceRoutingError, "hash"):
                EvidenceAuditLog(path)

    def test_appended_details_are_deep_copied_before_hashing(self):
        details = {"nested": {"value": 1}}
        log = EvidenceAuditLog(clock=lambda: "2026-08-13T00:00:00Z")
        event = log.append("challenge_received", "challenge:1", details=details)
        details["nested"]["value"] = 999
        self.assertEqual(event.details["nested"]["value"], 1)
        event.details["nested"]["value"] = 500
        self.assertEqual(log.events[0].details["nested"]["value"], 1)


if __name__ == "__main__":
    unittest.main()
