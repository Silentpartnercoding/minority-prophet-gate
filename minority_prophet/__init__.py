"""Minority Prophet Gate: refuse manufactured consensus in multi-agent systems.

Counts independent, attested evidence roots instead of voices. Core
properties are proven under the stated model -- copy invariance, immunity to
side-preserving AND root-preserving lineage corruption, and the margin flip
condition. FORMAL.md gives the pointers; the normative hypotheses are the theorem
ledger in the research repository, not this docstring.
"""
from .adapter_acp import AttestationVerifier, TrustAllVerifier, envelopes_to_claims
from .aggregator import Claim, EvidenceGraph, Verdict, aggregate
from .evidence_audit import (
    EvidenceAuditEvent,
    EvidenceAuditLog,
    EvidenceRoutingError,
)
from .evidence_request import (
    CollectorRoute,
    EvidenceRequest,
    EvidenceRequestError,
    EvidenceRequestExhausted,
    EvidenceRequestPolicy,
    EvidenceRequirement,
    issue_evidence_request,
    validate_evidence_return,
    verify_evidence_request,
)
from .evidence_router import (
    CallbackEvidenceCollector,
    CollectedEvidence,
    CollectionAuthorization,
    CollectionAuthorizer,
    CollectorDescriptor,
    EvidenceCollectionResult,
    EvidenceCollector,
    EvidenceDispatch,
    EvidenceRouter,
)
from .gate import EvidenceAssessment, GateDecision, assess, decide
from .memory_evidence import MemoryEvidenceAssessment, assess_memory_evidence
from .reconcile import StateVerdict, reconcile
from .runtime_adapter import (
    RuntimeAction,
    RuntimeAdapter,
    RuntimeBoundaryError,
    RuntimeController,
    RuntimeReceipt,
)
from .runtime_integrations import IdempotentHttpRuntime, InProcessToolRuntime
from .selective_hybrid import DeterministicDecision, SelectiveDecision, selective_decide

__version__ = "0.1.0"
__all__ = [
    "AttestationVerifier",
    "CallbackEvidenceCollector",
    "Claim",
    "CollectedEvidence",
    "CollectionAuthorization",
    "CollectionAuthorizer",
    "CollectorDescriptor",
    "CollectorRoute",
    "DeterministicDecision",
    "EvidenceAssessment",
    "EvidenceAuditEvent",
    "EvidenceAuditLog",
    "EvidenceCollectionResult",
    "EvidenceCollector",
    "EvidenceDispatch",
    "EvidenceGraph",
    "EvidenceRequest",
    "EvidenceRequestError",
    "EvidenceRequestExhausted",
    "EvidenceRequestPolicy",
    "EvidenceRequirement",
    "EvidenceRouter",
    "EvidenceRoutingError",
    "GateDecision",
    "IdempotentHttpRuntime",
    "InProcessToolRuntime",
    "MemoryEvidenceAssessment",
    "RuntimeAction",
    "RuntimeAdapter",
    "RuntimeBoundaryError",
    "RuntimeController",
    "RuntimeReceipt",
    "SelectiveDecision",
    "StateVerdict",
    "TrustAllVerifier",
    "Verdict",
    "aggregate",
    "assess",
    "assess_memory_evidence",
    "decide",
    "envelopes_to_claims",
    "issue_evidence_request",
    "reconcile",
    "selective_decide",
    "validate_evidence_return",
    "verify_evidence_request",
]
