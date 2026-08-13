"""Minority Prophet Gate: refuse manufactured consensus in multi-agent systems.

Counts independent, attested evidence roots instead of voices. Core
properties are proven under the stated model -- copy invariance, immunity to
side-preserving AND root-preserving lineage corruption, and the margin flip
condition. FORMAL.md gives the pointers; the normative hypotheses are the theorem
ledger in the research repository, not this docstring.
"""
from .aggregator import Claim, EvidenceGraph, Verdict, aggregate
from .reconcile import StateVerdict, reconcile
from .adapter_acp import AttestationVerifier, TrustAllVerifier, envelopes_to_claims
from .gate import EvidenceAssessment, GateDecision, assess, decide
from .runtime_adapter import (
    RuntimeAction,
    RuntimeAdapter,
    RuntimeBoundaryError,
    RuntimeController,
    RuntimeReceipt,
)
from .runtime_integrations import IdempotentHttpRuntime, InProcessToolRuntime
from .evidence_request import (
    EvidenceRequest,
    EvidenceRequestError,
    EvidenceRequestExhausted,
    EvidenceRequestPolicy,
    EvidenceRequirement,
    issue_evidence_request,
    validate_evidence_return,
    verify_evidence_request,
)
from .selective_hybrid import DeterministicDecision, SelectiveDecision, selective_decide
from .memory_evidence import MemoryEvidenceAssessment, assess_memory_evidence

__version__ = "0.1.0"
__all__ = ["Claim", "EvidenceGraph", "Verdict", "aggregate",
           "StateVerdict", "reconcile",
           "AttestationVerifier", "TrustAllVerifier", "envelopes_to_claims",
           "EvidenceAssessment", "GateDecision", "assess", "decide",
           "RuntimeAction", "RuntimeAdapter", "RuntimeBoundaryError",
           "RuntimeController", "RuntimeReceipt",
           "IdempotentHttpRuntime", "InProcessToolRuntime",
           "EvidenceRequest", "EvidenceRequestError", "EvidenceRequestExhausted",
           "EvidenceRequestPolicy", "EvidenceRequirement",
           "issue_evidence_request", "validate_evidence_return",
           "verify_evidence_request",
           "DeterministicDecision", "SelectiveDecision", "selective_decide",
           "MemoryEvidenceAssessment", "assess_memory_evidence"]
