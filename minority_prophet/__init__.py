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
from .selective_hybrid import DeterministicDecision, SelectiveDecision, selective_decide
from .memory_evidence import MemoryEvidenceAssessment, assess_memory_evidence
from .mandate_gate import (
    AuthorityReceiptCache,
    AuthorityRuntimeContext,
    BorderMandateVerifier,
    InMemoryAuthorityReceiptCache,
    InMemoryKnowledgeLedger,
    InMemoryMandateNonceStore,
    KnowledgeLedgerSink,
    MandateBundle,
    MandateGate,
    MandateGateError,
    MandateNonceStore,
)

__version__ = "0.1.0"
__all__ = ["Claim", "EvidenceGraph", "Verdict", "aggregate",
           "StateVerdict", "reconcile",
           "AttestationVerifier", "TrustAllVerifier", "envelopes_to_claims",
           "EvidenceAssessment", "GateDecision", "assess", "decide",
           "RuntimeAction", "RuntimeAdapter", "RuntimeBoundaryError",
           "RuntimeController", "RuntimeReceipt",
           "IdempotentHttpRuntime", "InProcessToolRuntime",
           "DeterministicDecision", "SelectiveDecision", "selective_decide",
           "MemoryEvidenceAssessment", "assess_memory_evidence",
           "AuthorityReceiptCache", "AuthorityRuntimeContext",
           "BorderMandateVerifier", "InMemoryAuthorityReceiptCache",
           "InMemoryKnowledgeLedger", "InMemoryMandateNonceStore",
           "KnowledgeLedgerSink", "MandateBundle", "MandateGate",
           "MandateGateError", "MandateNonceStore"]
