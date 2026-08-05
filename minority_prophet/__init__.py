"""Minority Prophet Gate: refuse manufactured consensus in multi-agent systems.

Counts independent, attested evidence roots instead of voices. Core
properties are proven (see FORMAL.md): copy invariance, immunity to
side-preserving lineage corruption, and the margin flip condition.
"""
from .aggregator import Claim, EvidenceGraph, Verdict, aggregate
from .reconcile import StateVerdict, reconcile
from .adapter_acp import AttestationVerifier, TrustAllVerifier, envelopes_to_claims
from .gate import GateDecision, decide
from .runtime_adapter import (
    RuntimeAction,
    RuntimeAdapter,
    RuntimeBoundaryError,
    RuntimeController,
    RuntimeReceipt,
)

__version__ = "0.1.0"
__all__ = ["Claim", "EvidenceGraph", "Verdict", "aggregate",
           "StateVerdict", "reconcile",
           "AttestationVerifier", "TrustAllVerifier", "envelopes_to_claims",
           "GateDecision", "decide",
           "RuntimeAction", "RuntimeAdapter", "RuntimeBoundaryError",
           "RuntimeController", "RuntimeReceipt"]
