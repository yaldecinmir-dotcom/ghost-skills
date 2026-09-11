"""Reference builder for the Ghost receipt, version 2.

Standalone and dependency-light on purpose: this file is published so a buyer can read
exactly how a v2 statement is constructed, without reading Ghost's service. It is NOT
wired into Ghost production, which still emits v1. Adopting v2 in production is a separate,
reviewable change.

The one rule that shapes everything here: a seller cannot sign that money moved.
`payment.state` may be UNPAID or CLAIMED and never SETTLED. SETTLED is a conclusion a
verifier reaches after checking the chain itself.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time

STATEMENT_TYPE = "ghost-verified-web-search-receipt/v2"
PAYLOAD_TYPE = "application/vnd.ghost.attestation+json"

#: The request fields that are part of the commitment, in a fixed order, with the value
#: used when the buyer omitted the field. Declared in the statement so a buyer who sent a
#: shorter body can still recompute the fingerprint.
REQUEST_SUBSET_FIELDS = ("query", "results", "country", "language")
REQUEST_SUBSET_DEFAULTS = {"query": "", "results": 10, "country": "", "language": ""}

#: The response fields that are part of the commitment. Every one is DERIVED from the
#: delivered body rather than copied from a field the body also asserts, so a body cannot
#: lie about itself: `urls` comes from results[].url and `result_count` from len(results).
RESPONSE_SUBSET_FIELDS = ("provider", "result_count", "urls")


def fingerprint(payload) -> str:
    """Canonical JSON, sorted keys, compact separators, SHA-256."""
    material = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(material.encode()).hexdigest()


def request_subset(body: dict) -> dict:
    """The deterministic request subset, extracted from the body actually received."""
    return {field: body.get(field, REQUEST_SUBSET_DEFAULTS[field])
            for field in REQUEST_SUBSET_FIELDS}


def response_subset(body: dict) -> dict:
    """The deterministic response subset, derived from the body actually delivered."""
    results = body.get("results") or []
    return {"provider": body.get("provider"),
            "result_count": len(results),
            "urls": [entry.get("url") for entry in results]}


def request_commitment(*, method: str, canonical_url: str, subset: dict) -> str:
    """Method, resource and body subset hashed together, so none can be swapped alone."""
    return fingerprint({"method": method.upper(), "canonical_url": canonical_url,
                        "subset": subset})


def response_commitment(*, status: int, subset: dict) -> str:
    return fingerprint({"status": status, "subset": subset})


def build_statement(*, method: str, canonical_url: str, request_body: dict,
                    response_status: int, response_body: dict,
                    seller: dict, payment: dict,
                    oracle_verdict: dict, provenance: dict,
                    served_at: float | None = None, signed_at: float | None = None,
                    receipt_id: str = "", operation_id: str = "") -> dict:
    """Assemble a v2 statement. The caller signs the result with a DSSE signer."""
    state = (payment or {}).get("state", "UNPAID")
    if state not in ("UNPAID", "CLAIMED"):
        raise ValueError("payment.state must be UNPAID or CLAIMED; a seller cannot "
                         "sign SETTLED")
    served_at = time.time() if served_at is None else served_at
    signed_at = time.time() if signed_at is None else signed_at
    req_subset = request_subset(request_body)
    res_subset = response_subset(response_body)
    return {
        "_type": STATEMENT_TYPE,
        # Identifies THIS receipt and THIS delivered operation. Two identical searches
        # produce two different receipts. These are identifiers, not payment evidence.
        "receipt_id": receipt_id or ("grc_" + secrets.token_hex(16)),
        "operation_id": operation_id or ("gop_" + secrets.token_hex(16)),
        "served_at": served_at,
        "signed_at": signed_at,
        "seller": dict(seller),
        "request": {
            "method": method.upper(),
            "canonical_url": canonical_url,
            "subset_fields": list(REQUEST_SUBSET_FIELDS),
            "subset_defaults": dict(REQUEST_SUBSET_DEFAULTS),
            "subset": req_subset,
            "fingerprint": request_commitment(method=method, canonical_url=canonical_url,
                                              subset=req_subset),
        },
        "response": {
            "status": response_status,
            "subset_fields": list(RESPONSE_SUBSET_FIELDS),
            "subset": res_subset,
            "fingerprint": response_commitment(status=response_status, subset=res_subset),
        },
        "provenance": dict(provenance),
        "oracle_verdict": dict(oracle_verdict),
        "payment": dict(payment),
    }
