"""Ghost receipt v2.1: canonicalisation, the fixed profile, and the statement builder.

Published for review. NOT wired into Ghost production, which still emits v1.

Three things changed from v2, each because the v2 fixture was attacked successfully and
the attack is recorded in `repro/`:

1. **RFC 8785 JCS** replaces `json.dumps(sort_keys=True)`. The old form escaped non-ASCII
   to \\uXXXX, wrote integral floats as `3.0`, and sorted keys by code point. JCS emits raw
   UTF-8, writes `3`, and sorts by UTF-16 code unit. A JavaScript verifier therefore
   computed a different digest for any query containing non-ASCII text, which for a search
   product is not an edge case.
2. **A fixed required profile.** v2 let the signer declare which fields were bound, so a
   seller could drop `query` from `subset_fields` and then swap the query freely. The field
   list is now fixed per statement type and the verifier refuses any statement that
   declares a different one.
3. **A delivered-content digest.** v2 bound only provider, count and URLs, so titles,
   snippets, the answer box and the knowledge panel could all be rewritten with the receipt
   still verifying.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import time

STATEMENT_TYPE = "ghost-verified-web-search-receipt/v2.1"
PAYLOAD_TYPE = "application/vnd.ghost.attestation+json"
SIGNATURE_ALGORITHM = "ed25519"
MAX_SIGNATURES = 1

# ---------------------------------------------------------------- RFC 8785 (JCS)

def _jcs_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code == 0x08:
            out.append("\\b")
        elif code == 0x0C:
            out.append("\\f")
        elif code == 0x0A:
            out.append("\\n")
        elif code == 0x0D:
            out.append("\\r")
        elif code == 0x09:
            out.append("\\t")
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)          # raw UTF-8, no \\uXXXX escaping
    out.append('"')
    return "".join(out)


def _jcs_number(value) -> str:
    """ECMAScript Number::toString, which is what RFC 8785 defers to."""
    if isinstance(value, bool):
        raise TypeError("bool is not a number")
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        raise ValueError("NaN and Infinity have no JSON serialisation")
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))      # 3.0 serialises as 3, not 3.0
    return repr(value)              # shortest round-trip, matches JS for finite doubles


def _utf16_sort_key(key: str) -> bytes:
    """JCS orders members by UTF-16 code unit, not by code point."""
    return key.encode("utf-16-be", errors="surrogatepass")


def jcs(value) -> str:
    """RFC 8785 JSON Canonicalization Scheme."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_sort_key(kv[0]))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v) for k, v in items) + "}"
    raise TypeError(f"{type(value).__name__} has no canonical form")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(jcs(value).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- fixed profile

#: Fixed for this statement type. A signer may not add, drop or reorder these.
REQUEST_SUBSET_FIELDS = ("query", "results", "country", "language")
REQUEST_SUBSET_DEFAULTS = {"query": "", "results": 10, "country": "", "language": ""}
RESPONSE_SUBSET_FIELDS = ("provider", "result_count", "urls", "content_digest")

#: Every delivered field that the content digest covers, in a fixed order.
RESULT_FIELDS = ("title", "url", "snippet", "position", "published")
DELIVERY_FIELDS = ("answer", "knowledge", "related_questions", "related_searches")

PROFILE = {
    "statement_type": STATEMENT_TYPE,
    "canonicalisation": "RFC 8785 JCS over UTF-8",
    "signature_algorithm": SIGNATURE_ALGORITHM,
    "max_signatures": MAX_SIGNATURES,
    "request_subset_fields": list(REQUEST_SUBSET_FIELDS),
    "request_subset_defaults": dict(REQUEST_SUBSET_DEFAULTS),
    "response_subset_fields": list(RESPONSE_SUBSET_FIELDS),
    "result_fields": list(RESULT_FIELDS),
    "delivery_fields": list(DELIVERY_FIELDS),
    "required_seller_fields": ["domain", "pay_to", "keyid"],
    "signed_payment_states": ["UNPAID", "CLAIMED"],
}


# ---------------------------------------------------------------- commitments

def request_subset(body: dict) -> dict:
    return {f: body.get(f, REQUEST_SUBSET_DEFAULTS[f]) for f in REQUEST_SUBSET_FIELDS}


def content_digest(body: dict) -> str:
    """A digest over everything delivered, not just the URLs.

    Each result contributes a fixed field list in a fixed order, so a rewritten title or
    snippet changes the digest. Absent optional blocks contribute null rather than being
    omitted, so "no answer box" and "an answer box that was deleted" are different.
    """
    results = body.get("results") or []
    normalised = {
        "results": [{f: r.get(f) for f in RESULT_FIELDS} for r in results],
        **{f: body.get(f) for f in DELIVERY_FIELDS},
    }
    return digest(normalised)


def response_subset(body: dict) -> dict:
    results = body.get("results") or []
    return {"provider": body.get("provider"),
            "result_count": len(results),
            "urls": [r.get("url") for r in results],
            "content_digest": content_digest(body)}


def request_commitment(*, method: str, exact_resource_url: str, subset: dict) -> str:
    # method is NOT case-folded: RFC 9110 defines it as case-sensitive.
    return digest({"method": method, "exact_resource_url": exact_resource_url,
                   "subset": subset})


def response_commitment(*, status: int, subset: dict) -> str:
    return digest({"status": status, "subset": subset})


def build_statement(*, method: str, exact_resource_url: str, request_body: dict,
                    response_status: int, response_body: dict, seller: dict, payment: dict,
                    oracle_verdict: dict, provenance: dict,
                    served_at: float | None = None, signed_at: float | None = None,
                    receipt_id: str = "", operation_id: str = "") -> dict:
    state = (payment or {}).get("state", "UNPAID")
    if state not in PROFILE["signed_payment_states"]:
        raise ValueError("payment.state must be UNPAID or CLAIMED; a seller cannot sign "
                         "SETTLED")
    for field in PROFILE["required_seller_fields"]:
        if not (seller or {}).get(field):
            raise ValueError(f"seller.{field} is required")
    served_at = time.time() if served_at is None else served_at
    signed_at = time.time() if signed_at is None else signed_at
    req_subset = request_subset(request_body)
    res_subset = response_subset(response_body)
    return {
        "_type": STATEMENT_TYPE,
        "profile": {"canonicalisation": PROFILE["canonicalisation"],
                    "signature_algorithm": SIGNATURE_ALGORITHM,
                    "max_signatures": MAX_SIGNATURES},
        "receipt_id": receipt_id or ("grc_" + secrets.token_hex(16)),
        "operation_id": operation_id or ("gop_" + secrets.token_hex(16)),
        "served_at": served_at,
        "signed_at": signed_at,
        "seller": dict(seller),
        "request": {"method": method, "exact_resource_url": exact_resource_url,
                    "subset_fields": list(REQUEST_SUBSET_FIELDS),
                    "subset_defaults": dict(REQUEST_SUBSET_DEFAULTS),
                    "subset": req_subset,
                    "fingerprint": request_commitment(
                        method=method, exact_resource_url=exact_resource_url,
                        subset=req_subset)},
        "response": {"status": response_status,
                     "subset_fields": list(RESPONSE_SUBSET_FIELDS),
                     "subset": res_subset,
                     "fingerprint": response_commitment(status=response_status,
                                                        subset=res_subset)},
        "provenance": dict(provenance),
        "oracle_verdict": dict(oracle_verdict),
        "payment": dict(payment),
    }
