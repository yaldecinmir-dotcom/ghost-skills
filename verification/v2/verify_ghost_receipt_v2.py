#!/usr/bin/env python3
"""Verify a Ghost v2 receipt against the HTTP exchange you actually observed.

    pip install cryptography
    python3 verify_ghost_receipt_v2.py <bundle.json> <keys.json> [--settlement-evidence f.json]

What changed from v1, and why this file exists: the v1 verifier recomputed its fingerprints
from a `recomputation_inputs` block that travelled inside the bundle. Editing the observed
request or response while leaving that block intact produced a false pass. Reported by
Merit Systems on 2026-09-11 and reproduced here. v2 never reads a shipped preimage. Every
commitment is derived from `http_request` and `http_response_body`, using the field list
the signed statement itself declares.

Three conclusions are kept apart and never merged:

  DSSE_SIGNATURE   who made the statement.
  PAYLOAD_BINDING  which exchange it is about, recomputed from your own copy.
  PAYMENT_STATE    UNPAID, CLAIMED or SETTLED. A seller may sign at most CLAIMED.
                   SETTLED is reached only by checking settlement evidence independently,
                   and this tool will not print it without that evidence.
"""
import argparse
import base64
import hashlib
import json
import sys
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.ghost.attestation+json"
STATEMENT_TYPE = "ghost-verified-web-search-receipt/v2"


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + sha256(raw).hexdigest()[:32]


def fingerprint(payload) -> str:
    material = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(material.encode()).hexdigest()


def load_keyring(path):
    """Read the key-discovery document. Retired keys stay usable for old receipts."""
    doc = json.loads(open(path).read())
    ring = {}
    for entry in doc.get("keys", []):
        key = serialization.load_pem_public_key(entry["public_key_pem"].encode())
        if not isinstance(key, Ed25519PublicKey):
            continue
        derived = key_id(key)
        if derived != entry.get("keyid"):
            print(f"FAIL  key document lists {entry.get('keyid')} but the material "
                  f"derives {derived}")
            raise SystemExit(2)
        ring[derived] = {"key": key, "not_before": entry.get("not_before") or 0,
                         "not_after": entry.get("not_after"), "status": entry.get("status")}
    return ring


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle"); ap.add_argument("keys")
    ap.add_argument("--settlement-evidence", default="")
    args = ap.parse_args()

    bundle = json.loads(open(args.bundle).read())
    ring = load_keyring(args.keys)
    request, response = bundle["http_request"], bundle["http_response_body"]
    receipt = response["receipt"]
    ok = True

    if not receipt.get("signed"):
        print("FAIL  receipt.signed is false"); return 2
    envelope = receipt["envelope"]
    if envelope["payloadType"] != PAYLOAD_TYPE:
        print(f"FAIL  payloadType {envelope['payloadType']!r}"); return 2

    entry = envelope["signatures"][0]
    trusted = ring.get(entry.get("keyid", ""))
    if trusted is None:
        print(f"FAIL  DSSE_SIGNATURE      no key in the discovery document for "
              f"{entry.get('keyid')!r}")
        return 2

    payload_bytes = base64.standard_b64decode(envelope["payload"])
    try:
        trusted["key"].verify(base64.standard_b64decode(entry["sig"]),
                              pae(envelope["payloadType"], payload_bytes))
    except InvalidSignature:
        print("FAIL  DSSE_SIGNATURE      does not verify over these payload bytes")
        return 2
    statement = json.loads(payload_bytes)
    print(f"ok    DSSE_SIGNATURE       {entry['keyid']}  (establishes WHO signed, nothing else)")

    if statement.get("_type") != STATEMENT_TYPE:
        print(f"FAIL  statement type {statement.get('_type')!r}"); return 2

    signed_at = statement.get("signed_at")
    if signed_at is None:
        print("FAIL  statement carries no signed_at"); return 2
    if not trusted["not_before"] <= signed_at <= (trusted["not_after"] or float("inf")):
        print(f"FAIL  key {entry['keyid']} was not valid at signed_at {signed_at}")
        return 2
    print(f"ok    KEY_VALIDITY         signed_at {signed_at:.0f} inside the key window")
    print(f"ok    IDENTIFIERS          receipt_id={statement.get('receipt_id')} "
          f"operation_id={statement.get('operation_id')}  (identifiers, NOT payment evidence)")

    # ---- request binding, derived from the observed request only -------------------
    sreq = statement["request"]
    defaults = sreq.get("subset_defaults") or {}
    observed_body = request.get("body") or {}
    observed_subset = {f: observed_body.get(f, defaults.get(f))
                       for f in sreq["subset_fields"]}
    got = fingerprint({"method": (request.get("method") or "").upper(),
                       "canonical_url": request.get("url"),
                       "subset": observed_subset})
    if got == sreq["fingerprint"]:
        print(f"ok    REQUEST_BINDING      {sreq['method']} {sreq['canonical_url']}")
    else:
        ok = False
        print("FAIL  REQUEST_BINDING      the observed request is not the one signed")
        print(f"                           signed   {sreq['fingerprint']}")
        print(f"                           observed {got}")
        for field in ("method", "canonical_url"):
            signed_value = sreq[field]
            seen = (request.get("method") or "").upper() if field == "method" \
                else request.get("url")
            if signed_value != seen:
                print(f"                           {field}: signed {signed_value!r}, "
                      f"observed {seen!r}")
        for field in sreq["subset_fields"]:
            if sreq["subset"].get(field) != observed_subset.get(field):
                print(f"                           body.{field}: signed "
                      f"{sreq['subset'].get(field)!r}, observed "
                      f"{observed_subset.get(field)!r}")

    # ---- response binding, derived from the observed response only -----------------
    sres = statement["response"]
    results = response.get("results") or []
    observed_res = {"provider": response.get("provider"),
                    "result_count": len(results),
                    "urls": [r.get("url") for r in results]}
    status = bundle.get("http_response_status", 200)
    got = fingerprint({"status": status, "subset": observed_res})
    if got == sres["fingerprint"]:
        print(f"ok    RESPONSE_BINDING     status {status}, {len(results)} results from "
              f"{observed_res['provider']}")
    else:
        ok = False
        print("FAIL  RESPONSE_BINDING     the observed response is not the one signed")
        print(f"                           signed   {sres['fingerprint']}")
        print(f"                           observed {got}")
        for i, (a, b) in enumerate(zip(sres["subset"].get("urls") or [],
                                       observed_res["urls"])):
            if a != b:
                print(f"                           urls[{i}]: signed {a!r}, observed {b!r}")
    if response.get("result_count") is not None and \
            response.get("result_count") != len(results):
        ok = False
        print(f"FAIL  RESPONSE_SELF_CHECK  body claims result_count "
              f"{response.get('result_count')} but carries {len(results)} results")

    # ---- seller identity ------------------------------------------------------------
    seller = statement.get("seller") or {}
    if seller.get("keyid") and seller["keyid"] != entry["keyid"]:
        ok = False
        print(f"FAIL  SELLER_BINDING       statement names key {seller['keyid']} but is "
              f"signed by {entry['keyid']}")
    else:
        print(f"ok    SELLER_BINDING       {seller.get('domain')} pay_to={seller.get('pay_to')}")

    # ---- payment state --------------------------------------------------------------
    pay = statement.get("payment") or {}
    state = pay.get("state")
    if state == "SETTLED":
        print("FAIL  PAYMENT_STATE        malformed: a seller may not sign SETTLED. "
              "SETTLED is a verifier conclusion, never a seller assertion.")
        return 2
    if state not in ("UNPAID", "CLAIMED"):
        print(f"FAIL  PAYMENT_STATE        unknown state {state!r}"); return 2

    billing = (response.get("billing") or {}).get("fee") or {}
    if billing:
        if str(billing.get("amount")) != str(pay.get("claimed_amount")) or \
                billing.get("currency") != pay.get("currency"):
            ok = False
            print(f"FAIL  BILLING_CROSSCHECK   unsigned billing says "
                  f"{billing.get('amount')} {billing.get('currency')}, signed statement "
                  f"claims {pay.get('claimed_amount')} {pay.get('currency')}")
        else:
            print(f"ok    BILLING_CROSSCHECK   unsigned billing agrees with the signed claim")

    conclusion = state
    if state == "UNPAID":
        print("--    PAYMENT_STATE        UNPAID  (the signed statement asserts no payment; "
              "any paid-looking field elsewhere in the body is not evidence)")
    else:
        ref = pay.get("settlement_reference") or ""
        print(f"--    PAYMENT_STATE        CLAIMED  seller asserts "
              f"{pay.get('claimed_amount')} {pay.get('currency')} via {pay.get('rail')}, "
              f"reference {ref or 'ABSENT'}")
        if not args.settlement_evidence:
            print("--    SETTLEMENT           NOT_VERIFIED  (no independent evidence supplied; "
                  "check the transfer on-chain yourself)")
        else:
            ev = json.loads(open(args.settlement_evidence).read())
            checks = {
                "tx_hash": (ev.get("tx_hash"), ref),
                "to": ((ev.get("to") or "").lower(), (pay.get("pay_to") or "").lower()),
                "asset": ((ev.get("asset") or "").lower(), (pay.get("asset") or "").lower()),
                "network": (ev.get("network"), pay.get("network")),
                "amount_minor": (str(ev.get("amount_minor")),
                                 str(pay.get("claimed_amount_minor"))),
            }
            bad = [k for k, (a, b) in checks.items() if not a or a != b]
            if bad:
                print(f"FAIL  SETTLEMENT           evidence does not match the claim on: "
                      f"{', '.join(bad)}")
                print("--    PAYMENT_STATE        stays CLAIMED; the PAID claim is NOT accepted")
                ok = False
            else:
                conclusion = "SETTLED"
                print(f"ok    SETTLEMENT           independently matched {ev.get('tx_hash')}")

    print()
    if not ok:
        print("RESULT: REJECT"); print("        SIGNATURE_VALID != PURCHASE_VERIFIED.")
        return 1
    print(f"RESULT: SIGNATURE_VALID + PAYLOAD_BOUND; PAYMENT_STATE={conclusion}")
    if conclusion != "SETTLED":
        print("        No settlement has been established by this tool.")
    print("        SIGNATURE_VALID != PURCHASE_VERIFIED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
