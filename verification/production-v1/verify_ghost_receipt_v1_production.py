#!/usr/bin/env python3
"""Verify a receipt that Ghost PRODUCTION actually emits. Supported path.

    pip install cryptography
    python3 verify_ghost_receipt_v1_production.py <bundle.json> [--keys keys.json]

Production emits v1 statements. This verifier exists because neither published verifier
was safe to point at one:

  verification/verify_ghost_receipt.py   recomputes its bindings from a `recomputation_
                                         inputs` block carried inside the bundle rather
                                         than from the observed HTTP exchange, so an
                                         observed-only tamper passes. UNSUPPORTED.
  verification/v2.1/...                  requires `signed_at` and the v2.1 statement
                                         type. A production v1 receipt has neither.

Four conclusions, never merged:

  SIGNATURE_VALID        who signed, under a key allowed to sign receipts. Nothing more.
  PAYLOAD_BOUND          which exchange, recomputed from YOUR copy of request and
                         response.
  DELIVERY_BOUND         what of the delivered answer is actually covered. In v1 that is
                         the provider, the result count and the URLs — and NOT the
                         titles, snippets, positions, answer box or knowledge panel.
  SETTLEMENT_UNVERIFIED  always, for v1. The statement binds no amount, no currency and
                         no settlement reference, so this tool cannot and will not report
                         a payment as established. A payment may well have settled; read
                         the chain yourself.
"""
import argparse
import base64
import hashlib
import json
import sys
import urllib.request
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.ghost.attestation+json"
ORIGIN = "https://ghost-identity.ghost-agent-os.workers.dev"
KEY_DISCOVERY = f"{ORIGIN}/.well-known/ghost-receipt-keys.json"

#: The ONE statement type this verifier supports, and the timestamp field it signs.
#: Selected by exact `_type` match and never guessed: v1 signs `served_at` and carries no
#: `served_at`-to-`signed_at` fallback, and a verifier that tried both would accept a
#: statement with no trustworthy time as though it had one.
SEARCH_RECEIPT = "ghost-verified-web-search-receipt/v1"
TIMESTAMP_FIELD = {SEARCH_RECEIPT: "served_at"}

#: Production also emits these. They are REFUSED here, on purpose. An earlier revision of
#: this file accepted them, checked the signature, skipped their bindings with a note, and
#: still printed PAYLOAD_BOUND — so a validly signed receipt of either type verified even
#: after the observed query and result URLs were rewritten. A verifier must never claim a
#: binding it did not recompute. Until each type's complete binding profile is implemented
#: from the producing code, the only honest answer is to stop.
REFUSED_TYPES = {
    "ghost-verified-search-receipt/v1":
        "its request and response preimages are not implemented in this verifier",
    "ghost-service-receipt/v2":
        "its request and response preimages are not implemented in this verifier",
}

failures: list[str] = []


def fail(label, *lines):
    failures.append(label)
    print(f"FAIL  {label:<22} {lines[0] if lines else ''}")
    for line in lines[1:]:
        print(f"      {'':<22} {line}")


def ok(label, detail=""):
    print(f"ok    {label:<22} {detail}")


def note(label, detail=""):
    print(f"--    {label:<22} {detail}")


def fingerprint(payload) -> str:
    """v1 canonicalisation: sorted keys, compact separators, SHA-256.

    Note this is NOT RFC 8785. A query containing non-ASCII text is escaped here and is
    not escaped under JCS, so a JCS implementation computes a different digest for the
    same query. v1 is pinned to what production emits; the JCS migration lives in the
    v2.1 fixture and is not deployed.
    """
    material = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(material.encode()).hexdigest()


def key_id(public_key) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw,
                                  serialization.PublicFormat.Raw)
    return "ed25519:" + sha256(raw).hexdigest()[:32]


def fetch_keys(path: str | None) -> dict:
    if path:
        return json.loads(open(path).read())
    request = urllib.request.Request(
        KEY_DISCOVERY, headers={"User-Agent": "ghost-receipt-verifier/1",
                                "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--keys", default="",
                        help="a local copy of the key document; omit to fetch the origin's")
    args = parser.parse_args()

    bundle = json.loads(open(args.bundle).read())
    request = bundle.get("http_request") or {}
    response = bundle.get("http_response_body") or {}
    receipt = response.get("receipt") or {}

    if not receipt.get("signed"):
        fail("RECEIPT", "receipt.signed is false; this deployment configured no key")
        return 2
    envelope = receipt["envelope"]
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        fail("PAYLOAD_TYPE", f"{envelope.get('payloadType')!r}")
        return 2

    signatures = envelope.get("signatures") or []
    if len(signatures) != 1:
        fail("SIGNATURE_PROFILE", f"exactly one signature is expected, found "
                                  f"{len(signatures)}")
        return 2
    entry = signatures[0]
    keyid = entry.get("keyid", "")

    document = fetch_keys(args.keys or None)
    listed = {k["keyid"]: k for k in document.get("keys", [])}
    trusted = listed.get(keyid)
    if trusted is None:
        fail("SIGNATURE_VALID", f"no key in the discovery document for {keyid!r}")
        return 2
    if trusted.get("use") != "receipt":
        fail("KEY_SCOPE", f"key use {trusted.get('use')!r} may not sign receipts")
        return 2

    public_key = serialization.load_pem_public_key(trusted["public_key_pem"].encode())
    if not isinstance(public_key, Ed25519PublicKey):
        fail("KEY_SCOPE", "the listed key is not Ed25519")
        return 2
    if key_id(public_key) != keyid:
        fail("KEY_SCOPE", f"the listed material derives {key_id(public_key)}, not {keyid}")
        return 2

    payload = base64.standard_b64decode(envelope["payload"])
    try:
        public_key.verify(base64.standard_b64decode(entry["sig"]),
                          b"DSSEv1 %d %s %d %s" % (len(PAYLOAD_TYPE),
                                                   PAYLOAD_TYPE.encode(),
                                                   len(payload), payload))
    except InvalidSignature:
        fail("SIGNATURE_VALID", "does not verify over these payload bytes")
        return 2
    statement = json.loads(payload)
    ok("SIGNATURE_VALID", f"{keyid} (use=receipt, status={trusted.get('status')}) "
                          f"— establishes WHO signed, nothing else")

    statement_type = statement.get("_type")
    if statement_type in REFUSED_TYPES:
        fail("STATEMENT_TYPE", f"{statement_type!r} is a production statement type this "
                               f"verifier does NOT support",
             REFUSED_TYPES[statement_type],
             "the signature above is genuine, and that is all this tool can say; no "
             "binding was checked and none is claimed")
        return 2
    field = TIMESTAMP_FIELD.get(statement_type)
    if field is None:
        fail("STATEMENT_TYPE", f"{statement_type!r} is not a supported production "
                               f"statement type; supported: {SEARCH_RECEIPT!r}",
             "v2.1 fixtures use their own verifier")
        return 2

    # ---- timestamp: the field this version actually signs, with no fallback --------
    when = statement.get(field)
    if when is None:
        fail("TIMESTAMP", f"{statement_type} must sign {field!r} and does not",
             "there is no fallback to another field; a statement with no signed time "
             "cannot be placed inside a key window")
        return 2
    ok("TIMESTAMP", f"{field}={when:.0f} (seller-asserted; not a trusted timestamp and "
                    f"not transparency-backed)")

    # ---- key validity, judged against the signed timestamp ------------------------
    if trusted.get("status") == "revoked":
        fail("KEY_SCOPE", "the signing key is revoked",
             "revocation is HARD: the only timestamp available is the seller-asserted one "
             "inside this statement, so a holder of the compromised key could date it "
             "before the revocation")
        return 2
    not_before = trusted.get("not_before") or 0
    not_after = trusted.get("not_after")          # null and 0 are different
    if when < not_before:
        fail("KEY_SCOPE", f"{field} {when:.0f} precedes not_before {not_before}")
        return 2
    if not_after is not None and when > not_after:
        fail("KEY_SCOPE", f"{field} {when:.0f} is after not_after {not_after} "
                          f"(status {trusted.get('status')})")
        return 2
    ok("KEY_VALIDITY", f"inside the window for a {trusted.get('status')} key")

    # ---- bindings, recomputed from the exchange you observed ----------------------
    # Only SEARCH_RECEIPT reaches this point. `bindings_checked` is what licenses the word
    # PAYLOAD_BOUND below; nothing else does.
    bindings_checked = {"request": False, "response": False}
    if statement_type == SEARCH_RECEIPT:
        body = request.get("body") or {}
        if "query" not in body:
            fail("REQUEST_BINDING", "http_request.body.query is required to recompute")
        else:
            observed = {"query": body.get("query"),
                        "results": body.get("results", 10)}
            got = fingerprint(observed)
            bindings_checked["request"] = True
            if got == statement.get("request_fingerprint"):
                ok("REQUEST_BINDING", statement["request_fingerprint"])
            else:
                fail("REQUEST_BINDING", "the observed request is not the one signed",
                     f"signed   {statement.get('request_fingerprint')}",
                     f"observed {got}",
                     "note: `results` defaults to 10 when the buyer omitted it, and the "
                     "signed preimage uses the effective value")

        results = response.get("results") or []
        observed = {"provider": response.get("provider"),
                    "result_count": response.get("result_count"),
                    "urls": [r.get("url") for r in results]}
        got = fingerprint(observed)
        bindings_checked["response"] = True
        if got == statement.get("response_fingerprint"):
            ok("RESPONSE_BINDING", statement["response_fingerprint"])
        else:
            fail("RESPONSE_BINDING", "the observed response is not the one signed",
                 f"signed   {statement.get('response_fingerprint')}",
                 f"observed {got}")

        attributes = statement.get("attributes") or {}
        if attributes.get("provider"):
            if attributes["provider"] == response.get("provider"):
                ok("PROVENANCE_BINDING", f"provider={attributes['provider']} (signed)")
            else:
                fail("PROVENANCE_BINDING",
                     f"signed provider={attributes['provider']}, body claims "
                     f"{response.get('provider')}")
        ok("DELIVERY_BOUND", "PARTIAL — the provider, the result count and the URLs are "
                             "covered")
        note("DELIVERY_NOT_BOUND", "titles, snippets, positions, the answer box and the "
                                   "knowledge panel are OUTSIDE the commitment and could "
                                   "differ from what was signed")

    # ---- payment: v1 signs nothing that supports a conclusion ---------------------
    payment = statement.get("payment") or {}
    status = payment.get("status")
    note("PAYMENT_STATE", f"NOT ESTABLISHED — v1 signs no amount and no currency. The "
                          f"signed payment block reads status={status}, "
                          f"evidence_class={payment.get('evidence_class')}, "
                          f"reference={payment.get('reference')!r}")
    if status not in ("NOT_ATTESTED", None):
        # A v1 search receipt must decline to speak about payment. Anything else here is
        # a claim the format cannot support.
        fail("PAYMENT_CLAIM", f"the signed payment block claims status={status!r}, but "
                              f"nothing in a v1 statement binds a settlement",
             "expected NOT_ATTESTED")
    note("SETTLEMENT_UNVERIFIED", "ALWAYS, for v1. Ghost settles UPFRONT, so a settlement "
                                  "very likely exists — and this receipt does not evidence "
                                  "it. Read the USDC transfer on Base yourself.")
    note("BILLING", "the `billing` block in the response body is OUTSIDE the signature, "
                    "so editing it changes nothing this tool checks")

    print()
    if failures:
        print("RESULT: REJECT   failed: " + ", ".join(dict.fromkeys(failures)))
    elif not all(bindings_checked.values()):
        # Unreachable by construction, kept as a guard: the success wording below must
        # be impossible to print when either binding was not actually recomputed.
        print("RESULT: REJECT   bindings not evaluated: "
              + ", ".join(k for k, v in bindings_checked.items() if not v))
        failures.append("BINDINGS_NOT_EVALUATED")
    else:
        print("RESULT: SIGNATURE_VALID + PAYLOAD_BOUND + DELIVERY_BOUND(partial); "
              "SETTLEMENT_UNVERIFIED")
        print("        Payment and settlement are NOT established by this receipt.")
    print("        SIGNATURE_VALID != PURCHASE_VERIFIED.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
