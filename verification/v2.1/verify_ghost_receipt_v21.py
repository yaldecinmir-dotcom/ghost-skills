#!/usr/bin/env python3
"""Verify a Ghost v2.1 receipt against the HTTP exchange you observed.

    pip install cryptography
    python3 verify_ghost_receipt_v21.py <bundle.json> <keys.json> [options]

      --profile production|fixture   which key scope may sign (default: production)
      --settlement-evidence FILE     an unsigned claim you assembled yourself
      --facilitator-evidence FILE    a DSSE envelope signed by a trusted facilitator key

Conclusions, kept strictly apart:

  DSSE_SIGNATURE            who signed, under a key scope that is allowed to sign this.
  PAYLOAD_BINDING           which exchange, recomputed from your own copy of it.
  SELLER_ASSERTION_BOUND    what the seller says it is. NOT proof of ownership.
  SETTLEMENT_EVIDENCE_MATCHED   an unsigned file you supplied agrees with the claim.
  PAYMENT_STATE=SETTLED     only from facilitator-signed evidence or your own chain read.
"""
import argparse, base64, json, sys
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, __file__.rsplit("/", 1)[0] if "/" in __file__ else ".")
from ghost_receipt_v21 import (MAX_SIGNATURES, PAYLOAD_TYPE, PROFILE, SIGNATURE_ALGORITHM,
                               STATEMENT_TYPE, content_digest, digest, jcs,
                               request_commitment, response_commitment)

FAILURES: list[str] = []


def fail(label, *lines):
    FAILURES.append(label)
    print(f"FAIL  {label:<22} {lines[0] if lines else ''}")
    for extra in lines[1:]:
        print(f"      {'':<22} {extra}")


def ok(label, detail=""):
    print(f"ok    {label:<22} {detail}")


def note(label, detail=""):
    print(f"--    {label:<22} {detail}")


def key_id(public_key) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + sha256(raw).hexdigest()[:32]


def load_keyring(path):
    doc = json.loads(open(path).read())
    ring = {}
    for entry in doc.get("keys", []):
        if entry.get("algorithm") != SIGNATURE_ALGORITHM:
            continue
        key = serialization.load_pem_public_key(entry["public_key_pem"].encode())
        if not isinstance(key, Ed25519PublicKey):
            continue
        derived = key_id(key)
        if derived != entry.get("keyid"):
            print(f"FAIL  key document claims {entry.get('keyid')} for material that "
                  f"derives {derived}")
            raise SystemExit(2)
        ring[derived] = {"key": key, "status": entry.get("status"),
                         "use": entry.get("use"),
                         "not_before": entry.get("not_before") or 0,
                         # null means open-ended; 0 means expired at the epoch.
                         "not_after": entry.get("not_after"),
                         "revoked_at": entry.get("revoked_at")}
    return ring


def key_usable(entry, *, signed_at, profile):
    """Scope, status and window. Every refusal names itself."""
    allowed_use = {"production": {"receipt"}, "fixture": {"receipt", "fixture"}}[profile]
    if entry["use"] not in allowed_use:
        return f"key use {entry['use']!r} may not sign under the {profile!r} profile"
    if entry["status"] == "revoked":
        at = entry.get("revoked_at")
        if at is None or signed_at >= at:
            return "key is revoked"
    if signed_at < entry["not_before"]:
        return f"signed_at {signed_at:.0f} precedes not_before {entry['not_before']}"
    if entry["not_after"] is not None and signed_at > entry["not_after"]:
        return (f"signed_at {signed_at:.0f} is after not_after {entry['not_after']} "
                f"(status {entry['status']})")
    return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle"); ap.add_argument("keys")
    ap.add_argument("--profile", choices=("production", "fixture"), default="production")
    ap.add_argument("--settlement-evidence", default="")
    ap.add_argument("--facilitator-evidence", default="")
    args = ap.parse_args()

    bundle = json.loads(open(args.bundle).read())
    ring = load_keyring(args.keys)
    request = bundle.get("http_request") or {}
    response = bundle.get("http_response_body") or {}
    receipt = response.get("receipt") or {}

    if not receipt.get("signed"):
        fail("RECEIPT", "receipt.signed is false"); return 2
    envelope = receipt["envelope"]
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        fail("PAYLOAD_TYPE", f"{envelope.get('payloadType')!r}"); return 2

    # ---- signature profile: exactly one, ed25519 only -----------------------------
    signatures = envelope.get("signatures") or []
    if len(signatures) != MAX_SIGNATURES:
        fail("SIGNATURE_PROFILE",
             f"this statement type permits exactly {MAX_SIGNATURES} signature, "
             f"found {len(signatures)}")
        return 2
    entry = signatures[0]
    keyid = entry.get("keyid", "")
    if not keyid.startswith("ed25519:"):
        fail("SIGNATURE_PROFILE", f"algorithm profile is {SIGNATURE_ALGORITHM} only; "
                                  f"keyid {keyid!r}")
        return 2
    trusted = ring.get(keyid)
    if trusted is None:
        fail("DSSE_SIGNATURE", f"no key in the discovery document for {keyid!r}"); return 2

    payload_bytes = base64.standard_b64decode(envelope["payload"])
    try:
        trusted["key"].verify(base64.standard_b64decode(entry["sig"]),
                              b"DSSEv1 %d %s %d %s" % (len(PAYLOAD_TYPE),
                                                       PAYLOAD_TYPE.encode(),
                                                       len(payload_bytes), payload_bytes))
    except InvalidSignature:
        fail("DSSE_SIGNATURE", "does not verify over these payload bytes"); return 2
    statement = json.loads(payload_bytes)

    if statement.get("_type") != STATEMENT_TYPE:
        fail("STATEMENT_TYPE", f"{statement.get('_type')!r}"); return 2
    signed_at = statement.get("signed_at")
    if signed_at is None:
        fail("SIGNED_AT", "absent"); return 2

    refusal = key_usable(trusted, signed_at=signed_at, profile=args.profile)
    if refusal:
        fail("KEY_SCOPE", refusal, f"keyid {keyid}"); return 2
    ok("DSSE_SIGNATURE", f"{keyid} (use={trusted['use']}, status={trusted['status']}, "
                         f"profile={args.profile})")
    ok("IDENTIFIERS", f"receipt_id={statement.get('receipt_id')} "
                      f"operation_id={statement.get('operation_id')} "
                      f"(identifiers, NOT payment evidence)")

    # ---- fixed profile: the signer may not choose what is bound -------------------
    sreq, sres = statement.get("request") or {}, statement.get("response") or {}
    if list(sreq.get("subset_fields") or []) != PROFILE["request_subset_fields"]:
        fail("MANDATORY_PROFILE",
             f"request subset_fields must be exactly {PROFILE['request_subset_fields']}",
             f"statement declares {sreq.get('subset_fields')}")
    if list(sres.get("subset_fields") or []) != PROFILE["response_subset_fields"]:
        fail("MANDATORY_PROFILE",
             f"response subset_fields must be exactly {PROFILE['response_subset_fields']}",
             f"statement declares {sres.get('subset_fields')}")
    if not FAILURES:
        ok("MANDATORY_PROFILE", "declared field lists match the fixed profile")

    # ---- signed clear fields must agree with the signed fingerprints --------------
    if not FAILURES:
        recomputed = request_commitment(method=sreq["method"],
                                        exact_resource_url=sreq["exact_resource_url"],
                                        subset=sreq["subset"])
        if recomputed != sreq["fingerprint"]:
            fail("SIGNED_SELF_CONSISTENCY",
                 "request fingerprint does not match the statement's own clear fields",
                 f"declared  {sreq['fingerprint']}", f"from clear {recomputed}")
        recomputed = response_commitment(status=sres["status"], subset=sres["subset"])
        if recomputed != sres["fingerprint"]:
            fail("SIGNED_SELF_CONSISTENCY",
                 "response fingerprint does not match the statement's own clear fields",
                 f"declared  {sres['fingerprint']}", f"from clear {recomputed}")
        if "SIGNED_SELF_CONSISTENCY" not in FAILURES:
            ok("SIGNED_SELF_CONSISTENCY", "clear fields and fingerprints agree")

    # ---- observed request --------------------------------------------------------
    if not FAILURES:
        defaults = sreq.get("subset_defaults") or {}
        body = request.get("body") or {}
        observed = {f: body.get(f, defaults.get(f)) for f in PROFILE["request_subset_fields"]}
        got = request_commitment(method=request.get("method"),
                                 exact_resource_url=request.get("url"), subset=observed)
        if got == sreq["fingerprint"]:
            ok("REQUEST_BINDING", f"{sreq['method']} {sreq['exact_resource_url']}")
        else:
            lines = ["the observed request is not the one signed",
                     f"signed   {sreq['fingerprint']}", f"observed {got}"]
            if sreq["method"] != request.get("method"):
                lines.append(f"method: signed {sreq['method']!r}, observed "
                             f"{request.get('method')!r} (case-sensitive, RFC 9110)")
            if sreq["exact_resource_url"] != request.get("url"):
                lines.append(f"url: signed {sreq['exact_resource_url']!r}, observed "
                             f"{request.get('url')!r}")
            for f in PROFILE["request_subset_fields"]:
                if sreq["subset"].get(f) != observed.get(f):
                    lines.append(f"body.{f}: signed {sreq['subset'].get(f)!r}, observed "
                                 f"{observed.get(f)!r}")
            fail("REQUEST_BINDING", *lines)

    # ---- observed response, including delivered content --------------------------
    if not FAILURES:
        status = bundle.get("http_response_status")
        if status is None:
            fail("RESPONSE_STATUS", "http_response_status is absent; it is part of the "
                                    "commitment and is never assumed")
        else:
            results = response.get("results") or []
            observed = {"provider": response.get("provider"),
                        "result_count": len(results),
                        "urls": [r.get("url") for r in results],
                        "content_digest": content_digest(response)}
            got = response_commitment(status=status, subset=observed)
            if got == sres["fingerprint"]:
                ok("RESPONSE_BINDING", f"status {status}, {len(results)} results from "
                                       f"{observed['provider']}")
                ok("DELIVERED_CONTENT", f"{observed['content_digest'][:23]}… covers titles, "
                                        f"snippets, positions, answer and knowledge")
            else:
                lines = ["the observed response is not the one signed",
                         f"signed   {sres['fingerprint']}", f"observed {got}"]
                if sres["subset"].get("content_digest") != observed["content_digest"]:
                    lines.append("delivered content differs: a title, snippet, position, "
                                 "answer or knowledge block was changed")
                for i, (a, b) in enumerate(zip(sres["subset"].get("urls") or [],
                                               observed["urls"])):
                    if a != b:
                        lines.append(f"urls[{i}]: signed {a!r}, observed {b!r}")
                fail("RESPONSE_BINDING", *lines)
            if response.get("result_count") is not None and \
                    response.get("result_count") != len(results):
                fail("RESPONSE_SELF_CHECK",
                     f"body claims result_count {response.get('result_count')} but carries "
                     f"{len(results)} results")

    # ---- seller: an assertion, bound but never proved ----------------------------
    seller = statement.get("seller") or {}
    missing = [f for f in PROFILE["required_seller_fields"] if not seller.get(f)]
    pay = statement.get("payment") or {}
    if missing:
        fail("SELLER_BINDING", f"required seller fields absent: {', '.join(missing)}")
    else:
        if seller["keyid"] != keyid:
            fail("SELLER_BINDING", f"statement names key {seller['keyid']} but is signed "
                                   f"by {keyid}")
        host = (sreq.get("exact_resource_url") or "").split("//")[-1].split("/")[0]
        if seller["domain"] != host:
            fail("SELLER_BINDING", f"seller.domain {seller['domain']!r} is not the host of "
                                   f"the signed resource URL ({host!r})")
        if pay.get("state") == "CLAIMED" and seller["pay_to"] != pay.get("pay_to"):
            fail("SELLER_BINDING", f"seller.pay_to {seller['pay_to']} does not match "
                                   f"payment.pay_to {pay.get('pay_to')}")
        if "SELLER_BINDING" not in FAILURES:
            note("SELLER_ASSERTION_BOUND",
                 f"{seller['domain']} pay_to={seller['pay_to']} — asserted by the signer "
                 f"and bound to the signature; domain ownership is NOT proved here")

    # ---- payment -----------------------------------------------------------------
    state = pay.get("state")
    if state == "SETTLED":
        fail("PAYMENT_STATE", "malformed: a seller may not sign SETTLED. SETTLED is a "
                              "verifier conclusion, never a seller assertion")
        return 2
    if state not in PROFILE["signed_payment_states"]:
        fail("PAYMENT_STATE", f"unknown state {state!r}"); return 2

    billing = (response.get("billing") or {}).get("fee") or {}
    if billing:
        if str(billing.get("amount")) != str(pay.get("claimed_amount")) or \
                billing.get("currency") != pay.get("currency"):
            fail("BILLING_CROSSCHECK",
                 f"unsigned billing says {billing.get('amount')} {billing.get('currency')}, "
                 f"signed claim is {pay.get('claimed_amount')} {pay.get('currency')}")
        else:
            ok("BILLING_CROSSCHECK", "unsigned billing agrees with the signed claim")

    conclusion = state
    if state == "UNPAID":
        note("PAYMENT_STATE", "UNPAID — the signed statement asserts no payment; any "
                              "paid-looking field elsewhere is not evidence")
    else:
        ref = pay.get("settlement_reference") or ""
        note("PAYMENT_STATE", f"CLAIMED — seller asserts {pay.get('claimed_amount')} "
                              f"{pay.get('currency')} via {pay.get('rail')}, reference "
                              f"{ref or 'ABSENT'}")

        def matches(ev):
            checks = {"tx_hash": (ev.get("tx_hash"), ref),
                      "to": ((ev.get("to") or "").lower(), (pay.get("pay_to") or "").lower()),
                      "asset": ((ev.get("asset") or "").lower(),
                                (pay.get("asset") or "").lower()),
                      "network": (ev.get("network"), pay.get("network")),
                      "amount_minor": (str(ev.get("amount_minor")),
                                       str(pay.get("claimed_amount_minor")))}
            return [k for k, (a, b) in checks.items() if not a or a != b]

        if args.settlement_evidence:
            bad = matches(json.loads(open(args.settlement_evidence).read()))
            if bad:
                fail("SETTLEMENT_EVIDENCE_MATCHED", f"mismatch on: {', '.join(bad)}")
                note("PAYMENT_STATE", "stays CLAIMED; the PAID claim is NOT accepted")
            else:
                note("SETTLEMENT_EVIDENCE_MATCHED",
                     "an UNSIGNED file you supplied agrees with the claim. This is a "
                     "consistency check on your own notes, not proof that a transfer "
                     "happened. PAYMENT_STATE stays CLAIMED.")
        if args.facilitator_evidence:
            env = json.loads(open(args.facilitator_evidence).read())
            sigs = env.get("signatures") or []
            fkeyid = sigs[0].get("keyid") if len(sigs) == 1 else ""
            ftrusted = ring.get(fkeyid or "")
            if ftrusted is None or ftrusted.get("use") != "facilitator":
                fail("SETTLEMENT", "evidence is not signed by a key the discovery document "
                                   "lists with use=facilitator")
            else:
                fpayload = base64.standard_b64decode(env["payload"])
                try:
                    ftrusted["key"].verify(
                        base64.standard_b64decode(sigs[0]["sig"]),
                        b"DSSEv1 %d %s %d %s" % (len(env["payloadType"]),
                                                 env["payloadType"].encode(),
                                                 len(fpayload), fpayload))
                except InvalidSignature:
                    fail("SETTLEMENT", "facilitator signature does not verify")
                else:
                    bad = matches(json.loads(fpayload))
                    if bad:
                        fail("SETTLEMENT", f"facilitator evidence mismatch: {', '.join(bad)}")
                        note("PAYMENT_STATE", "stays CLAIMED")
                    else:
                        conclusion = "SETTLED"
                        ok("SETTLEMENT", f"facilitator-signed evidence for "
                                         f"{json.loads(fpayload).get('tx_hash')}")
        if not args.settlement_evidence and not args.facilitator_evidence:
            note("SETTLEMENT", "NOT_VERIFIED — no evidence supplied; read the chain yourself")

    print()
    if FAILURES:
        print("RESULT: REJECT   failed: " + ", ".join(dict.fromkeys(FAILURES)))
        print("        SIGNATURE_VALID != PURCHASE_VERIFIED.")
        return 1
    print(f"RESULT: SIGNATURE_VALID + PAYLOAD_BOUND; PAYMENT_STATE={conclusion}")
    if conclusion != "SETTLED":
        print("        No settlement has been established by this tool.")
    print("        SIGNATURE_VALID != PURCHASE_VERIFIED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
