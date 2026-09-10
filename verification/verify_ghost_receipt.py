#!/usr/bin/env python3
"""Independently verify a Ghost Verified Web Search receipt. No Ghost code required.

    pip install cryptography
    python3 verify_ghost_receipt.py receipt-fixture.json keys/fixture-synthetic.pub.pem

Exit status is 0 only when the signature verifies AND every binding the receipt actually
carries matches the request/response held alongside it.

The distinction this tool exists to keep visible:

  DSSE_SIGNATURE  - who made the statement. Nothing more.
  PAYLOAD_BINDING - which exchange the statement is about, recomputed from your own copy
                    of the request and the response.
  SETTLEMENT      - whether money moved. Ghost's receipt does NOT establish this. See the
                    NOT_BOUND lines below and check the chain yourself.
"""
import base64, hashlib, json, sys
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.ghost.attestation+json"


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding: DSSEv1 <len(type)> <type> <len(payload)> <payload>"""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def key_id(public_key: Ed25519PublicKey) -> str:
    """Ghost derives the keyid from the key, so a name cannot be repointed at other material."""
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + sha256(raw).hexdigest()[:32]


def fingerprint(payload) -> str:
    """Ghost's canonicalisation for a fingerprint preimage: JSON, sorted keys, no spaces."""
    material = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(material.encode()).hexdigest()


def main(bundle_path: str, pubkey_path: str) -> int:
    bundle = json.loads(open(bundle_path).read())
    public_key = serialization.load_pem_public_key(open(pubkey_path, "rb").read())
    if not isinstance(public_key, Ed25519PublicKey):
        print("FAIL  the supplied key is not Ed25519"); return 2

    response = bundle["http_response_body"]
    receipt = response["receipt"]
    ok = True

    if not receipt.get("signed"):
        print("FAIL  receipt.signed is false; no signing key was configured"); return 2
    envelope = receipt["envelope"]

    # 1. payload type, checked before anything is parsed
    if envelope["payloadType"] != PAYLOAD_TYPE:
        print(f"FAIL  payloadType is {envelope['payloadType']!r}, expected {PAYLOAD_TYPE!r}")
        return 2
    print(f"ok    payloadType         {envelope['payloadType']}")

    # 2. issuer: the presented keyid must be the one derived from the key you trust
    derived = key_id(public_key)
    presented = envelope["signatures"][0].get("keyid", "")
    if presented != derived:
        print(f"FAIL  DSSE_SIGNATURE      unknown issuer: envelope says {presented}, "
              f"the supplied key is {derived}")
        return 2
    print(f"ok    keyid                {derived}")

    # 3. signature over the PAE of the exact transported bytes
    payload_bytes = base64.standard_b64decode(envelope["payload"])
    try:
        public_key.verify(base64.standard_b64decode(envelope["signatures"][0]["sig"]),
                          pae(envelope["payloadType"], payload_bytes))
    except InvalidSignature:
        print("FAIL  DSSE_SIGNATURE      signature does not verify over these payload bytes")
        return 2
    print("ok    DSSE_SIGNATURE       valid  (establishes WHO signed, nothing else)")

    statement = json.loads(payload_bytes)  # parsed only after the signature verified

    # 4. payload bindings, recomputed from your own copy of the exchange
    req_pre = bundle["recomputation_inputs"]["request_fingerprint_preimage"]
    res_pre = bundle["recomputation_inputs"]["response_fingerprint_preimage"]

    got, want = fingerprint(req_pre), statement.get("request_fingerprint")
    if got == want:
        print(f"ok    REQUEST_BINDING      {want}")
    else:
        ok = False
        print(f"FAIL  REQUEST_BINDING      receipt says {want}\n"
              f"                           your request hashes to {got}")

    got, want = fingerprint(res_pre), statement.get("response_fingerprint")
    if got == want:
        print(f"ok    RESPONSE_BINDING     {want}")
    else:
        ok = False
        print(f"FAIL  RESPONSE_BINDING     receipt says {want}\n"
              f"                           your response hashes to {got}")

    # 5. provenance is carried in the clear inside the signed payload
    attrs = statement.get("attributes") or {}
    if attrs.get("provider") and attrs.get("provider") == response.get("provider"):
        print(f"ok    PROVENANCE_BINDING   provider={attrs['provider']} (signed)")
    elif attrs.get("provider"):
        ok = False
        print(f"FAIL  PROVENANCE_BINDING   receipt signed provider={attrs['provider']}, "
              f"response body claims {response.get('provider')}")

    # 6. what this receipt does NOT establish. Never printed as a pass.
    billing = (response.get("billing") or {}).get("fee") or {}
    print(f"--    AMOUNT_BINDING       NOT_BOUND  (response asserts "
          f"{billing.get('amount')} {billing.get('currency')} OUTSIDE the signature)")
    payment = statement.get("payment") or {}
    print(f"--    SETTLEMENT_BINDING   NOT_BOUND  (signed payment block is "
          f"status={payment.get('status')} evidence_class={payment.get('evidence_class')} "
          f"reference={payment.get('reference')!r})")
    print("--    INDEPENDENT_SETTLEMENT_EVIDENCE  not supplied by this receipt; confirm the "
          "USDC transfer on Base yourself")

    print()
    if ok:
        print("RESULT: SIGNATURE_VALID + PAYLOAD_BOUND; AMOUNT_UNVERIFIED; "
              "SETTLEMENT_UNVERIFIED")
        print("        This establishes that Ghost signed a statement about THIS request")
        print("        and THIS result set. It does NOT establish that the stated amount")
        print("        was charged or that any payment settled. Two receipts differing")
        print("        only in the billing block are indistinguishable to this tool.")
    else:
        print("RESULT: REJECT")
    print("        SIGNATURE_VALID != PURCHASE_VERIFIED.")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__); raise SystemExit(2)
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
