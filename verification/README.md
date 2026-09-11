# Ghost receipt verification fixture

A public, non-sensitive test vector for the DSSE receipt that Ghost Verified Web Search
returns in the `receipt` field of every paid response. It exists so a buyer can verify the
format independently, before making any paid call.

**Everything here is SYNTHETIC.** No payment occurred. The result URLs are `example.org`,
`example.net` and `example.com` placeholders. The envelope is signed with an ephemeral key
generated for this fixture, **not** Ghost's production receipt key. The production public
key is published alongside it so the same procedure works on a real receipt.

The receipt in `receipt-fixture.json` was produced by the unmodified production code path
(`_receipt_for` in Ghost's service), so the schema, the field set and the canonicalisation
are the real ones, not a hand-written illustration.

## Files

| File | What it is |
|---|---|
| `receipt-fixture.json` | The canonical vector: HTTP request, full response body, DSSE envelope, decoded payload, and the two fingerprint preimages |
| `verify_ghost_receipt.py` | Standalone verifier, ~120 lines, `cryptography` only, no Ghost imports |
| `keys/fixture-synthetic.pub.pem` | Public key for this fixture. Verifies the vector below |
| `keys/ghost-production.pub.pem` | Public key for real Ghost receipts served from production |
| `negatives/*.json` | Five tamper fixtures |

## Keys

| Key | keyid | Use |
|---|---|---|
| Fixture (synthetic, ephemeral) | `ed25519:56475aa75463474c0285df5dbf2bcab7` | This vector only |
| Ghost production receipt key | `ed25519:7099881747dbeb09281700d24375d46b` | Real receipts from `ghost-identity.ghost-agent-os.workers.dev` |

Algorithm: **Ed25519**, raw EdDSA over the DSSE PAE. Signature and payload are
**standard** base64 (not URL-safe), per the DSSE spec.

The keyid is *derived from the key*, never assigned:

```
keyid = "ed25519:" + sha256(raw_32_byte_public_key).hexdigest()[:32]
```

so a keyid cannot later be pointed at different key material. The verifier recomputes it
from the key you supply and refuses if the envelope presents a different one.

**Key discovery today is this file.** Ghost does not yet serve the public key from a
well-known path on the origin. That is a real gap and is listed under Known gaps below.

## Envelope and canonicalisation

Standard DSSE (in-toto/TUF), no Ghost-specific framing.

```
payloadType : application/vnd.ghost.attestation+json
payload     : standard base64 of the exact signed bytes
signatures  : [ { keyid, sig } ]   sig = standard base64
```

Signed bytes are the PAE, exactly as the DSSE spec defines it:

```
DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>
```

lengths in ASCII decimal, single ASCII spaces, payload bytes verbatim.

**The payload is opaque.** The bytes are transported as-is and the signature covers those
exact bytes. Do not re-serialise the decoded JSON and hash that; verify over the
transported bytes and parse only afterwards. Ghost happens to emit
`json.dumps(statement, sort_keys=True)` (UTF-8, `", "` and `": "` separators, the Python
default), but nothing in verification depends on reproducing that.

Two things inside the payload *are* recomputable, and that is the point:

```
fingerprint(x) = "sha256:" + sha256(
    json.dumps(x, sort_keys=True, separators=(",", ":"))
).hexdigest()
```

Note the separators differ from the envelope serialisation: fingerprint preimages are
**compact** JSON with sorted keys, no spaces.

## Decoded payload of the vector

```json
{
  "_type": "ghost-verified-web-search-receipt/v1",
  "attributes": {
    "attempts": [{"elapsed_ms": 812, "outcome": "DELIVERED", "provider": "serpingapi.com"}],
    "provider": "serpingapi.com"
  },
  "oracle_verdict": {"deterministic": true, "oracle": "verified-web-search/v1",
                     "verdict": "DELIVERED"},
  "payment": {"confirmations": 0, "evidence_class": "LIVE_UNPAID",
              "reference": "", "status": "NOT_CONNECTED"},
  "request_fingerprint": "sha256:9e4e20862aa0b8119c71f130b87c0131304b139d1c05b5f3dfe9cb4fef8a28db",
  "response_fingerprint": "sha256:0294a59b1703dc482d7840d8b3c7e618a919464d977a3dba43008ac289468182",
  "served_at": 1789055947.5019064
}
```

Fingerprint preimages, so you can recompute both by hand:

```json
request  : {"query": "x402 selection receipt attribution", "results": 3}
response : {"provider": "serpingapi.com", "result_count": 3,
            "urls": ["https://example.org/a", "https://example.net/b",
                     "https://example.com/c"]}
```

## What the signature binds, exactly

| Field | Bound? | How |
|---|---|---|
| HTTP method | **NO** | not present in the signed statement |
| Canonical resource / path | **NO** | not present in the signed statement |
| Request-body commitment | **YES**, partial | `request_fingerprint` over `{query, results}` only. Other body fields (`country`, `language`) are **not** covered |
| Returned-result commitment | **YES**, partial | `response_fingerprint` over `{provider, result_count, urls}`. Titles, snippets, positions, answer box and knowledge panel are **not** covered |
| Provider / provenance | **YES** | `attributes.provider` and `attributes.attempts`, in the clear inside the signed payload |
| Delivery verdict | **YES** | `oracle_verdict` |
| Amount / currency | **NO** | the `billing` block sits in the response body, outside the envelope |
| Settlement reference | **NO** | the signed `payment` block on this path is `status=NOT_CONNECTED`, `evidence_class=LIVE_UNPAID`, `reference=""`. The receipt makes **no settlement claim at all** |
| Time | statement only | `served_at`, a seller-asserted timestamp. No trusted timestamp, no transparency log |

### Which claim rests on what

- **DSSE_SIGNATURE** establishes only that the holder of the Ghost receipt key made this
  statement. It says nothing about what happened.
- **PAYLOAD_BINDING** establishes that the statement is about *this* query and *this* set
  of returned URLs from *this* provider, because you recompute both fingerprints from your
  own copy of the exchange.
- **INDEPENDENT_SETTLEMENT_EVIDENCE** is not supplied. Ghost's receipt does not carry a
  transaction hash, an amount, or a settled status on the search path. If you need to know
  that money moved, check the USDC transfer on Base yourself. Do not treat the receipt as
  evidence of payment.

`SIGNATURE_VALID != PURCHASE_VERIFIED`, and on the amount and settlement axes Ghost's
current receipt does not close the gap.

## Verify

```bash
pip install cryptography
python3 verify_ghost_receipt.py receipt-fixture.json keys/fixture-synthetic.pub.pem
```

Expected on the positive vector (exit 0):

```
ok    payloadType         application/vnd.ghost.attestation+json
ok    keyid                ed25519:56475aa75463474c0285df5dbf2bcab7
ok    DSSE_SIGNATURE       valid  (establishes WHO signed, nothing else)
ok    REQUEST_BINDING      sha256:9e4e2086...
ok    RESPONSE_BINDING     sha256:0294a59b...
ok    PROVENANCE_BINDING   provider=serpingapi.com (signed)
--    AMOUNT_BINDING       NOT_BOUND
--    SETTLEMENT_BINDING   NOT_BOUND
```

## Tamper fixtures

Run the verifier against each. Exit status in brackets.

| Fixture | Signature | Binding | Outcome |
|---|---|---|---|
| `n1-altered-request-body` | VALID | REQUEST_BINDING **FAIL** | REJECT [1]. Authentic signature, different question |
| `n2-altered-returned-url` | VALID | RESPONSE_BINDING **FAIL** | REJECT [1]. Authentic signature, different result set |
| `n3-altered-amount` | VALID | all bindings pass | **NOT DETECTED** [0]. See below |
| `n4-altered-issuer-keyid` | **FAIL** | not reached | REJECT [2]. Unknown issuer |
| `n5-altered-signed-payload` | **FAIL** | not reached | REJECT [2]. Payload edited after signing |

`n1` and `n2` are the interesting pair: the signature stays valid and the receipt is still
rejected, because authenticity and aboutness are different questions.

**`n3` is a known gap, stated rather than hidden.** The billing block was changed from
`0.01 USDC` to `1.00 USDC` and nothing in the receipt notices, because amount is not in the
signed payload. The verifier prints `AMOUNT_BINDING NOT_BOUND` and the result line says
`AMOUNT_UNVERIFIED; SETTLEMENT_UNVERIFIED`. It must never be read as a pass. Two receipts
differing only in the billing block are indistinguishable.

## Known gaps

These are reported, not silently patched. Nothing in Ghost's production receipt changed to
produce this fixture.

1. `MISSING_BINDING = amount/currency` — not in the signed payload.
2. `MISSING_BINDING = settlement_reference` — the settlement reference exists at signing
   time on the paid path and is not passed into the statement; the signed `payment` block
   is left at `NOT_CONNECTED` / `LIVE_UNPAID`, a holdover from the older relay flow where
   the buyer paid the upstream directly. On today's merchant path that block understates
   what happened, and it is misleading in the other direction from the usual failure, so
   it is being corrected rather than relied on.
3. `MISSING_BINDING = http_method` and `MISSING_BINDING = canonical_resource_url`.
4. `MISSING_BINDING = full_response_body` — snippets and titles are outside the commitment.
5. No key-discovery endpoint on the origin. This file is the only key distribution.
   **(Closed 2026-09-11: the origin now serves `/.well-known/ghost-receipt-keys.json`. See Current production status below.)**
6. `served_at` is not `signed_at`, which is the field name Ghost's own DSSE verifier
   expects for its freshness check. A generic verifier must either skip the freshness check
   or read `served_at`.

Feedback on which of these matter for a cross-seller fixture is welcome on the issue that
prompted this vector.

---

## Current production status (2026-09-12)

This section is the live truth. Everything above it is the historical record of what was
verified at the time and is left unedited on purpose.

| | |
|---|---|
| Production receipt format | **v1** (`ghost-verified-web-search-receipt/v1`) |
| v2.1 | **synthetic review fixture. NOT the production receipt** |
| Supported production verifier | [`verification/production-v1/`](production-v1/PRODUCTION-V1-VERIFICATION.md) |
| Origin key discovery | **LIVE** at `/.well-known/ghost-receipt-keys.json` |
| Failure contract | **LIVE** at `/.well-known/ghost-502-contract.json` |
| Payment flow | **upfront**, advertised in the 402 as `extra.paymentFlow` |
| Signed timestamp | v1 signs `served_at`; v2.1 signs `signed_at`; selected by `_type`, no fallback |
| Revocation | **HARD**: a revoked key's receipts are refused whatever timestamp they carry |
| The six production gaps reported by x402-lab | **closed** |

The verifier in this directory is **unsupported**. Use the production-v1 one above.
