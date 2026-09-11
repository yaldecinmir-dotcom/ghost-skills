# Ghost receipt fixture, version 2

v2 exists because v1's verifier had a divergence bug, reported by Merit Systems on
2026-09-11 and reproduced here before anything was changed.

**The bug.** `verify_ghost_receipt.py` in v1 recomputed its fingerprints from a
`recomputation_inputs` block that travelled inside the bundle, rather than from the HTTP
exchange. Editing `http_request.body.query` or a returned result URL while leaving those
preimages intact still exited 0. v1's own n1 and n2 updated both representations together,
so they missed it.

**v1 is left exactly as published** at commit `87778ea`, in `../` alongside this
directory, as the historical record of what was verified. It is not edited, and its
verifier should not be used.

Everything here is **SYNTHETIC**: ephemeral fixture key, placeholder result URLs, no
payment. Ghost production still emits v1. Adopting v2 in production is a separate,
reviewable change that has not been made.

## What v2 binds

| Field | v1 | v2 |
|---|---|---|
| HTTP method | no | **yes**, in the clear and inside the request commitment |
| Canonical resource URL | no | **yes**, same |
| Request body subset | partial, implicit | **yes**, explicit `subset_fields` + `subset_defaults` |
| Response subset | partial, implicit | **yes**, explicit `subset_fields`, every value derived from the body |
| Provider / provenance | yes | yes |
| Seller identity | no | **yes**, domain, `pay_to` and `keyid` |
| Amount and currency | no, outside the envelope | **yes**, as `claimed_amount`, a seller assertion |
| Settlement | no | reference only, never a settled claim |
| Receipt and operation identity | no | **yes**, `receipt_id` and `operation_id` |
| `signed_at` | absent | **yes**, checked against the key validity window |

`receipt_id` and `operation_id` are identifiers. They make two otherwise identical
searches distinguishable, which v1 could not do. **They are not payment evidence and must
never be presented as such.**

## Payment states

The seller may sign exactly two states.

- **UNPAID** — the statement asserts no payment. Anything paid-looking elsewhere in the
  response body is not evidence and the verifier says so.
- **CLAIMED** — the seller asserts an amount, a rail and possibly a settlement reference.
  This is an assertion, not proof. A verifier must not treat it as settled.

**SETTLED is never a signed value.** A seller cannot sign that money moved. SETTLED is a
conclusion the verifier reaches only after independently matching settlement evidence it
obtained itself against the signed claim: transaction hash, recipient, asset, network and
minor amount must all agree. A statement carrying `state: SETTLED` is rejected as
malformed even when its signature is genuine. `negatives/n5b-validly-signed-SETTLED.json`
demonstrates precisely that.

## Verify

```bash
pip install cryptography
python3 verify_ghost_receipt_v2.py receipt-fixture-v2-unpaid.json keys/keys.json
python3 verify_ghost_receipt_v2.py receipt-fixture-v2-claimed.json keys/keys.json
python3 verify_ghost_receipt_v2.py receipt-fixture-v2-claimed.json keys/keys.json \
    --settlement-evidence settlement-evidence-matching.json
```

Every commitment is recomputed from `http_request` and `http_response_body` using the
field list the signed statement declares. No preimage is read from the bundle.

| Case | Signature | Outcome | Exit |
|---|---|---|---|
| `receipt-fixture-v2-unpaid.json` | valid | PAYMENT_STATE=UNPAID | 0 |
| `receipt-fixture-v2-claimed.json` | valid | PAYMENT_STATE=CLAIMED, settlement NOT_VERIFIED | 0 |
| same, with matching evidence | valid | PAYMENT_STATE=SETTLED | 0 |
| same, with `settlement-evidence-wrong.json` | valid | REJECT, stays CLAIMED | 1 |
| `n1-observed-query-only` | valid | REQUEST_BINDING FAIL | 1 |
| `n2-observed-result-url-only` | valid | RESPONSE_BINDING FAIL | 1 |
| `n3-amount-in-signed-payload` | **fail** | amount is inside the envelope now | 2 |
| `n3b-unsigned-billing-mismatch` | valid | BILLING_CROSSCHECK FAIL | 1 |
| `n4-seller-identity` | **fail** | payload edited | 2 |
| `n4b-seller-keyid-mismatch` | **fail** | payload edited | 2 |
| `n5-seller-signed-SETTLED` | **fail** | payload edited | 2 |
| `n5b-validly-signed-SETTLED` | **valid** | refused on the rule | 2 |
| `n6-unpaid-dressed-as-paid` | valid | stays UNPAID, crosscheck FAIL | 1 |

`n1` and `n2` are the two cases v1 passed and v2 must not. They are the reason this
directory exists.

## Key discovery and rotation

`keys/keys.json` is the discovery document. Each entry carries the keyid, PEM, status and
a validity window, and the verifier refuses any entry whose material does not derive the
keyid it claims.

Rotation publishes the replacement with a future `not_before` while the predecessor keeps
a `not_after` at or after that moment, so the windows overlap and no honest receipt is
rejected mid-changeover. **A retired key is never removed from the document**: receipts
signed while it was valid must stay verifiable forever, which is why the verifier checks
`signed_at` against the key window rather than against the current time. A compromised key
is marked revoked instead, and receipts signed after that moment are rejected.

The intended home is `/.well-known/ghost-receipt-keys.json` on the origin. **The origin
does not serve it yet.** That is a production change and has not been made, so this file
is the interim discovery point.

## Open gaps, carried forward not hidden

From x402-lab's unpaid observation of 2026-09-10, still open and all requiring production
changes that have not been made:

1. The OpenAPI exact payment block omits scheme, timeout and token-domain fields.
2. The advertised facilitator appears in no captured metadata document.
3. `price.task_class` reads `schema_freshness` on the web-search product. Wrong label.
4. No published 502 schema for the post-payment failure path.
5. **Failure credit is not redeemable by a first-time payer.** On the 502 path Ghost posts
   the balance against the payer address, but a balance is only spendable by presenting a
   token in `X-Ghost-Credit-Token`, and that token is minted only at the explicit top-up
   endpoint, never on the failure path. So the buyer the credit belongs to has no way to
   present it. This is a real defect in the failure-credit promise, not a documentation
   gap, and it is stated here rather than left to be discovered.
6. No key-discovery endpoint on the origin, as above.

v1 additionally noted that `served_at` was not `signed_at`. v2 carries both.
