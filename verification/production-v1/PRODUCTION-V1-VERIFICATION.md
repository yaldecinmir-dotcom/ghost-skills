# Verifying a receipt Ghost production actually emits

**Production emits v1.** This is the supported path for verifying it. The v2.1 fixture is
a synthetic review artefact and is not what the origin serves.

```bash
pip install cryptography
python3 verify_ghost_receipt_v1_production.py receipt-fixture-production-v1.json \
    --keys keys-fixture.json          # offline, against the bundled fixture key

python3 verify_ghost_receipt_v1_production.py your-receipt.json
    # omit --keys to fetch the origin's live key document
```

Key discovery, live:
https://ghost-identity.ghost-agent-os.workers.dev/.well-known/ghost-receipt-keys.json

## Which verifier to use

| Verifier | Use on | Status |
|---|---|---|
| `verification/production-v1/verify_ghost_receipt_v1_production.py` | receipts from the live origin | **supported** |
| `verification/verify_ghost_receipt.py` | nothing | **unsupported.** It recomputes bindings from a `recomputation_inputs` block carried inside the bundle instead of from the observed HTTP exchange, so a tamper that edits only the observed request or response passes. Kept as historical evidence. |
| `verification/v2.1/verify_ghost_receipt_v21.py` | the v2.1 synthetic fixtures only | not applicable to production. It requires `signed_at` and the v2.1 statement type; a production v1 receipt carries neither. |

## The timestamp, stated exactly

A production v1 statement signs **`served_at`** and does **not** contain `signed_at`. An
earlier revision of the published key policy described `signed_at`, which is v2.1's field,
and applying it to a v1 receipt would have rejected every honest receipt the origin emits.

The rule is now version-specific and lives in the live key document under
`timestamp_policy`:

| Statement type | Signed timestamp field |
|---|---|
| `ghost-verified-web-search-receipt/v1` | `served_at` |
| `ghost-verified-search-receipt/v1` | `served_at` |
| `ghost-service-receipt/v2` | `served_at` |
| `ghost-verified-web-search-receipt/v2.1` | `signed_at` |

The field is selected by `_type`. A statement whose required field is absent is
**rejected**, and there is deliberately **no fallback** between the two fields: trying
`signed_at` and then `served_at` would let a statement with no trustworthy time pass as
one that has it. `n5` is a validly signed receipt with the field removed, and it is
refused; `n6` is a v2.1 statement handed to this verifier, and it is refused rather than
guessed at.

**What the timestamp is worth.** It is a **seller-asserted claim inside a statement the
seller signed**. It is not a trusted timestamp, there is no transparency log, and no third
party attests to when signing happened. It is good enough to place a receipt inside a key
validity window under normal operation, and it is not good enough to survive a compromised
key, which is why revocation is hard (below).

## Key validity and revocation

The window is checked against the statement's signed timestamp, not against the clock, so
a receipt signed while a key was valid stays verifiable after that key retires. Retired
keys are never removed from the key document.

**Revocation is HARD.** Every receipt signed by a revoked key is refused, whatever
timestamp it carries. Historical validity is not offered for revoked keys, and the reason
is the paragraph above: the only timestamp available is the one inside the statement, so
whoever holds a compromised key can sign a statement dated before the revocation.
Accepting pre-revocation receipts would accept exactly the forgeries revocation exists to
stop. Retirement is not a compromise and does keep historical validity; revocation does
not. `null` and `0` are different values for `not_after`: null is open-ended, 0 expired at
the epoch.

## What a v1 receipt binds, and what it does not

| | v1 |
|---|---|
| Request body commitment | `{query, results}` only, with `results` defaulting to 10 when the buyer omitted it |
| Response commitment | `{provider, result_count, urls}` |
| Provider / provenance | signed, in the clear |
| HTTP method, resource URL | **not bound** |
| Titles, snippets, positions, answer box, knowledge panel | **not bound** |
| Amount, currency | **not signed at all** |
| Settlement reference | **not signed**; the signed `payment` block on the search path reads `NOT_CONNECTED` / `LIVE_UNPAID` with an empty reference |

Because v1 signs no amount and no settlement reference, this verifier **reports no payment
conclusion at all**. It prints `PAYMENT_STATE NOT ESTABLISHED` and `SETTLEMENT NOT
ESTABLISHED` rather than a state that could be misread as proof. The `billing` block in
the response body sits outside the signature.

Ghost settles **upfront**, meaning the authorization settles before the search runs, so a
settlement may well exist for a receipt this tool cannot evidence. Read the USDC transfer
on Base yourself.

## Canonicalisation

v1 hashes with sorted-key, compact-separator JSON, which is **not** RFC 8785. A query with
non-ASCII text is escaped here and is not escaped under JCS, so a JCS implementation
computes a different digest for the same query. The JCS migration exists in the v2.1
fixture and **is not deployed**. This verifier matches what production emits today.

## Fixtures

`receipt-fixture-production-v1.json` was produced by the unmodified production receipt
function with a synthetic key, so the schema and canonicalisation are production's while
no real payment or key is involved.

| Fixture | Signature | Outcome | Exit |
|---|---|---|---|
| positive | valid | SIGNATURE_VALID + PAYLOAD_BOUND (v1 scope) | 0 |
| `n1-observed-query-only` | valid | REQUEST_BINDING fail | 1 |
| `n2-observed-result-url-only` | valid | RESPONSE_BINDING fail | 1 |
| `n3-provider-swapped-in-body` | valid | RESPONSE and PROVENANCE fail | 1 |
| `n4-edited-signed-payload` | **fail** | payload edited after signing | 2 |
| `n5-no-signed-timestamp` | valid | refused: v1 must sign `served_at` | 2 |
| `n6-v21-statement-in-production-verifier` | valid | refused: wrong statement type | 2 |

`n1` and `n2` are the cases the unsupported v1 fixture verifier passes.
