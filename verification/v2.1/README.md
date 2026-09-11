# Ghost receipt fixture, version 2.1 — adversarial hardening

v2.1 exists because the v2 fixture was attacked and lost, eleven times. Every change here
is preceded by a reproduction against the untouched v2 verifier, recorded in
[`repro/FINDINGS.md`](repro/FINDINGS.md) and re-runnable:

```bash
python3 repro/reproduce_v2_findings.py     # 11 findings, 11 reproduced
```

**v1 and v2 are unchanged.** They stay exactly as published, at `../` and `../v2`, as the
record of what was verified at the time. Their verifiers should not be used.

Everything here is **SYNTHETIC**: synthetic keys, placeholder result URLs, no payment.
**Ghost production is unchanged and still emits v1.** Adopting v2.1 in production is a
separate, reviewable change that has not been made.

```bash
pip install cryptography
python3 run_tests.py        # 41 checks, 0 failed
node verify_vectors.js      # 6 canonicalisation vectors, 0 failed
```

## What v2 got wrong

| | v2 | v2.1 |
|---|---|---|
| Fixture key signing a production receipt | accepted | key scopes plus an enforced `--profile` |
| Revoked key | no concept | refused when `signed_at >= revoked_at`, or when no `revoked_at` is given (see note) |
| Retired key | no concept | accepted only for `signed_at` inside its window |
| Hand-written settlement file | produced **SETTLED** | produces `SETTLEMENT_EVIDENCE_MATCHED`; state stays CLAIMED |
| Signer choosing what is bound | allowed | fixed profile, exact field lists |
| Titles, snippets, answer, knowledge | unbound | `content_digest` over every delivered field |
| Signed clear fields vs their own fingerprint | unchecked | cross-checked |
| `seller.pay_to`, domain, required fields | unchecked | cross-checked and required |
| Missing `http_response_status` | assumed 200 | refused |
| `not_after: 0` | treated as no expiry | `null` and `0` distinguished |
| Extra signatures | ignored | exactly one permitted |
| Non-ASCII query | different digest in JS | RFC 8785 JCS, verified across two languages |
| HTTP method | upper-cased, masking a difference | compared exactly, RFC 9110 |
| `canonical_url` | nothing was canonicalised | renamed `exact_resource_url` |

## Payment states

A seller may sign **UNPAID** or **CLAIMED**, nothing else.

**SETTLED is never a signed value and never follows from a file you wrote yourself.**
Supplying `--settlement-evidence` with an unsigned file reports
`SETTLEMENT_EVIDENCE_MATCHED`, which means only that your own notes agree with the seller's
claim, and the state stays CLAIMED. `PAYMENT_STATE=SETTLED` requires
`--facilitator-evidence`: a DSSE envelope signed by a key the discovery document lists with
`use: facilitator`. A receipt-scope key signing settlement evidence is refused, and so is a
facilitator key signing a receipt. Reading the chain yourself is the other acceptable route
and always available.

A statement carrying `state: SETTLED` is refused as malformed **even when its signature is
genuine**.

## Seller

`SELLER_ASSERTION_BOUND`, never "identity verified". The verifier checks that `domain`,
`pay_to` and `keyid` are present, that `keyid` is the key that signed, that `domain` is the
host of the signed resource URL, and that `pay_to` matches `payment.pay_to`. All of that
binds the assertion to the signature. **None of it proves the signer owns the domain or the
address.** Domain ownership needs a separate proof Ghost does not yet publish.

## Keys

`keys/keys.json` carries `use` (`receipt`, `fixture`, `facilitator`), `status` (`active`,
`retired`, `revoked`), a validity window and, for revoked keys, `revoked_at`. The verifier
refuses any entry whose material does not derive the keyid it claims, and `--profile
production` admits only `use: receipt`.

Rotation overlaps windows: the replacement gets a future `not_before` while the predecessor
keeps a `not_after` at or after that moment. **A retired key is never removed**, because
`signed_at` is checked against the key window rather than the clock, so historical receipts
stay verifiable forever. `n14` is the positive control for exactly that.

The intended home is `/.well-known/ghost-receipt-keys.json` on the origin. **It is served
as of 2026-09-11**, and it carries the production key plus the version-aware timestamp
policy and the hard-revocation rule. See Current production status below.

## Canonicalisation

RFC 8785 JCS over UTF-8. `canonicalization-vectors.json` carries six vectors with their
expected serialisation and digest; `verify_vectors.js` checks them under Node.

The migration matters commercially rather than pedantically: under v2, a query containing
non-ASCII text digested differently in JavaScript than in Python, so a Turkish, French or
Japanese query would have read as a tampered response to a JS verifier. The v2.1 fixture
deliberately uses a non-ASCII query so any implementation that skips JCS fails immediately
rather than silently much later.

Migration plan for production, unimplemented: emit v1 unchanged, add v2.1 alongside under a
distinct `_type`, and let buyers verify either. The `_type` string is what selects the
canonicalisation, so no receipt is ever ambiguous about which rule applies.

## Test matrix

41 checks across positive, settlement semantics, key scope and rotation, 24 adversarial
negatives, and cross-language canonicalisation. `n14` is a positive control, not a failure
case. See `run_tests.py`.

## Not implemented, by design

[`PAYMENT_BINDING_DESIGN.md`](PAYMENT_BINDING_DESIGN.md) describes how a receipt would bind
to one specific payment through the payment-requirement digest, the payment-payload digest,
the EIP-3009 payer and nonce, and the settlement transaction. **None of it is built.**
`receipt_id` and `operation_id` distinguish two otherwise identical searches and are not
payment evidence.

## A note on revocation, added 2026-09-12

This fixture's verifier refuses a revoked key when the statement's `signed_at` is at or
after `revoked_at`, and accepts it before that moment. The table above previously summed
that up as "refused", which was imprecise.

**Production does not follow that rule.** The live key policy is HARD revocation: every
receipt signed by a revoked key is refused whatever timestamp it carries. The reasoning is
that the only timestamp available is the seller-asserted one inside the statement, so a
holder of a compromised key can sign a statement dated before the revocation. Accepting
pre-revocation receipts would accept exactly the forgeries revocation exists to stop.

The fixture is left unchanged as published evidence; the production rule is the one that
governs live receipts, and it is stated in the live key document.

## Still open

Unchanged from v2, all requiring production changes that have not been made: the OpenAPI
exact payment block omits scheme, timeout and token-domain; the advertised facilitator
appears in no metadata document; `price.task_class` reads `schema_freshness` on the
web-search product; there is no published 502 schema; failure credit is not redeemable by a
first-time payer, because the balance is posted against the payer address while spending
requires a token that is only minted at the explicit top-up endpoint; and there is no
key-discovery endpoint on the origin.

---

## Current production status (2026-09-12)

This section is the live truth. Everything above it is the historical record of what was
verified at the time and is left unedited on purpose.

| | |
|---|---|
| Production receipt format | **v1** (`ghost-verified-web-search-receipt/v1`) |
| v2.1 | **synthetic review fixture. NOT the production receipt** |
| Supported production verifier | [`verification/production-v1/`](../production-v1/PRODUCTION-V1-VERIFICATION.md) |
| Origin key discovery | **LIVE** at `/.well-known/ghost-receipt-keys.json` |
| Failure contract | **LIVE** at `/.well-known/ghost-502-contract.json` |
| Payment flow | **upfront**, advertised in the 402 as `extra.paymentFlow` |
| Signed timestamp | v1 signs `served_at`; v2.1 signs `signed_at`; selected by `_type`, no fallback |
| Revocation | **HARD**: a revoked key's receipts are refused whatever timestamp they carry |
| The six production gaps reported by x402-lab | **closed** |

The verifier in this directory is **unsupported**. Use the production-v1 one above.
