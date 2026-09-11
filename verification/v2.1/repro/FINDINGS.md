# Reproduction log: what v2 actually failed

Every change in v2.1 is here because the attack below succeeded against the **v2** fixture
and verifier first. Nothing was changed on the strength of a description alone. Run
`python3 repro/reproduce_v2_findings.py` from the `v2.1` directory to reproduce.

| # | Attack on v2 | v2 result | Closed in v2.1 by |
|---|---|---|---|
| P0-1 | Fixture key signs a receipt claiming the production seller | **exit 0**, accepted | key `use` scopes plus a `--profile` the verifier enforces |
| P0-2 | Hand-written settlement-evidence file, no chain consulted | **exit 0, PAYMENT_STATE=SETTLED** | unsigned evidence yields `SETTLEMENT_EVIDENCE_MATCHED` and the state stays CLAIMED; SETTLED needs facilitator-signed evidence |
| P0-3 | Signer drops `query` from `subset_fields`, then swaps the query freely | **exit 0 twice** | fixed required profile; declared field lists must equal the profile exactly |
| P0-4 | Rewrite title, snippet, answer box and knowledge panel | **exit 0**, unnoticed | `content_digest` over every delivered field |
| P1-5a | Signed clear `method: GET` while the fingerprint covers POST | **exit 0** | signed-self-consistency check |
| P1-5b | Signed `response.subset.provider` disagrees with its own fingerprint | **exit 0** | same |
| P1-6a | `seller.pay_to` differs from `payment.pay_to` | **exit 0** | seller crosscheck |
| P1-6b | `seller` block emptied entirely | **exit 0** | required seller fields |
| P2-10 | `http_response_status` absent | **exit 0**, silently assumed 200 | absent status is refused |
| P2-11 | Key with `not_after: 0` | **exit 0**, `0 or inf` made it open-ended | null and 0 are distinguished |
| P2-12 | A second, unknown signature appended | **exit 0**, only `signatures[0]` read | exactly one signature permitted |

## Canonicalisation divergence, measured across two languages

v2 canonicalised with `json.dumps(sort_keys=True, separators=(",", ":"))`. Compared with
RFC 8785 JCS as implemented in JavaScript:

| Vector | v2 (Python) | JCS (JavaScript) | Same digest? |
|---|---|---|---|
| `{"query": "café İstanbul 🔍"}` | `"café İstanbul 🔍"` | `"café İstanbul 🔍"` | **no** |
| `{"results": 3.0}` | `3.0` | `3` | **no** |
| `{"￿":1, "\U00010000":2}` | code-point order | UTF-16 code-unit order | **no** |
| `{"n": 1e21}` | `1e+21` | `1e+21` | yes |
| `{"q": "a\tb"}` | `"a\tb"` | `"a\tb"` | yes |

The first row is the one that matters commercially: **any search query containing
non-ASCII text produced a different digest in a JavaScript verifier than in Ghost's.** For
a web-search product sold to agents worldwide that is not an edge case, and it would have
read as a tampered response rather than as an encoding disagreement.

v2.1 uses JCS. `canonicalization-vectors.json` carries six vectors with their expected
serialisation and digest; `verify_vectors.js` checks them under Node and passes 6/6.
