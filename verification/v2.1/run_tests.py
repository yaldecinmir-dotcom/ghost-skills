#!/usr/bin/env python3
"""Full v2.1 test matrix. Run from this directory:  python3 run_tests.py"""
import json, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
KEYS = str(HERE / "keys" / "keys.json")
V = [sys.executable, str(HERE / "verify_ghost_receipt_v21.py")]
rows, failed = [], 0


def check(mode, name, args, want_exit, want_text=""):
    global failed
    r = subprocess.run(V + args, capture_output=True, text=True)
    good = r.returncode == want_exit and (not want_text or want_text in r.stdout)
    rows.append((mode, name, r.returncode, want_exit, "PASS" if good else "FAIL"))
    if not good:
        failed += 1
        print(f"\n--- {name} expected exit {want_exit}"
              f"{' and ' + repr(want_text) if want_text else ''}, got {r.returncode}")
        print((r.stdout + r.stderr)[-1200:])


def f(p):
    return str(HERE / p)


# positive
check("positive", "unpaid", [f("receipt-fixture-v21-unpaid.json"), KEYS], 0,
      "PAYMENT_STATE=UNPAID")
check("positive", "claimed, no evidence", [f("receipt-fixture-v21-claimed.json"), KEYS], 0,
      "PAYMENT_STATE=CLAIMED")
check("positive", "delivered content bound", [f("receipt-fixture-v21-claimed.json"), KEYS],
      0, "DELIVERED_CONTENT")
check("positive", "seller labelled as assertion",
      [f("receipt-fixture-v21-claimed.json"), KEYS], 0, "SELLER_ASSERTION_BOUND")

# settlement semantics
check("settlement", "unsigned evidence never settles",
      [f("receipt-fixture-v21-claimed.json"), KEYS, "--settlement-evidence",
       f("settlement-evidence-unsigned.json")], 0, "PAYMENT_STATE=CLAIMED")
check("settlement", "unsigned evidence reports MATCHED only",
      [f("receipt-fixture-v21-claimed.json"), KEYS, "--settlement-evidence",
       f("settlement-evidence-unsigned.json")], 0, "SETTLEMENT_EVIDENCE_MATCHED")
check("settlement", "wrong unsigned evidence rejected",
      [f("receipt-fixture-v21-claimed.json"), KEYS, "--settlement-evidence",
       f("settlement-evidence-unsigned-wrong.json")], 1)
check("settlement", "facilitator-signed evidence settles",
      [f("receipt-fixture-v21-claimed.json"), KEYS, "--facilitator-evidence",
       f("settlement-evidence-facilitator-signed.json")], 0, "PAYMENT_STATE=SETTLED")
check("settlement", "facilitator evidence, wrong amount",
      [f("receipt-fixture-v21-claimed.json"), KEYS, "--facilitator-evidence",
       f("settlement-evidence-facilitator-signed-wrong-amount.json")], 1)
check("settlement", "receipt key cannot sign settlement evidence",
      [f("receipt-fixture-v21-claimed.json"), KEYS, "--facilitator-evidence",
       f("settlement-evidence-signed-by-receipt-key.json")], 1)

# key scope, rotation, revocation
check("keys", "fixture key refused under production profile",
      [f("negatives/n11-fixture-key-signs-production-receipt.json"), KEYS], 2, "KEY_SCOPE")
check("keys", "fixture key accepted under fixture profile",
      [f("negatives/n11-fixture-key-signs-production-receipt.json"), KEYS,
       "--profile", "fixture"], 0)
check("keys", "retired key inside its window still verifies",
      [f("negatives/n14-retired-key-inside-window-ACCEPTED.json"), KEYS], 0)

# every adversarial negative, expectation read from the fixture itself
for path in sorted((HERE / "negatives").glob("*.json")):
    spec = json.loads(path.read_text())
    want = spec["expected_result"]["exit"]
    if path.name.startswith(("n11", "n14")):
        continue  # covered above with explicit profiles
    check("negative", path.stem, [str(path), KEYS], want)

# cross-language canonicalisation
from ghost_receipt_v21 import jcs  # noqa: E402
vectors = json.loads((HERE / "canonicalization-vectors.json").read_text())
for v in vectors["vectors"]:
    got = jcs(v["value"])
    good = got == v["jcs"]
    rows.append(("canonical", v["name"], "-", "-", "PASS" if good else "FAIL"))
    if not good:
        failed += 1
        print(f"\n--- JCS vector {v['name']}: expected {v['jcs']!r}, got {got!r}")

width = max(len(r[1]) for r in rows)
print(f"\n{'MODE':<11} {'CASE':<{width}}  exit  want  result")
for mode, name, got, want, res in rows:
    print(f"{mode:<11} {name:<{width}}  {str(got):>4}  {str(want):>4}  {res}")
print(f"\n{len(rows)} checks, {failed} failed")
raise SystemExit(1 if failed else 0)
