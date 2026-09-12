#!/usr/bin/env python3
"""Production-v1 verifier test matrix. Run from this directory:  python3 run_tests.py

Beyond exit codes, one invariant is asserted on the text itself: the phrase PAYLOAD_BOUND
may appear in a run's output only when BOTH binding lines were printed as `ok`. That is
the property CP-01 violated.
"""
import json, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
V = [sys.executable, str(HERE / "verify_ghost_receipt_v1_production.py")]
KEYS = ["--keys", str(HERE / "keys-fixture.json")]
rows, failed = [], 0


def run(name, path, want_exit):
    global failed
    r = subprocess.run(V + [str(path)] + KEYS, capture_output=True, text=True)
    out = r.stdout
    claims_bound = "PAYLOAD_BOUND" in out
    both_ok = "ok    REQUEST_BINDING" in out and "ok    RESPONSE_BINDING" in out
    invariant = (not claims_bound) or both_ok

    # v1 binds no settlement, so no run may ever CONCLUDE one. The word may appear where
    # the tool quotes a statement's own field back (n9 does exactly that before refusing
    # it), so this checks the conclusion lines rather than the whole text.
    concluded_settled = any(
        "SETTLED" in line and not line.lstrip().startswith("--")
        for line in out.splitlines()
        if line.startswith("RESULT:") or line.startswith("ok    "))
    good = r.returncode == want_exit and invariant and not concluded_settled
    if concluded_settled:
        print(f"\n--- {name}: a v1 run concluded SETTLED, which v1 cannot support")
    rows.append((name, r.returncode, want_exit, claims_bound, both_ok,
                 "PASS" if good else "FAIL"))
    del concluded_settled
    if not good:
        failed += 1
        print(f"\n--- {name}: exit {r.returncode} (want {want_exit}); "
              f"claims_bound={claims_bound} both_bindings_ok={both_ok}\n{out[-1500:]}")


run("positive", HERE / "receipt-fixture-production-v1.json", 0)
for path in sorted((HERE / "negatives").glob("*.json")):
    want = json.loads(path.read_text())["expected_result"]["exit"]
    run(path.stem, path, want)

# Static check: no code path may print PAYLOAD_BOUND outside the guarded success branch.
src = (HERE / "verify_ghost_receipt_v1_production.py").read_text()
# Count PRINT sites, not mentions: comments may name the phrase, only one line may emit it.
occurrences = sum(1 for line in src.splitlines()
                  if "PAYLOAD_BOUND" in line and line.lstrip().startswith("print("))
static_ok = occurrences == 1 and "bindings_checked.values()" in src
rows.append(("static: single guarded PAYLOAD_BOUND site", occurrences, 1, "-", "-",
             "PASS" if static_ok else "FAIL"))
if not static_ok:
    failed += 1

w = max(len(r[0]) for r in rows)
print(f"\n{'CASE':<{w}}  exit  want  claims_bound  bindings_ok  result")
for name, got, want, cb, bo, res in rows:
    print(f"{name:<{w}}  {str(got):>4}  {str(want):>4}  {str(cb):>12}  {str(bo):>11}  {res}")
print(f"\n{len(rows)} checks, {failed} failed")
raise SystemExit(1 if failed else 0)
