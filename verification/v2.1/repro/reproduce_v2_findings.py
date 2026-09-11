#!/usr/bin/env python3
"""Reproduce, against the untouched v2 fixture, every weakness that v2.1 closes.

    pip install cryptography
    python3 repro/reproduce_v2_findings.py        # run from the v2.1 directory

Reads ../v2 and writes nothing there. Exit 0 when every finding still reproduces, which is
the point: these are the receipts for the changes, not a regression suite.
"""
import base64, copy, json, pathlib, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent.parent
V2 = HERE.parent / "v2"
sys.path.insert(0, str(V2))
from receipt_v2 import fingerprint  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa
from cryptography.hazmat.primitives import serialization  # noqa: E402
from hashlib import sha256  # noqa: E402

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEYID = "ed25519:" + sha256(KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()[:32]
TMP = pathlib.Path(tempfile.mkdtemp())
BASE = json.loads((V2 / "receipt-fixture-v2-claimed.json").read_text())
results = []


def sign(statement):
    payload = json.dumps(statement, sort_keys=True).encode()
    pae = b"DSSEv1 %d %s %d %s" % (len("application/vnd.ghost.attestation+json"),
                                   b"application/vnd.ghost.attestation+json",
                                   len(payload), payload)
    return {"payload": base64.standard_b64encode(payload).decode(),
            "payloadType": "application/vnd.ghost.attestation+json",
            "signatures": [{"keyid": KEYID,
                            "sig": base64.standard_b64encode(KEY.sign(pae)).decode()}]}


def resign(bundle, edit):
    st = json.loads(base64.b64decode(
        bundle["http_response_body"]["receipt"]["envelope"]["payload"]))
    edit(st)
    bundle["http_response_body"]["receipt"]["envelope"] = sign(st)
    return st


def run(bundle, keys=None, extra=()):
    path = TMP / "b.json"
    path.write_text(json.dumps(bundle))
    proc = subprocess.run(
        [sys.executable, str(V2 / "verify_ghost_receipt_v2.py"), str(path),
         keys or str(V2 / "keys" / "keys.json"), *extra],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout


def record(ident, description, reproduced, detail=""):
    results.append((ident, reproduced))
    mark = "REPRODUCED" if reproduced else "not reproduced"
    print(f"{ident:<7} {description}\n        -> {mark} {detail}")


b = copy.deepcopy(BASE)
resign(b, lambda st: st["seller"].update({"keyid": KEYID}))
rc, _ = run(b)
record("P0-1", "fixture-scope key signs a production-claiming receipt", rc == 0,
       f"(exit {rc}; keys.json marks it use=fixture and v2 ignores that)")

forged = TMP / "forged.json"
st = json.loads(base64.b64decode(BASE["http_response_body"]["receipt"]["envelope"]["payload"]))
forged.write_text(json.dumps({"tx_hash": st["payment"]["settlement_reference"],
                              "to": st["payment"]["pay_to"], "asset": st["payment"]["asset"],
                              "network": "eip155:8453", "amount_minor": "10000",
                              "_source": "written by hand; no chain was consulted"}))
rc, out = run(copy.deepcopy(BASE), extra=("--settlement-evidence", str(forged)))
record("P0-2", "hand-written evidence file yields SETTLED",
       "PAYMENT_STATE=SETTLED" in out, f"(exit {rc})")

b = copy.deepcopy(BASE)


def drop_query(st):
    st["request"]["subset_fields"] = ["results", "country", "language"]
    st["request"]["subset"].pop("query", None)
    st["request"]["fingerprint"] = fingerprint(
        {"method": st["request"]["method"],
         "canonical_url": st["request"]["canonical_url"],
         "subset": st["request"]["subset"]})


resign(b, drop_query)
rc1, _ = run(b)
b2 = copy.deepcopy(b)
b2["http_request"]["body"]["query"] = "any question at all"
rc2, _ = run(b2)
record("P0-3", "signer drops query from subset_fields, then swaps the query",
       rc1 == 0 and rc2 == 0, f"(exit {rc1} then {rc2})")

b = copy.deepcopy(BASE)
b["http_response_body"]["results"][0]["title"] = "REWRITTEN TITLE"
b["http_response_body"]["answer"] = {"text": "fabricated", "source": "https://evil"}
rc, _ = run(b)
record("P0-4", "title, snippet, answer and knowledge rewritten", rc == 0, f"(exit {rc})")

b = copy.deepcopy(BASE)
resign(b, lambda st: st["request"].update({"method": "GET"}))
rc, _ = run(b)
record("P1-5a", "signed clear method disagrees with its own fingerprint", rc == 0,
       f"(exit {rc})")

b = copy.deepcopy(BASE)
resign(b, lambda st: st["response"]["subset"].update({"provider": "serper.dev"}))
rc, _ = run(b)
record("P1-5b", "signed response subset disagrees with its own fingerprint", rc == 0,
       f"(exit {rc})")

b = copy.deepcopy(BASE)
resign(b, lambda st: st["seller"].update({"pay_to": "0x" + "00" * 19 + "ad"}))
rc, _ = run(b)
record("P1-6a", "seller.pay_to differs from payment.pay_to", rc == 0, f"(exit {rc})")

b = copy.deepcopy(BASE)
resign(b, lambda st: st.__setitem__("seller", {}))
rc, _ = run(b)
record("P1-6b", "seller block emptied entirely", rc == 0, f"(exit {rc})")

b = copy.deepcopy(BASE)
b.pop("http_response_status", None)
rc, _ = run(b)
record("P2-10", "http_response_status absent, silently assumed 200", rc == 0, f"(exit {rc})")

doc = json.loads((V2 / "keys" / "keys.json").read_text())
for entry in doc["keys"]:
    if entry["keyid"] == KEYID:
        entry["not_after"] = 0
kp = TMP / "k0.json"
kp.write_text(json.dumps(doc))
rc, _ = run(copy.deepcopy(BASE), keys=str(kp))
record("P2-11", "key with not_after=0 treated as open-ended", rc == 0, f"(exit {rc})")

b = copy.deepcopy(BASE)
b["http_response_body"]["receipt"]["envelope"]["signatures"].append(
    {"keyid": "ed25519:" + "f" * 32, "sig": "AAAA"})
rc, _ = run(b)
record("P2-12", "a second unknown signature is ignored", rc == 0, f"(exit {rc})")

missing = [i for i, r in results if not r]
print(f"\n{len(results)} findings, {len(results) - len(missing)} reproduced")
if missing:
    print("did NOT reproduce: " + ", ".join(missing))
raise SystemExit(1 if missing else 0)
