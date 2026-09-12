#!/usr/bin/env python3
"""Documentation regression check: the supported verifier must be unmissable.

    python3 verification/check_verifier_docs.py      # from the repo root

The failure this guards against is a reader reaching for the wrong tool. The v1 fixture
verifier is kept unchanged as historical evidence, and for a while the root README
introduced it as a standalone verifier on line 21 and handed out a runnable command on
line 144, while the notice that it is unsupported sat on line 223. Ordering is the whole
risk here, so ordering is what this asserts.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFICATION = ROOT / "verification"
OLD = "verify_ghost_receipt.py"
SUPPORTED = "verify_ghost_receipt_v1_production.py"
SUPPORTED_DIR = "production-v1"

failures: list[str] = []


def check(condition, message):
    print(("ok    " if condition else "FAIL  ") + message)
    if not condition:
        failures.append(message)


def first_index(haystack: str, needle: str) -> int:
    found = haystack.find(needle)
    return found if found >= 0 else 10**9


readme = (VERIFICATION / "README.md").read_text()

# 1. the supported path is named before the old one is mentioned at all
check(first_index(readme, SUPPORTED) < first_index(readme, OLD),
      "root README names the supported verifier before the old one")

# 2. the supported path appears in the first 25 lines, where a reader actually looks
head = "\n".join(readme.splitlines()[:25])
check(SUPPORTED in head and SUPPORTED_DIR in head,
      "supported verifier appears in the first 25 lines")

# 3. every runnable old-verifier command is preceded by an unsupported warning
for match in re.finditer(rf"^\s*(?:>\s*)?python3 {re.escape(OLD)}.*$", readme,
                         flags=re.MULTILINE):
    before = readme[:match.start()].upper()
    check("UNSUPPORTED" in before and "HISTORICAL" in before,
          f"the command on line {readme[:match.start()].count(chr(10)) + 1} "
          f"is preceded by an UNSUPPORTED/HISTORICAL warning")

# 4. the old verifier is explicitly marked, in the table row that describes it
row = next((line for line in readme.splitlines()
            if line.startswith(f"| `{OLD}`")), "")
check("UNSUPPORTED" in row.upper(), "the Files table marks the old verifier unsupported")

# 5. no document presents the old verifier as current or supported
BAD = re.compile(
    r"(?:current|supported|recommended|use this)[^.\n]{0,80}" + re.escape(OLD)
    + r"|" + re.escape(OLD) + r"[^.\n]{0,40}(?:is (?:the )?(?:current|supported))",
    re.IGNORECASE)
for doc in sorted(VERIFICATION.rglob("*.md")) + [ROOT / "README.md"]:
    text = doc.read_text()
    hit = BAD.search(text)
    check(hit is None,
          f"{doc.relative_to(ROOT)} never presents the old verifier as current"
          + (f" (found: {hit.group(0)!r})" if hit else ""))

# 6. the production procedure is reachable and names the supported command
procedure = VERIFICATION / SUPPORTED_DIR / "PRODUCTION-V1-VERIFICATION.md"
check(procedure.exists(), "the production-v1 procedure document exists")
check(SUPPORTED in procedure.read_text(), "the procedure names the supported command")
check((VERIFICATION / SUPPORTED_DIR / SUPPORTED).exists(),
      "the supported verifier file exists")

# 7. link check: every relative markdown link in the verification docs resolves
for doc in sorted(VERIFICATION.rglob("*.md")) + [ROOT / "README.md"]:
    for target in re.findall(r"\]\(([^)#][^)]*)\)", doc.read_text()):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        resolved = (doc.parent / target.split("#")[0]).resolve()
        check(resolved.exists(),
              f"{doc.relative_to(ROOT)} -> {target} resolves")

print(f"\n{'FAILED' if failures else 'PASS'}: "
      f"{len(failures)} problem(s)")
sys.exit(1 if failures else 0)
