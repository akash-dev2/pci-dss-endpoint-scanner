#!/usr/bin/env python3
"""Condition B cross-check scanner (independent implementation).

Shares no code with scanner/lightweight_pci_scanner.py: separate regex
style, iterative Luhn implementation, no IIN validation, CSV output with
NO detection-class label, single-scan pass.

Usage:
    python cross_check_scanner.py <corpus> --out results/condition_B/scan_results.jsonl
    (writes JSON Lines of {file, masked, len} — no class field)
"""
import os
import re
import sys
import platform
from datetime import datetime, timezone

PAN_RE = re.compile(r"\b[0-9][0-9\- ]{11,30}[0-9]\b")
T2_RE = re.compile(r";?[0-9]{13,19}=[0-9]{4}")
T1_RE = re.compile(r"%B[0-9]{13,19}\^")


def luhn(x):
    s = 0
    for i, c in enumerate(reversed(x)):
        v = int(c)
        if i % 2 == 1:
            v *= 2
            if v > 9:
                v -= 9
        s += v
    return s % 10 == 0


def dig(x):
    return re.sub(r"[^0-9]", "", x)


def main():
    root = sys.argv[1]
    outarg = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "results/condition_B/scan_results.jsonl"
    outdir = os.path.dirname(outarg)
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    host = platform.node()
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    n = 0
    with open(outarg, "w", encoding="utf-8", newline="\n") as out:
        for dp, _dn, fn in os.walk(root):
            for f in sorted(fn):
                p = os.path.abspath(os.path.join(dp, f))
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        txt = fh.read(5242880)
                except OSError:
                    continue
                hits = set()
                for m in T1_RE.finditer(txt) or []:
                    hits.add(dig(m.group(0)))
                for m in T2_RE.finditer(txt):
                    hits.add(dig(m.group(0).split("=")[0]))
                for m in PAN_RE.finditer(txt):
                    d = dig(m.group(0))
                    if 13 <= len(d) <= 19 and luhn(d):
                        hits.add(d)
                for d in sorted(hits):
                    rec = {"file": p, "matched": "****" + d[-4:], "len": len(d),
                           "host": host, "time": ts}
                    out.write((str(rec).replace("'", '"')) + "\n")
                    n += 1
    sys.stderr.write(f"records={n}\n")


if __name__ == "__main__":
    main()
