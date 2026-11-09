#!/usr/bin/env python3
"""Lightweight PCI DSS cardholder-data scanner (Conditions P and A).

Standard-library only. Walks a scan root, extracts numeric candidates,
applies Luhn validation and (optionally) IIN/length validation, detects
plaintext Track 1 / Track 2 / CVV-context SAD artifacts, and writes
masked JSONL output.

Usage:
    python lightweight_pci_scanner.py <scan_root> --config <config.json> --out <out.jsonl>
"""
import argparse
import json
import os
import platform
import re
import sys
from datetime import datetime, timezone

MAX_BYTES_DEFAULT = 5 * 1024 * 1024           # 5 MiB per-file read cap


# ------------------------------------------------------------------ Luhn ----
def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# ------------------------------------------------------------------ IIN -----
class IinRules:
    """Issuer-validation rule matcher built from iin_rules-v1.0.json."""

    def __init__(self, rules_path: str):
        with open(rules_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.discrete = []      # (prefix, lo_len, hi_len)
        self.ranges = []        # (a, b, lo_len, hi_len) inclusive prefix bounds
        for rule in doc["rules"]:
            if "accept_lengths" in rule:
                vals = [int(x) for x in rule["accept_lengths"]]
            elif "accept_ends" in rule:
                vals = [int(x) for x in rule["accept_ends"]]
            else:
                vals = [int(rule["accept_range"][0]), int(rule["accept_range"][1])]
            lo, hi = min(vals), max(vals)
            for p in rule.get("prefixes", []):
                self.discrete.append((p, lo, hi))
            for spec in rule.get("prefix_ranges", []):
                a, b = spec.split("-")
                self.ranges.append((a, b, lo, hi))

    def matches(self, digits: str) -> bool:
        for p, lo, hi in self.discrete:
            if digits.startswith(p) and lo <= len(digits) <= hi:
                return True
        for a, b, lo, hi in self.ranges:
            n = len(a)
            if len(digits) >= n and lo <= len(digits) <= hi and a <= digits[:n] <= b:
                return True
        return False


# ------------------------------------------------------------ extraction ----
_LINEJOIN = re.compile(r"(?<=[0-9])[ \t]*\r?\n[ \t]*(?=[0-9])")

_TRACK1 = re.compile(r"%B(\d{13,19})\^[^\^\?\n]{2,80}\^[0-9]{4}[^?\n]*\??")
_TRACK2 = re.compile(r";?(\d{13,19})=\d{4}[^?\n]{0,60}\??")
_CVV = re.compile(r"(?i)\b(?:cvv|cvc|cid)\b[^0-9\n]{0,40}(\d{3,4})\b")


def enumerate_candidates(text: str):
    """Yield candidate digit strings of length 13–19 (separators removed)."""
    joined = _LINEJOIN.sub("", text)
    for run in re.finditer(r"[0-9][0-9 \-\t]{11,}", joined):
        digits = re.sub(r"[^0-9]", "", run.group(0))
        if 13 <= len(digits) <= 19:
            yield digits
        elif len(digits) > 19:
            cap = len(digits) - 12
            starts = range(0, min(cap, 24))          # bounded window enumeration
            for s in starts:
                yield digits[s:s + 19]


# ------------------------------------------------------------------ scan ----
def scan_file(path: str, max_bytes: int, iin):
    with open(path, "rb") as fh:
        blob = fh.read(max_bytes)
    text = blob.decode("utf-8", errors="replace")
    findings = []
    track_pans = set()

    for m in _TRACK1.finditer(text):
        findings.append(("sad_track1", m.group(1)))
        track_pans.add(m.group(1))
    for m in _TRACK2.finditer(text):
        findings.append(("sad_track2", m.group(1)))
        track_pans.add(m.group(1))
    for m in _CVV.finditer(text):
        findings.append(("sad_cvv_context", m.group(1)))

    seen = set()
    for cand in enumerate_candidates(text):
        # candidates already emitted as part of track records are not re-reported
        if cand in track_pans:
            continue
        if not luhn_ok(cand):
            continue
        if cand in seen:
            continue
        seen.add(cand)
        if iin is None:
            findings.append(("pan_luhn_only", cand))
        elif iin.matches(cand):
            findings.append(("pan_iin_valid", cand))
        else:
            findings.append(("unmatched_luhn_valid", cand))
    return findings


def mask(pan: str) -> str:
    return "****" + pan[-4:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--rules", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "iin_rules-v1.0.json"))
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as fh:
        cfg = json.load(fh)
    max_bytes = int(cfg.get("max_bytes", MAX_BYTES_DEFAULT))
    iin = IinRules(args.rules) if cfg.get("iin_validation", False) else None

    host = platform.node()
    out = open(args.out, "w", encoding="utf-8", newline="\n")
    records = 0
    for dirpath, _dirs, files in os.walk(args.root):
        for name in sorted(files):
            full = os.path.abspath(os.path.join(dirpath, name))
            try:
                fnd = scan_file(full, max_bytes, iin)
            except OSError:
                continue
            for cls, value in fnd:
                rec = {
                    "host": host,
                    "path": full,
                    "detection_class": cls,
                    "object": mask(value),
                    "escalation": cls.startswith("sad"),
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                out.write(json.dumps(rec) + "\n")
                records += 1
    out.close()
    sys.stderr.write(f"records={records}\n")


if __name__ == "__main__":
    main()
