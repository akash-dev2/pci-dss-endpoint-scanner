#!/usr/bin/env python3
"""Deterministic synthetic corpus generator.

Emits files into <out>/<class>/ plus manifest.json recording ground truth
per file. Labels are never embedded in file content. No real cardholder
data is used; PANs are synthetic test numbers.

Classes:
  valid_pan            - contains ground-truth PANs (test BIN ranges;
                         ~3% of PAN files use issued ranges absent from
                         rule set v1.0, i.e. private-label-like)
  luhn_valid_noncard   - numeric identifiers passing Luhn by chance; some
                         deliberately match recognised IIN prefixes
  luhn_invalid_numeric - numeric strings failing the checksum
  sad_bearing          - Track 1 / Track 2 records and CVV contexts
  benign               - prose, logs, telephony, binary blobs, and
                         adversarial CVV-keyword / binary digit noise

Usage:
    python generate_corpus.py --out corpus --files 5000 --seed 42
"""
import argparse
import json
import os
import random

TEST_BINS = {
    "Visa": (["4"], (13, 16, 19)),
    "Mastercard": (["51", "52", "53", "54", "55", "2221", "2720"], (16,)),
    "American Express": (["34", "37"], (15,)),
    "Discover": (["6011", "644", "648", "65"], (16,)),
}
# issued-like ranges deliberately absent from rule set v1.0 (private-label-like)
OFF_RULE_BINS = (["81", "91", "97"], (16,))

NONCARD_PREFIXES = ("71", "80", "90", "24", "28", "77", "83")          # no IIN
CARDPREFIX_NONCARD = ("4", "51", "55", "222", "60", "35", "62", "50")  # IIN-lookalike

TRAIN_FORMATS = ("plain", "space", "hyphen", "line")


def luhn_check_digit(body: str) -> int:
    total = 0
    alt = True
    for ch in reversed(body):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return (10 - total % 10) % 10


def make_pan(rng, bin_prefix: str, length: int) -> str:
    body = bin_prefix + "".join(rng.choice("0123456789") for _ in range(length - len(bin_prefix) - 1))
    return body + str(luhn_check_digit(body))


def fmt(pan: str, form: str) -> str:
    if form == "space":
        return " ".join(pan[i:i + 4] for i in range(0, len(pan), 4)).rstrip()
    if form == "hyphen":
        return "-".join(pan[i:i + 4] for i in range(0, len(pan), 4)).rstrip()
    if form == "line":
        return "\n".join(pan[i:i + 4] for i in range(0, len(pan), 4)).rstrip()
    return pan


def fmt_invalid(rng, digits):
    for _ in range(200):
        body = digits[:-1]
        for i in rng.sample(range(len(body)), 2):
            body = body[:i] + rng.choice("0123456789") + body[i + 1:]
        cand = body + digits[-1]
        total, alt = 0, False
        for ch in reversed(cand):
            d = ord(ch) - 48
            if alt:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
            alt = not alt
        if total % 10 != 0:
            return cand
    retdigits = digits
    retdigits = retdigits[:-1] + str((int(retdigits[-1]) + 1) % 10) if luhn(retdigits) else retdigits
    return retdigits


def luhn(s: str) -> bool:
    total, alt = 0, False
    for ch in reversed(s):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


PROSE = ("invoice processed by the billing subsystem on schedule. "
         "support contacted the vendor regarding renewal terms. "
         "the quarterly reconciliation finished without exceptions. "
         "archived attachments were moved to cold storage per policy. ")
PHONE = ("555-867-{n}", "(555){n}-{m}")


def pad(rng, base, minlen, maxlen):
    while len(base) < rng.randint(minlen, maxlen):
        base += "\n" + PROSE * rng.randint(1, 4) + f" ref=2026-{rng.randint(1000,9999)} tel=555-867-{rng.randint(1000,9999)}"
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--files", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)

    # class mix (paper Section 4.3 five classes)
    mix = [
        ("valid_pan", round(args.files * 0.10)),
        ("luhn_valid_noncard", round(args.files * 0.02)),
        ("luhn_invalid_numeric", round(args.files * 0.05)),
        ("sad_bearing", round(args.files * 0.08)),
        ("benign", 0),
    ]
    mix[-1] = ("benign", args.files - sum(c for _, c in mix[:-1]))

    manifest = []
    idx = 0
    for cls, count in mix:
        sub = os.path.join(args.out, cls)
        os.makedirs(sub, exist_ok=True)
        for _ in range(count):
            idx += 1
            name = f"{cls}_{idx:05d}.txt"
            rel = os.path.join(cls, name)
            content, has_pan, has_sad = "", False, False
            sad_kinds = {"track1": False, "track2": False, "cvv": False}

            if cls == "valid_pan":
                if rng.random() < 0.03:                       # off-rule private-label-like
                    prefix = rng.choice(OFF_RULE_BINS[0])
                    lengths = OFF_RULE_BINS[1]
                else:
                    brand = rng.choice(list(TEST_BINS))
                    prefix = rng.choice(TEST_BINS[brand][0])
                    lengths = TEST_BINS[brand][1]
                form = rng.choice(TRAIN_FORMATS)
                pan = make_pan(rng, prefix, rng.choice(lengths))
                content = fmt(pan, form) + "\n" + PROSE * rng.randint(2, 30)
                has_pan = True

            elif cls == "luhn_valid_noncard":
                prefix_pool = CARDPREFIX_NONCARD if rng.random() < 0.55 else NONCARD_PREFIXES
                pan = make_pan(rng, rng.choice(prefix_pool), rng.choice([13, 15, 16, 19]))
                content = f"order id: {pan}\n" + PROSE * rng.randint(2, 30)
                if not luhn(pan):
                    pan = make_pan(rng, rng.choice(prefix_pool), 16)
                    content = f"order id: {pan}\n" + PROSE * rng.randint(2, 30)

            elif cls == "luhn_invalid_numeric":
                pan = make_pan(rng, rng.choice(NONCARD_PREFIXES), rng.choice([13, 15, 16, 19]))
                pan = fmt_invalid(rng, pan)
                content = f"reference {pan} valid\n" + PROSE * rng.randint(2, 30)

            elif cls == "sad_bearing":
                brand = rng.choice(list(TEST_BINS))
                pan = make_pan(rng, rng.choice(TEST_BINS[brand][0]),
                               rng.choice(TEST_BINS[brand][1]))
                kind = rng.random()
                if kind < 0.4:
                    trail = rng.choice(["^2412101", ""])
                    rec = f"%B{pan}^SMITH/JOHN^2412{trail}?"
                    if rng.random() < 0.5:
                        rec = rec[:-1]                          # truncated log: no trailing ?
                    content = rec + "\n" + PROSE * rng.randint(2, 20)
                    sad_kinds["track1"] = True
                elif kind < 0.8:
                    disc = rng.choice(["=2601", "=2601XY4A"])
                    rec = f";{pan}{disc}?"
                    if rng.random() < 0.5:
                        rec = rec.lstrip(";")                   # sentinel stripped in logging
                    if rng.random() < 0.5:
                        rec = rec[:-1] if rec.endswith("?") else rec
                    content = rec + "\n" + PROSE * rng.randint(2, 20)
                    sad_kinds["track2"] = True
                else:
                    content = (f"auth response cvv={rng.randint(100,999)} pan={pan}\n"
                               + PROSE * rng.randint(2, 20))
                    sad_kinds["cvv"] = True
                    has_pan = True          # standalone PAN printed alongside CVV context
                has_sad = True

            else:  # benign
                r = rnd = rng.random()
                if r < 0.55:
                    lines = []
                    for _ in range(rng.randint(8, 40)):
                        lines.append(f"[2026-04-{rng.randint(10,28)} {rng.randint(10,17)}:{rng.randint(10,59)}:11] "
                                     f"INFO ref=2026-{rng.randint(10000,99999)} "
                                     f"tel=(555)867-{rng.randint(1000,9999)} "
                                     f"order={rng.randint(10**8, 10**9 - 1)}")
                    content = "\n".join(lines) + "\n" + PROSE * rng.randint(1, 8)
                elif r < 0.75:
                    # binary-ish blob with stray digit fragments
                    frag = "".join(rng.choice("0123456789ABCDEFx.") for _ in range(rng.randint(400, 900)))
                    content = "\x00\x01binary-ish payload\x02\n" + frag + "\n" + PROSE * 3
                elif r < 0.90:
                    # adversarial CVV/CVC-keyword proximity that is NOT SAD
                    content = (f"configuration: cvc rule {rng.randint(100,999)} applies to "
                               f"settlement windows unit {rng.randint(10,99)}\n"
                               + PROSE * rng.randint(3, 25))
                else:
                    content = PROSE * rng.randint(30, 90)

            size = max(len(content), 0)
            if size < 3000:                                   # pad to realistic file sizes
                content = content + "\n" + PROSE * ((3000 // len(PROSE)) + 1)
            with open(os.path.join(args.out, rel), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)

            manifest.append({
                "file": os.path.normpath(rel).replace("\\", "/"),
                "class": cls,
                "has_pan": has_pan,
                "has_sad": has_sad,
                "sad_has_track1": sad_kinds["track1"],
                "sad_has_track2": sad_kinds["track2"],
                "sad_has_cvv": sad_kinds["cvv"],
            })

    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"seed": args.seed, "files": len(manifest), "entries": manifest}, fh, indent=1)

    # aux mapping for the FP classifier: benign files of the adversarial
    # CVV/CVC-keyword subtype (manifest carries no semantic subtype labels).
    # Deterministic from the same rng stream: re-derive which benign files
    # took the r<0.90 branch by replaying their content markers.
    cvc_files = []
    for m in manifest:
        if m["class"] != "benign":
            continue
        with open(os.path.join(args.out, m["file"]), encoding="utf-8") as fh:
            head = fh.read(120)
        if "cvc rule" in head:
            cvc_files.append(m["file"])
    with open(os.path.join(args.out, "..", "evaluation", "fp_aux.json"),
              "w", encoding="utf-8") as fh:
        json.dump({"benign_cvc": cvc_files}, fh, indent=1)

    print(f"generated {len(manifest)} files -> {args.out}")


if __name__ == "__main__":
    main()
