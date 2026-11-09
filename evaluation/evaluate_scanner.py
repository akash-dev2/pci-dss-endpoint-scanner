#!/usr/bin/env python3
"""Evaluation harness: file-level metrics, Wilson CIs, McNemar tests,
FP classification. Consumes manifest.json and per-condition JSONL outputs.

Usage:
    python evaluate_scanner.py --manifest corpus/manifest.json \
        --conditions results/condition_P results/condition_A results/condition_B \
        --out results/metrics.json

Also writes results/fp_classification.csv, results/environment.json.
"""
import argparse
import csv
import json
import math
import os
import platform
import sys


def wilson(k, n, z=1.96):
    if n == 0:
        return [0.0, 0.0, 0.0]
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(100 * p, 2), round(100 * max(0.0, centre - half), 2), round(100 * min(1.0, centre + half), 2)]


def mcnemar(n01, n10):
    """b = baseline-only, c = other-only. Returns chi2, p."""
    if n01 + n10 == 0:
        return 0.0, 1.0
    chi2 = (abs(n01 - n10) - 1) ** 2 / (n01 + n10)
    p = math.erfc(math.sqrt(chi2 / 2))
    return round(chi2, 3), round(p, 5)


def f1(prec, rec):
    if prec + rec == 0:
        return 0.0
    return round(2 * prec * rec / (prec + rec), 4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--conditions", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    corpus_dir = os.path.dirname(os.path.abspath(args.manifest))
    with open(args.manifest, encoding="utf-8") as fh:
        man = json.load(fh)
    entries = man["entries"]
    for e in entries:
        e["abs"] = os.path.normpath(os.path.join(corpus_dir, e["file"])).lower()

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    cond_names = [os.path.basename(c.rstrip("/\\")).replace("condition_", "") for c in args.conditions]

    cond_meta = {}
    with open(os.path.join("configs", "condition_P.json"), encoding="utf-8") as fh:
        cond_meta["P"] = json.load(fh)
    with open(os.path.join("configs", "condition_B.json"), encoding="utf-8") as fh:
        cond_meta["B"] = json.load(fh)

    cond_records = {}
    for cname, cdir in zip(cond_names, args.conditions):
        recs = []
        path = os.path.join(cdir, "scan_results.jsonl")
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
        cond_records[cname] = recs

    def detections(cname):
        """Map abs file path -> set of detection classes."""
        d = {}
        for r in cond_records[cname]:
            key = os.path.normpath(r["path"] if "path" in r else r["file"]).lower()
            d.setdefault(key, set()).add(r.get("detection_class", "hit_unlabelled"))
        return d

    det = {c: detections(c) for c in cond_names}

    def flag_pan(cname, entry):
        if cname == "B":                       # no class labels in cross-check output
            return entry["abs"] in det["B"]
        return any(x.startswith("pan_") for x in det[cname].get(entry["abs"], ()))

    # ------------------------------------------------------------ PAN level
    pos = [e for e in entries if e["has_pan"]]
    neg = [e for e in entries if not e["has_pan"] and not e["has_sad"]]
    pan = {}
    for cname in cond_names:
        d = det[cname]
        tp = sum(1 for e in pos if flag_pan(cname, e))
        fp = sum(1 for e in neg if flag_pan(cname, e))
        fn = len(pos) - tp
        tn = len(neg) - fp
        tpr, lo_t, hi_t = wilson(tp, len(pos))
        fpr, lo_f, hi_f = wilson(fp, len(neg))
        prec = round(100 * tp / (tp + fp), 2) if tp + fp else 0.0
        pan[cname] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "TPR": tpr, "wilson_95_ci_TPR": [lo_t, hi_t],
            "FPR": fpr, "wilson_95_ci_FPR": [lo_f, hi_f],
            "precision": prec, "f1": f1(prec, tpr),
            "n_positive_files": len(pos), "n_negative_files": len(neg),
        }

    # ---------------------------------------------------- SAD level (P only)
    sad = {}
    dp = det["P"]
    for kind, cls in (("track1", "sad_track1"), ("track2", "sad_track2"), ("cvv", "sad_cvv_context")):
        pk = [e for e in entries if e[f"sad_has_{kind}"]]
        nk = [e for e in entries if not e[f"sad_has_{kind}"]]
        tp = sum(1 for e in pk if cls in dp.get(e["abs"], ()))
        fp = sum(1 for e in nk if cls in dp.get(e["abs"], ()))
        tpr, lo_t, hi_t = wilson(tp, len(pk))
        fpr, lo_f, hi_f = wilson(fp, len(nk))
        sad[kind] = {
            "class": cls, "TP": tp, "FP": fp, "FN": len(pk) - tp, "TN": len(nk) - fp,
            "TPR": tpr, "wilson_95_ci_TPR": [lo_t, hi_t],
            "FPR": fpr, "wilson_95_ci_FPR": [lo_f, hi_f],
        }
    sad["overall"] = {
        "TPR": round(sum(sad[k]["TP"] for k in ("track1", "track2", "cvv")) /
                     max(1, sum(sad[k]["TP"] + sad[k]["FN"] for k in ("track1", "track2", "cvv"))) * 100, 2)
    }

    # ------------------------------------------------------- McNemar P vs A
    pa, pb = det["P"], det["A"]
    pos_only_a = sum(1 for e in pos if flag_pan("A", e) and not flag_pan("P", e))
    pos_only_p = sum(1 for e in pos if flag_pan("P", e) and not flag_pan("A", e))
    chi_t, p_t = mcnemar(pos_only_a, pos_only_p)
    neg_only_a = sum(1 for e in neg if flag_pan("A", e) and not flag_pan("P", e))
    neg_only_p = sum(1 for e in neg if flag_pan("P", e) and not flag_pan("A", e))
    chi_f, p_f = mcnemar(neg_only_a, neg_only_p)
    paired = {
        "TPR_change_pp": round(pan["P"]["TPR"] - pan["A"]["TPR"], 2),
        "FPR_change_pp": round(pan["P"]["FPR"] - pan["A"]["FPR"], 2),
        "mcnemar_TPR": {"discordant_A_only": pos_only_a, "discordant_P_only": pos_only_p,
                        "chi2": chi_t, "p": p_t},
        "mcnemar_FPR": {"discordant_A_only": neg_only_a, "discordant_P_only": neg_only_p,
                        "chi2": chi_f, "p": p_f},
    }

    # ------------------------------------------------- FP classification CSV
    fp_rows = []
    cats = {c: {} for c in cond_names}
    for cname in cond_names:
        d = det[cname]
        fp_files = [e for e in neg if flag_pan(cname, e)]
        counter = {"Luhn-passing non-card number": 0,
                   "Card-like numeric identifier with no recognised IIN": 0,
                   "Partial match in binary or encoded content": 0,
                   "SAD keyword-digit proximity over-match": 0}
        for e in fp_files:
            if e["class"] == "luhn_valid_noncard":
                # cross-condition rule: category 1 when the numerals satisfy
                # IIN validation (Condition P flags them), category 2 otherwise
                if any(x == "pan_iin_valid" for x in det["P"].get(e["abs"], ())):
                    counter["Luhn-passing non-card number"] += 1
                else:
                    counter["Card-like numeric identifier with no recognised IIN"] += 1
            elif e["class"] == "benign":
                if e["file"] in FPCACHE.get("benign_cvc", set()):
                    counter["SAD keyword-digit proximity over-match"] += 1
                else:
                    counter["Partial match in binary or encoded content"] += 1
            else:
                counter["Luhn-passing non-card number"] += 1
        # SAD-level CVV over-match FP (benign cvc files), counted per condition
        cvv_fp = [e for e in entries if e["class"] == "benign"
                  and "sad_cvv_context" in d.get(e["abs"], ())]
        counter["SAD keyword-digit proximity over-match"] += len(cvv_fp)
        cats[cname].update(counter)
        total = sum(counter.values()) or 1
        for k, v in counter.items():
            fp_rows.append([cname, k, v, round(100 * v / total, 2)])
    with open(os.path.join(out_dir, "fp_classification.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["condition", "category", "count", "percentage"])
        w.writerows(fp_rows)

    fp_red = round(100 * (pan["A"]["FP"] - pan["P"]["FP"]) / max(1, pan["A"]["FP"]), 1)
    recall_cost = round(pan["A"]["TPR"] - pan["P"]["TPR"], 2)

    env = {
        "reference_endpoint": {
            "host": platform.node(),
            "windows_version": platform.version(),
            "windows_platform": platform.platform(terse=True),
            "python_version": platform.python_version(),
            "role": "carries all detection-performance and scan-overhead measurements (Tables 2-4)",
        },
        "modelled_deployment_environment": {
            "modelled": True,
            "endpoints": 10,
            "windows_version": "Windows 11 23H2 (modelled)",
            "ad_functional_level": "Windows Server 2016 (assumed by model)",
            "dc_version": "Windows Server 2019 (assumed by model)",
            "source": "results/overhead.json -> deployment_latency (deterministic refresh-schedule model; §4.1, §8)",
        },
        "corpus_gb": None,   # filled from results/overhead.json when present
        "corpus_files": None,
    }
    ov_path = os.path.join(out_dir, "overhead.json")
    if os.path.exists(ov_path):
        try:
            with open(ov_path, encoding="utf-8") as fh:
                ov = json.load(fh)
            env["corpus_gb"] = ov.get("corpus_gb")
            env["corpus_files"] = ov.get("corpus_files")
        except (OSError, ValueError):
            pass

    metrics = {
        "pan_detection": pan,
        "sad_detection": sad,
        "paired_tests": paired,
        "fp_reduction_percent": fp_red,
        "recall_cost_pp": recall_cost,
        "eliminated_false_positives": pan["A"]["FP"] - pan["P"]["FP"],
        "added_false_negatives": pan["A"]["TP"] - pan["P"]["TP"],
        "condition_B_class_label": False,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)

    with open(os.path.join(out_dir, "environment.json"), "w", encoding="utf-8") as fh:
        json.dump(env, fh, indent=2)

    print(json.dumps({"pan": pan.get("P"), "paired": paired["TPR_change_pp"],
                      "fp_red": fp_red, "recall_cost": recall_cost}, indent=2))


FPCACHE = {}


def cv_check(filename, entries):
    """True when a benign FP file is the adversarial CVV-keyword subtype.

    Adversarial subtype is detectable from runner-provided mapping; the
    harness falls back to filename ordering used by generate_corpus.py.
    """
    # benign cvc-overmatch files were generated in the r<0.90 branch; the
    # harness receives their names via results/fp_aux.json written by the
    # corpus generator when present.
    return filename in FPCACHE.get("benign_cvc", set())


if __name__ == "__main__":
    # load benign-cvc aux mapping if available
    aux = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "fp_aux.json")
    if os.path.exists(aux):
        with open(aux, encoding="utf-8") as fh:
            FPCACHE.update(json.load(fh))
    main()
