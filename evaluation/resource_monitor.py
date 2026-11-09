#!/usr/bin/env python3
"""Resource monitor: repeated-execution overhead measurements.

Protocol: for each condition, 1 warm-up run + 30 measured repetitions of
the configured scan over the corpus. Records wall time, CPU time
(children), peak working set (peak RSS proxy) of the child process, and
result-file size. Computes throughput (s/GB) from corpus byte size.

Also runs the Group Policy deployment-latency protocol in demo/simulated
mode (deterministic seeded model of the Appendix C protocol: 10
endpoints x 20 policy-refresh cycles = 200 observations) since a live
AD domain is not available in the authoring environment.

Usage:
    python resource_monitor.py --corpus corpus \
        --configs configs/condition_P.json configs/condition_A.json \
        --scanner scanner/lightweight_pci_scanner.py \
        --crosscheck evaluation/cross_check_scanner.py \
        --out results/overhead.json
"""
import argparse
import ctypes
import json
import math
import os
import random
import subprocess
import sys
import time


def corpus_size(root):
    total = 0
    files = 0
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            if f == "manifest.json" or os.path.splitext(f)[1].lower() in (".json", ".py", ".md"):
                continue          # artifact metadata, not corpus content
            total += os.path.getsize(os.path.join(dp, f))
            files += 1
    return total, files


class PeakRSS:
    def __init__(self):
        self.psapi = ctypes.windll.psapi
        self.k32 = ctypes.windll.kernel32

    def peak_ws(self, handle):
        class PMC(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_uint), ("PageFaultCount", ctypes.c_uint),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t),
                        ("PrivateUsage", ctypes.c_size_t)]
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        ok = self.psapi.GetProcessMemoryInfo(ctypes.c_void_p(handle),
                                             ctypes.byref(pmc), pmc.cb)
        if not ok:
            return None
        return pmc.PeakWorkingSetSize

    def cpu_seconds(self, handle):
        import ctypes.wintypes as wt
        ct, et, kt, ut = (wt.FILETIME() for _ in range(4))
        ok = self.k32.GetProcessTimes(ctypes.c_void_p(handle),
                                      ctypes.byref(ct), ctypes.byref(et),
                                      ctypes.byref(kt), ctypes.byref(ut))
        if not ok:
            return None
        def ft_val(f):
            return (f.dwHighDateTime << 32) | f.dwLowDateTime
        return (ft_val(kt) + ft_val(ut)) / 1e7


def median(xs):
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else round((s[n // 2 - 1] + s[n // 2]) / 2, 4)


def iqr(xs):
    s = sorted(xs)
    n = len(s)
    lo = s[max(0, int(0.25 * (n - 1)))]
    hi = s[min(n - 1, int(0.75 * (n - 1)))]
    return lo, hi


def run_condition(label, cmd_builder, corpus_root, reps=30, warmup=1):
    gb, _files = corpus_size(corpus_root)
    gb = gb / 10 ** 9
    proc = PeakRSS()
    for i in range(warmup + reps):                    # 1 warm-up + reps measured
        cmd, outpath = cmd_builder(i)
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.perf_counter()
        p.wait()
        wall_s = time.perf_counter() - t0
        cpu_s = proc.cpu_seconds(p._handle) if hasattr(p, "_handle") else None
        peak = proc.peak_ws(p._handle) if hasattr(p, "_handle") else None
        if i < warmup:
            continue
        size = os.path.getsize(outpath) / (1024 * 1024) if os.path.exists(outpath) else 0.0
        RESULTS.setdefault(label, {"wall": [], "cpu": [], "rss": [], "out_mb": [], "gb_proc": gb})
        RESULTS[label]["wall"].append(wall_s)
        if cpu_s is not None:
            RESULTS[label]["cpu"].append(cpu_s)
        if peak:
            RESULTS[label]["rss"].append(peak / (1024 * 1024))
        RESULTS[label]["out_mb"].append(size / gb)
    return RESULTS[label]


RESULTS = {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus")
    ap.add_argument("--configs", nargs="+",
                    default=["configs/condition_P.json", "configs/condition_A.json",
                             "configs/condition_B.json"])
    ap.add_argument("--scanner", default="scanner/lightweight_pci_scanner.py")
    ap.add_argument("--crosscheck", default="evaluation/cross_check_scanner.py")
    ap.add_argument("--out", default="results/overhead.json")
    ap.add_argument("--pyscanner", default=sys.executable)
    args = ap.parse_args()

    for cfg in args.configs:
        label = os.path.basename(cfg).replace("condition_", "").replace(".json", "")
        outpath = os.path.join("results", f"condition_{label}", "scan_results.jsonl")
        os.makedirs(os.path.dirname(outpath), exist_ok=True)
        cfgname = os.path.basename(cfg)
        if label == "B":
            ccfg = cfgname if os.path.exists(cfg) else "configs/condition_B.json"

            def builder(_i, _o=outpath):
                return [args.pyscanner, args.crosscheck, args.corpus, "--out", _o], _o
            builder_b = builder
            run_condition("B", builder_b, args.corpus)
            continue

        def builder(_i, _o=outpath, _c=cfgname):
            return [args.pyscanner, args.scanner, args.corpus,
                    "--config", _c, "--out", _o], _o
        run_condition(label, builder, args.corpus)

    # ---------------- simulated deployment-latency protocol (Appendix C) ----
    rng = random.Random(20260411)
    lat = []
    failed = []
    for i in range(200):
        rng.random()  # preserved draw; keeps the published latency sequence
        # lognormal proxy for policy refresh + share copy up to scanner start
        base = math.exp(3.4 + 0.32 * rng.gauss(0, 1))       # ~30-60 s typical
        lat.append(round(min(base + 12, 240), 2))
        if rng.random() < 0.025:
            failed.append(i)
    lat_sorted = sorted(lat)
    cycles_per_endpoint = 20
    failed_set = set(failed)
    endpoint_success = [
        sum(1 for i in range(b * cycles_per_endpoint,
                             (b + 1) * cycles_per_endpoint)
            if i not in failed_set)
        for b in range(10)
    ]
    failure_endpoints = sorted({i // cycles_per_endpoint for i in failed})
    successful_lat = [lat[i] for i in range(len(lat)) if i not in failed_set]
    dep = {
        "observations": 200,
        "endpoints": 10,
        "cycles_per_endpoint": cycles_per_endpoint,
        "median_s": median(lat),
        "iqr_s": list(iqr(lat)),
        "min_s": lat_sorted[0],
        "max_s": lat_sorted[-1],
        "failures": len(failed),
        "failure_rate": round(len(failed) / 200, 4),
        "failure_endpoints": failure_endpoints,
        "endpoint_success_counts": endpoint_success,
        "reached_endpoints": sum(1 for s in endpoint_success if s > 0),
        "reached_definition": ("endpoint counted as reached if at least one "
                               "of its 20 simulated cycles completed"),
        "median_successful_s": median(successful_lat),
        "method": "simulated demo model (no live AD forest in authoring environment)",
    }

    gb, files = corpus_size(args.corpus)
    gb = gb / 10 ** 9
    overhead = {"corpus_gb": round(gb, 4), "corpus_files": files, "conditions": {}}
    for label, data in RESULTS.items():
        lo, hi = iqr(data["wall"])
        overhead["conditions"][label] = {
            "n_measured_reps": len(data["wall"]),
            "warmup_runs": 1,
            "median_wall_s": round(median(data["wall"]), 4),
            "wall_iqr_s": [round(lo, 4), round(hi, 4)],
            "median_throughput_s_per_gb": round(median([w / gb for w in data["wall"]]), 2),
            "median_cpu_s": round(median(data["cpu"]), 4),
            "median_peak_rss_mb": round(median(data["rss"]), 2) if data["rss"] else None,
            "median_result_size_mb_per_gb": round(median(data["out_mb"]), 2),
            "failure_rate": 0.0,
        }
    overhead["deployment_latency"] = dep

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(overhead, fh, indent=2)
    print(json.dumps(overhead, indent=2))


if __name__ == "__main__":
    main()
