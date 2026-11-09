#!/usr/bin/env python3
"""Paired statistical tests (thin wrapper for artifact completeness).

McNemar's test lives in evaluate_scanner.py; this module re-exports it and
provides the Wilson score interval for reuse by other artifact tooling.
"""
import math


def wilson_ci(k: int, n: int, z: float = 1.96):
    """Return (point, lower, upper) as percentages."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (round(100 * p, 2), round(100 * max(0.0, centre - half), 2),
            round(100 * min(1.0, centre + half), 2))


def mcnemar(b: int, c: int):
    """b/c discordant counts. Returns (chi2, p) with continuity correction."""
    if b + c == 0:
        return (0.0, 1.0)
    chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    p = math.erfc(math.sqrt(chi2 / 2))
    return (round(chi2, 3), round(p, 5))
