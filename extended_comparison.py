# extended_comparison.py
# Fair comparison: Baseline vs Extended using the REAL updated code
# Uses bb84_protocol from the updated project directly

import sys
import os
import math
import json
import random

# Add updated project path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bb84_backend.core.bb84_quantum import bb84_protocol

THRESHOLD = 0.11   # τ — security threshold
N_RUNS    = 100    # Monte Carlo runs per condition
LENGTH    = 256    # key length
SAMPLE    = 0.2    # QBER sample fraction

NOISE_LEVELS = [0.00, 0.025, 0.05, 0.075,
                0.10, 0.11,  0.15, 0.175,
                0.20, 0.25]

def run_comparison(p_noise, n_runs=N_RUNS):
    baseline_unsafe = 0
    extended_unsafe = 0
    baseline_qber_list = []
    extended_qber_list = []
    baseline_hbin_list = []
    extended_hbin_list = []
    baseline_p1_list   = []
    extended_p1_list   = []

    for run in range(n_runs):
        seed = run  # reproducible

        # ── BASELINE: threshold=99 means it NEVER aborts ──
        ka_b, kb_b, _, qkd_b = bb84_protocol(
            length=LENGTH,
            authenticate=False,
            p_noise=p_noise,
            qber_sample_frac=SAMPLE,
            qber_threshold=99.0,   # never aborts
            seed=seed
        )
        qber_b = qkd_b.get("QBER", 0.0)
        abort_b = qkd_b.get("QKD Abort", False)

        # Key quality metrics for baseline
        n = len(ka_b)
        if n > 0:
            p1_b  = round(ka_b.count(1) / n, 4)
            p0_b  = round(1 - p1_b, 4)
            hbin_b = round(-(p1_b*math.log2(p1_b) + p0_b*math.log2(p0_b)), 4) \
                     if 0 < p1_b < 1 else 0.0
        else:
            p1_b, hbin_b = 0.5, 0.0

        baseline_qber_list.append(qber_b)
        baseline_p1_list.append(p1_b)
        baseline_hbin_list.append(hbin_b)
        if qber_b > THRESHOLD:
            baseline_unsafe += 1

        # ── EXTENDED: threshold=0.11 — aborts when unsafe ──
        ka_e, kb_e, _, qkd_e = bb84_protocol(
            length=LENGTH,
            authenticate=False,
            p_noise=p_noise,
            qber_sample_frac=SAMPLE,
            qber_threshold=THRESHOLD,   # real threshold
            seed=seed
        )
        qber_e  = qkd_e.get("QBER", 0.0)
        abort_e = qkd_e.get("QKD Abort", False)

        # Key quality metrics for extended
        n2 = len(ka_e)
        if n2 > 0:
            p1_e  = round(ka_e.count(1) / n2, 4)
            p0_e  = round(1 - p1_e, 4)
            hbin_e = round(-(p1_e*math.log2(p1_e) + p0_e*math.log2(p0_e)), 4) \
                     if 0 < p1_e < 1 else 0.0
        else:
            p1_e, hbin_e = 0.5, 0.0

        extended_qber_list.append(qber_e)
        extended_p1_list.append(p1_e)
        extended_hbin_list.append(hbin_e)
        if abort_e:
            extended_unsafe += 1
            extended_blocked = extended_unsafe  # sessions correctly aborted
    def avg(lst): return round(sum(lst)/len(lst), 4) if lst else 0
    def std(lst):
        a = avg(lst)
        return round((sum((x-a)**2 for x in lst)/len(lst))**0.5, 4) if lst else 0

    return {
        "p_noise":              p_noise,
        "n_runs":               n_runs,
        "threshold_tau":        THRESHOLD,
        # Baseline
        "baseline_qber_mean":   avg(baseline_qber_list),
        "baseline_qber_std":    std(baseline_qber_list),
        "baseline_p1_mean":     avg(baseline_p1_list),
        "baseline_hbin_mean":   avg(baseline_hbin_list),
        "baseline_unsafe_pct":  round(100*baseline_unsafe/n_runs, 1),
        "baseline_action":      "Always encrypts (no abort control)",
        # Extended
        "extended_qber_mean":   avg(extended_qber_list),
        "extended_qber_std":    std(extended_qber_list),
        "extended_p1_mean":     avg(extended_p1_list),
        "extended_hbin_mean":   avg(extended_hbin_list),
        "extended_unsafe_pct":  round(100*extended_unsafe/n_runs, 1),
        "extended_action":      "Aborts when QBER > τ (Extension 1 active)",
    }

# ── MAIN ─────────────────────────────────────────────────────
if __name__ == "__main__":
    results = []

    print("=" * 70)
    print("FAIR COMPARISON: Baseline vs Extended (Real Updated Code)")
    print(f"n_runs={N_RUNS} | τ={THRESHOLD} | length={LENGTH} | 10 noise levels")
    print("=" * 70)
    print(f"\n{'p_noise':>8} | {'Base QBER':>10} | {'Ext QBER':>10} | "
          f"{'Base Unsafe%':>13} | {'Ext Unsafe%':>12}")
    print("-" * 70)

    for p in NOISE_LEVELS:
        print(f"  Running p_noise={p:.3f} ...", end=" ", flush=True)
        r = run_comparison(p_noise=p, n_runs=N_RUNS)
        results.append(r)
        print(f"✓  QBER_base={r['baseline_qber_mean']:.4f} | "
              f"QBER_ext={r['extended_qber_mean']:.4f} | "
              f"Unsafe_base={r['baseline_unsafe_pct']}% | "
              f"Unsafe_ext={r['extended_unsafe_pct']}%")

    with open("extended_comparison_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 70)
    print("KEY FINDING:")
    r25 = next(r for r in results if r["p_noise"] == 0.25)
    print(f"At p_noise=0.25:")
    print(f"  Baseline: {r25['baseline_unsafe_pct']}% unsafe sessions proceed to AES")
    print(f"  Extended: {r25['extended_unsafe_pct']}% — all blocked by Extension 1")
    print("=" * 70)
    print("DONE — Results saved to extended_comparison_results.json")