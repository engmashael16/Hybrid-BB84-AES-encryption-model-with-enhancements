#!/usr/bin/env python3
"""
Monte Carlo wrapper/summariser for the BB84 hybrid experiment.

How to use:
1) Save this file in the project root, next to extended_comparison.py
2) If extended_comparison_results.json already exists and is up to date:
      python montecarlo_experiment.py --skip-run
3) If you want to regenerate the repeated-run results first:
      python montecarlo_experiment.py --run

Outputs:
- results/montecarlo_summary.csv
- results/montecarlo_summary.json
- results/montecarlo_summary_for_thesis.txt

Important note:
The source JSON uses the names baseline_unsafe_pct and extended_unsafe_pct.
In the outputs of this script, these are reported more carefully as:
- baseline_qber_gt_tau_pct
- extended_qber_gt_tau_pct
because, for the extended model, the flagged sessions are expected to trigger
an abort rather than proceed to unsafe encryption.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REQUIRED_KEYS = [
    "p_noise",
    "n_runs",
    "threshold_tau",
    "baseline_qber_mean",
    "baseline_qber_std",
    "baseline_p1_mean",
    "baseline_hbin_mean",
    "baseline_unsafe_pct",
    "baseline_action",
    "extended_qber_mean",
    "extended_qber_std",
    "extended_p1_mean",
    "extended_hbin_mean",
    "extended_unsafe_pct",
    "extended_action",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a thesis-ready Monte Carlo summary from extended_comparison_results.json"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--run",
        action="store_true",
        help="Run extended_comparison.py before summarising the results.",
    )
    group.add_argument(
        "--skip-run",
        action="store_true",
        help="Do not rerun experiments; summarise the existing JSON file only.",
    )
    return parser.parse_args()


def maybe_run_extended(project_root: Path, should_run: bool) -> None:
    if not should_run:
        return

    script_path = project_root / "extended_comparison.py"
    if not script_path.exists():
        raise FileNotFoundError(
            f"Could not find {script_path.name}. Place montecarlo_experiment.py in the project root."
        )

    print(f"[INFO] Running {script_path.name} ...")
    subprocess.run([sys.executable, str(script_path)], cwd=project_root, check=True)
    print("[INFO] Repeated-run comparison finished.\n")


def load_results(results_json: Path) -> list[dict[str, Any]]:
    if not results_json.exists():
        raise FileNotFoundError(
            f"Could not find {results_json.name}. Run extended_comparison.py first or use --run."
        )

    with results_json.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list) or not data:
        raise ValueError(f"{results_json.name} does not contain a non-empty list of result blocks.")

    for idx, row in enumerate(data, start=1):
        missing = [k for k in REQUIRED_KEYS if k not in row]
        if missing:
            raise KeyError(
                f"Missing keys in result block #{idx}: {', '.join(missing)}"
            )
    return data


def safe_round(value: Any, digits: int = 4) -> float:
    return round(float(value), digits)


def pct_to_runs(pct_value: Any, n_runs: Any) -> int:
    return round((float(pct_value) / 100.0) * int(n_runs))


def transform_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for row in rows:
        n_runs = int(row["n_runs"])
        tau = safe_round(row["threshold_tau"], 4)
        baseline_flag_pct = safe_round(row["baseline_unsafe_pct"], 2)
        extended_flag_pct = safe_round(row["extended_unsafe_pct"], 2)

        cleaned.append(
            {
                "p_noise": safe_round(row["p_noise"], 4),
                "n_runs": n_runs,
                "threshold_tau": tau,
                "baseline_qber_mean": safe_round(row["baseline_qber_mean"], 4),
                "baseline_qber_std": safe_round(row["baseline_qber_std"], 4),
                "extended_qber_mean": safe_round(row["extended_qber_mean"], 4),
                "extended_qber_std": safe_round(row["extended_qber_std"], 4),
                "baseline_p1_mean": safe_round(row["baseline_p1_mean"], 4),
                "extended_p1_mean": safe_round(row["extended_p1_mean"], 4),
                "baseline_hbin_mean": safe_round(row["baseline_hbin_mean"], 4),
                "extended_hbin_mean": safe_round(row["extended_hbin_mean"], 4),
                # Renamed carefully for thesis writing.
                "baseline_qber_gt_tau_pct": baseline_flag_pct,
                "extended_qber_gt_tau_pct": extended_flag_pct,
                "baseline_qber_gt_tau_runs": pct_to_runs(baseline_flag_pct, n_runs),
                "extended_qber_gt_tau_runs": pct_to_runs(extended_flag_pct, n_runs),
                "baseline_action": str(row["baseline_action"]),
                "extended_action": str(row["extended_action"]),
            }
        )
    return cleaned


def write_csv(output_csv: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "p_noise",
        "n_runs",
        "threshold_tau",
        "baseline_qber_mean",
        "baseline_qber_std",
        "extended_qber_mean",
        "extended_qber_std",
        "baseline_p1_mean",
        "extended_p1_mean",
        "baseline_hbin_mean",
        "extended_hbin_mean",
        "baseline_qber_gt_tau_pct",
        "baseline_qber_gt_tau_runs",
        "extended_qber_gt_tau_pct",
        "extended_qber_gt_tau_runs",
        "baseline_action",
        "extended_action",
    ]
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)



def write_json(output_json: Path, rows: list[dict[str, Any]]) -> None:
    summary = {
        "design_note": (
            "This file summarises repeated-run Monte Carlo results from "
            "extended_comparison_results.json. The source fields "
            "baseline_unsafe_pct and extended_unsafe_pct are reported here as the "
            "percentage of runs whose estimated QBER exceeded tau. For the extended "
            "model, those flagged runs are interpreted as abort-triggered sessions, "
            "not unsafe encrypted sessions."
        ),
        "n_conditions": len(rows),
        "noise_values": [row["p_noise"] for row in rows],
        "rows": rows,
    }
    with output_json.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)



def build_thesis_text(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""

    n_runs = rows[0]["n_runs"]
    tau = rows[0]["threshold_tau"]
    noise_values = ", ".join(f"{row['p_noise']:.3f}" for row in rows)

    baseline_flag_min = min(row["baseline_qber_gt_tau_pct"] for row in rows)
    baseline_flag_max = max(row["baseline_qber_gt_tau_pct"] for row in rows)
    extended_flag_min = min(row["extended_qber_gt_tau_pct"] for row in rows)
    extended_flag_max = max(row["extended_qber_gt_tau_pct"] for row in rows)

    return (
        "Repeated-Trial Monte Carlo Design\n"
        "The disturbance comparison experiment was executed as a repeated-trial Monte Carlo "
        f"simulation across {len(rows)} configured noise conditions (p_noise = {noise_values}). "
        f"For each condition, the full workflow was run {n_runs} independent times using fresh random "
        "bit strings, basis choices, sampled positions, and noise realisations. The QBER threshold was "
        f"held fixed at tau = {tau:.2f}. The reported results are aggregate statistics over these repeated runs.\n\n"
        "Interpretation Note\n"
        "In the source experiment file, the fields baseline_unsafe_pct and extended_unsafe_pct refer to the "
        "percentage of runs in which the estimated QBER exceeded tau. In the baseline model, such flagged runs "
        "would still proceed to encryption because no abort controller is active. In the extended model, the "
        "same flagged runs should be interpreted as abort-triggered sessions rather than unsafe encrypted sessions.\n\n"
        "Observed Range\n"
        f"Across the recorded conditions, the percentage of baseline runs with estimated QBER > tau ranged from "
        f"{baseline_flag_min:.2f}% to {baseline_flag_max:.2f}%. In the extended model, the percentage of runs with "
        f"estimated QBER > tau ranged from {extended_flag_min:.2f}% to {extended_flag_max:.2f}%; under Extension 1, "
        "these sessions are treated as abort-triggered outcomes."
    )



def write_text(output_txt: Path, text: str) -> None:
    with output_txt.open("w", encoding="utf-8") as f:
        f.write(text)



def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parent
    results_json = project_root / "extended_comparison_results.json"
    results_dir = project_root / "results"
    results_dir.mkdir(exist_ok=True)

    maybe_run_extended(project_root, should_run=args.run)
    raw_rows = load_results(results_json)
    rows = transform_rows(raw_rows)

    output_csv = results_dir / "montecarlo_summary.csv"
    output_json = results_dir / "montecarlo_summary.json"
    output_txt = results_dir / "montecarlo_summary_for_thesis.txt"

    write_csv(output_csv, rows)
    write_json(output_json, rows)
    write_text(output_txt, build_thesis_text(rows))

    print("[DONE] Monte Carlo summary files created:")
    print(f"  - {output_csv}")
    print(f"  - {output_json}")
    print(f"  - {output_txt}")


if __name__ == "__main__":
    main()
