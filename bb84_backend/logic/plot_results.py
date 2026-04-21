import pandas as pd
import matplotlib.pyplot as plt
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CSV_PATH = os.path.join(BASE_DIR, "results", "experiment_log.csv")
OUT_DIR = os.path.join(BASE_DIR, "results", "figures")
TAU = 0.11  # QBER threshold


def plot_qber_vs_noise(df):
    df = df.dropna(subset=["p_noise", "qber"])
    grouped = df.groupby("p_noise")["qber"].agg(["mean", "std"]).reset_index()
    grouped = grouped.sort_values("p_noise")

    plt.figure(figsize=(6.4, 3.8))
    plt.errorbar(grouped["p_noise"], grouped["mean"], yerr=grouped["std"].fillna(0),
                 fmt="o-", capsize=4, label="QBER")
    plt.axhline(TAU, color="r", linestyle="--", label=f"Threshold (τ={TAU})")
    plt.xlabel("Channel noise probability (p_noise)")
    plt.ylabel("QBER")
    plt.title("QBER vs Noise Probability")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "Fig_QBER_vs_Noise.png"), dpi=600)
    plt.savefig(os.path.join(OUT_DIR, "Fig_QBER_vs_Noise.pdf"))

def plot_key_quality_metrics(df):
    df = df.dropna(subset=["p_noise", "p1", "H_bin", "H_inf"])
    grouped = df.groupby("p_noise")[["p1", "H_bin", "H_inf"]].mean().reset_index()
    grouped = grouped.sort_values("p_noise")

    plt.figure(figsize=(6.4, 4.2))
    plt.plot(grouped["p_noise"], grouped["p1"], marker="o", label="Ones Ratio (p1)")
    plt.plot(grouped["p_noise"], grouped["H_bin"], marker="s", label="Binary Entropy (H_bin)")
    plt.plot(grouped["p_noise"], grouped["H_inf"], marker="^", label="Min-Entropy (H_inf)")
    plt.xlabel("Channel noise probability (p_noise)")
    plt.ylabel("Value")
    plt.title("Key Quality Metrics vs Noise Probability")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "Fig_KeyQuality_vs_Noise.png"), dpi=600)
    plt.savefig(os.path.join(OUT_DIR, "Fig_KeyQuality_vs_Noise.pdf"))

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    df = pd.read_csv(CSV_PATH)
    plot_qber_vs_noise(df)
    plot_key_quality_metrics(df)
    print(f"✅ Graphs saved in: {OUT_DIR}")

if __name__ == "__main__":
    main()
