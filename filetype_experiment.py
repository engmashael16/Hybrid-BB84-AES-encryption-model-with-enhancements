# filetype_experiment.py
# Runs encrypt_file_local on 4 file types across 2 noise conditions

import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bb84_backend.logic.controller import encrypt_file_local

files = [
    ("Plain Text (10 KB)",   "test_text.txt",     10240),
    ("Document (200 KB)",    "test_document.txt", 204800),
    ("PDF-size (500 KB)",    "test_pdf.txt",      512000),
    ("Binary/Image (2 MB)", "test_image.bin",    2097152),
]

noise_conditions = [0.00, 0.10]

all_results = []

print("=" * 65)
print("FILE TYPE EXPERIMENT — Extended Pipeline (with Noise Conditions)")
print("=" * 65)

for p_noise in noise_conditions:
    print(f"\n{'='*65}")
    print(f"NOISE CONDITION: p_noise = {p_noise}")
    print(f"{'='*65}")

    for label, filename, expected_size in files:
        print(f"\n  Processing: {label} ({expected_size//1024} KB) ...")

        if not os.path.exists(filename):
            print(f"  ERROR: {filename} not found!")
            continue

        data = open(filename, "rb").read()
        actual_size = len(data)

        start = time.perf_counter()
        try:
            encrypted_b64, key_b_str = encrypt_file_local(data, filename, p_noise=p_noise)
            elapsed = round(time.perf_counter() - start, 4)

            enc_size = len(encrypted_b64.encode()) * 3 // 4
            expansion = round(enc_size / actual_size, 4)

            with open("bb84_metrics.json") as f:
                m = json.load(f)

            result = {
                "p_noise":        p_noise,
                "file_type":      label,
                "file_size_kb":   round(actual_size / 1024, 1),
                "enc_time_s":     elapsed,
                "expansion_ratio": expansion,
                "qber":           m.get("QBER", "N/A"),
                "qkd_abort":      m.get("QKD Abort", "N/A"),
                "key_a_length":   m.get("Key A Length", "N/A"),
                "bit_match_pct":  m.get("A/B Bit Match Percentage", "N/A"),
                "shannon_entropy": m.get("Estimated Shannon Entropy", "N/A"),
                "hmac_check":     m.get("HMAC Integrity Check", "N/A"),
                "pq_signature":   m.get("Post-Quantum Signature", "N/A"),
            }

            all_results.append(result)

            print(f"  File size:    {result['file_size_kb']} KB")
            print(f"  Enc time:     {elapsed} s")
            print(f"  Expansion:    {expansion}x")
            print(f"  QBER:         {result['qber']}")
            print(f"  QKD Abort:    {result['qkd_abort']}")
            print(f"  Bit Match:    {result['bit_match_pct']}%")
            print(f"  Shannon H:    {result['shannon_entropy']}")
            print(f"  HMAC:         {result['hmac_check']}")
            print(f"  PQ Signature: {result['pq_signature']}")

        except Exception as e:
            print(f"  ERROR: {e}")
            all_results.append({
                "p_noise": p_noise,
                "file_type": label,
                "error": str(e)
            })

with open("filetype_results.json", "w") as f:
    json.dump(all_results, f, indent=2)

print("\n" + "=" * 65)
print("DONE — Results saved to filetype_results.json")
print("=" * 65)