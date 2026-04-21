# bb84_quantum.py
# BB84 Quantum Key Distribution using Qiskit AerSimulator with optional post-quantum authentication.
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from typing import List, Tuple, Dict, Optional
import secrets
import random

# Optional: Post-quantum authentication (fallback if not available)
try:
    from dilithium import Dilithium, parameter_sets
    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False


def generate_random_bits(length: int) -> List[int]:
    """
    Generates a secure random bitstring of given length using system entropy.
    """
    return [secrets.randbits(1) for _ in range(length)]


def generate_random_bases(length: int) -> List[str]:
    """
    Randomly assigns measurement bases ('Z' or 'X') for each qubit.
    """
    return [secrets.choice(['Z', 'X']) for _ in range(length)]


def measure_qubit(bit: int, basis: str, measure_basis: str) -> int:
    """
    Simulates the quantum measurement of a single qubit using Qiskit AerSimulator.
    """
    circuit = QuantumCircuit(1, 1)

    if bit == 1:
        circuit.x(0)
    if basis == 'X':
        circuit.h(0)

    if measure_basis == 'X':
        circuit.h(0)
    circuit.measure(0, 0)

    simulator = AerSimulator()
    result = simulator.run(circuit, shots=1).result()
    counts = result.get_counts()

    return int(max(counts, key=counts.get))


def apply_bitflip_noise(bit: int, p_noise: float, rng: random.Random) -> int:
    """
    Simulates channel noise by flipping the bit with probability p_noise.
    """
    if p_noise <= 0.0:
        return bit
    return 1 - bit if rng.random() < p_noise else bit


def estimate_qber(
    alice_sifted: List[int],
    bob_sifted: List[int],
    sample_frac: float,
    rng: random.Random
) -> Tuple[float, List[int], List[int], int, int]:
    """
    Estimates QBER by disclosing a random subset of sifted bits, then removes them
    from the final key material.

    Returns:
        qber, alice_final, bob_final, sample_size, mismatches
    """
    n = len(alice_sifted)
    if n == 0:
        return 0.0, alice_sifted, bob_sifted, 0, 0

    # clamp sample fraction to [0,1]
    if sample_frac < 0.0:
        sample_frac = 0.0
    if sample_frac > 1.0:
        sample_frac = 1.0

    sample_size = max(1, int(sample_frac * n))
    indices = set(rng.sample(range(n), sample_size))

    mismatches = sum(1 for i in indices if alice_sifted[i] != bob_sifted[i])
    qber = mismatches / sample_size

    alice_final = [b for i, b in enumerate(alice_sifted) if i not in indices]
    bob_final = [b for i, b in enumerate(bob_sifted) if i not in indices]

    return qber, alice_final, bob_final, sample_size, mismatches


def bb84_protocol(
    length: int = 128,
    authenticate: bool = False,
    p_noise: float = 0.0,
    qber_sample_frac: float = 0.2,
    qber_threshold: float = 0.11,
    seed: Optional[int] = None
) -> Tuple[List[int], List[int], Optional[bytes], Dict]:
    """
    Runs the BB84 protocol simulation and returns keys + optional post-quantum signature
    + QBER information.

    Args:
        length: Number of qubits to simulate.
        authenticate: If True, perform post-quantum authentication using Dilithium (if available).
        p_noise: Probability of a bit-flip on Bob's measurement outcome (simulated channel noise).
        qber_sample_frac: Fraction of sifted bits disclosed to estimate QBER.
        qber_threshold: Abort if QBER exceeds this threshold.
        seed: Optional RNG seed for reproducibility in sampling/noise.

    Returns:
        (key_alice_final, key_bob_final, signature, qkd_info)
    """
    rng = random.Random(seed)

    alice_bits = generate_random_bits(length)
    alice_bases = generate_random_bases(length)
    bob_bases = generate_random_bases(length)

    # Bob measures, with optional noise applied to his measurement outcome
    bob_results: List[int] = []
    for bit, prep_basis, measure_basis in zip(alice_bits, alice_bases, bob_bases):
        measured = measure_qubit(bit, prep_basis, measure_basis)
        measured = apply_bitflip_noise(measured, p_noise, rng)
        bob_results.append(measured)

    # Sifting: keep positions where bases match
    matching_indices = [i for i in range(length) if alice_bases[i] == bob_bases[i]]
    key_alice = [alice_bits[i] for i in matching_indices]
    key_bob = [bob_results[i] for i in matching_indices]

    # Optional post-quantum authentication (same spirit as original code)
    signature: Optional[bytes] = None
    if authenticate and PQCRYPTO_AVAILABLE:
        public_data = "".join(alice_bases).encode("utf-8")
        dil = Dilithium(parameter_set=parameter_sets["Dilithium5"])
        pk, sk = dil.generate_keypair()
        signature = dil.sign(public_data, sk)
        if not dil.verify(public_data, signature, pk):
            raise ValueError("Post-quantum signature verification failed.")

    # QBER estimation (sample-based) after sifting
    qber, key_alice_final, key_bob_final, sample_size, mismatches = estimate_qber(
        key_alice, key_bob, sample_frac=qber_sample_frac, rng=rng
    )

    abort = qber > qber_threshold

    qkd_info = {
        "QBER": round(qber, 6),
        "QBER Threshold": qber_threshold,
        "QBER Sample Fraction": qber_sample_frac,
        "QBER Sample Size": sample_size,
        "QBER Mismatches": mismatches,
        "QKD Abort": abort,
        "Channel Noise Probability": p_noise,
        "Matching Indices Count": len(matching_indices)
    }

    return key_alice_final, key_bob_final, signature, qkd_info
