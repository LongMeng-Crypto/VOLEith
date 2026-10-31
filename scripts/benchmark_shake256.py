#!/usr/bin/env python3
"""Independent VOLEith SHAKE256 baseline, with no UOV dependency."""
import argparse
import csv
import json
from pathlib import Path
import subprocess

def main():
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser()
    p.add_argument('--input-bits', type=int, default=384)
    p.add_argument('--output-bits', type=int, nargs='+', default=[256, 360])
    p.add_argument('--security', type=int, nargs='+', default=[128, 192, 256])
    p.add_argument('--profile', choices=['s', 'f', 'both'], default='both')
    p.add_argument('--iterations', type=int, default=20)
    p.add_argument('--output', type=Path, default=root / 'build-release/shake-benchmarks')
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rows = []
    for output_bits in args.output_bits:
        for security in args.security:
            for profile in (['s', 'f'] if args.profile == 'both' else [args.profile]):
                cmd = [root / 'build-release/vole-shake256', '--input-bits', args.input_bits,
                       '--output-bits', output_bits, '--security', security, '--profile', profile,
                       '--iterations', args.iterations]
                result = json.loads(subprocess.check_output([str(x) for x in cmd], text=True))
                rows.append(result)
                (args.output / f'shake-{output_bits}-{security}{profile}.json').write_text(json.dumps(result, indent=2) + '\n')
                print(f'{output_bits} bits, {security}{profile}: prove {result["prover_median_ms"]:.3f} ms, verify {result["verifier_median_ms"]:.3f} ms, {result["proof_bytes"]} B', flush=True)
    keys = ['output_bits', 'security_bits', 'profile', 'prover_median_ms',
            'verifier_median_ms', 'proof_bytes', 'and_gates', 'witness_bits_logical']
    with (args.output / 'summary.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, keys, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)

if __name__ == '__main__':
    main()
