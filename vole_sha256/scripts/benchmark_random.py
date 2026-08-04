#!/usr/bin/env python3
"""Run the in-process C++ benchmark with a fresh random message per sample."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def main() -> int:
    source_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Benchmark random 0..550-byte secrets using the C++ benchmark timing boundaries."
    )
    parser.add_argument("--iterations", "-n", type=int, default=5)
    parser.add_argument(
        "--binary",
        type=Path,
        default=source_root / "build-release" / "vole-sha256",
        help="path to the vole-sha256 CLI",
    )
    parser.add_argument("--context", default="random-benchmark-v1")
    parser.add_argument("--message-bytes", type=int, default=55)
    args = parser.parse_args()

    if args.iterations <= 0:
        parser.error("--iterations must be positive")
    if not 0 <= args.message_bytes <= 550:
        parser.error("--message-bytes must be between 0 and 550")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"CLI binary not found: {binary}; build the release target first")

    command = [
        str(binary),
        "benchmark",
        "--iterations",
        str(args.iterations),
        "--context",
        args.context,
        "--message-bytes",
        str(args.message_bytes),
        "--random-messages",
        "true",
        "--print-samples",
        "true",
    ]
    os.execv(str(binary), command)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
