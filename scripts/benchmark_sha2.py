#!/usr/bin/env python3
"""Benchmark visibility-aware SHA-256/384/512 circuits through VOLEith."""

from __future__ import annotations

import argparse
import hashlib
import secrets
import shlex
import subprocess
import tempfile
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class AlgorithmProfile:
    name: str
    digest_name: str
    export_command: str
    partition_command: str
    digest_output_key: str
    block_bits: int
    length_field_bits: int
    maximum_message_bytes: int
    daa_message_bytes: int
    daa_secret_bits: int
    all_secret_message_bytes: int
    security_bits: int

    @property
    def daa_layout(self) -> str:
        total_bits = self.daa_message_bytes * 8
        return (
            f"secret:0:{self.daa_secret_bits},"
            f"public:{self.daa_secret_bits}:{total_bits}"
        )


PROFILES = {
    "sha256": AlgorithmProfile(
        name="sha256",
        digest_name="sha256",
        export_command="export-sha256-circuit",
        partition_command="sha256-partition-input",
        digest_output_key="public_sha256",
        block_bits=512,
        length_field_bits=64,
        maximum_message_bytes=550,
        daa_message_bytes=48,
        daa_secret_bits=128,
        all_secret_message_bytes=55,
        security_bits=128,
    ),
    "sha384": AlgorithmProfile(
        name="sha384",
        digest_name="sha384",
        export_command="export-sha384-circuit",
        partition_command="sha384-partition-input",
        digest_output_key="public_sha384",
        block_bits=1024,
        length_field_bits=128,
        maximum_message_bytes=1100,
        daa_message_bytes=72,
        daa_secret_bits=192,
        all_secret_message_bytes=72,
        security_bits=192,
    ),
    "sha512": AlgorithmProfile(
        name="sha512",
        digest_name="sha512",
        export_command="export-sha512-circuit",
        partition_command="sha512-partition-input",
        digest_output_key="public_sha512",
        block_bits=1024,
        length_field_bits=128,
        maximum_message_bytes=1100,
        daa_message_bytes=96,
        daa_secret_bits=256,
        all_secret_message_bytes=96,
        security_bits=256,
    ),
}


def parse_key_values(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def run_command(command: list[str]) -> str:
    print(f"$ {shlex.join(command)}", flush=True)
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if completed.stderr:
        print(completed.stderr, end="" if completed.stderr.endswith("\n") else "\n")
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed with exit status {completed.returncode}: "
            f"{shlex.join(command)}"
        )
    return completed.stdout


def selected_profiles(name: str) -> list[AlgorithmProfile]:
    if name == "all":
        return [PROFILES[algorithm] for algorithm in ("sha256", "sha384", "sha512")]
    return [PROFILES[name]]


def message_and_layout(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    profile: AlgorithmProfile,
) -> tuple[bytes, str]:
    if args.message_hex is not None:
        try:
            message = bytes.fromhex(args.message_hex)
        except ValueError as error:
            parser.error(f"--message-hex is invalid: {error}")
        if args.message_bytes is not None and len(message) != args.message_bytes:
            parser.error("--message-hex length does not match --message-bytes")
        message_bytes = len(message)
    else:
        if args.message_bytes is not None:
            message_bytes = args.message_bytes
        elif args.profile == "daa":
            message_bytes = profile.daa_message_bytes
        else:
            message_bytes = profile.all_secret_message_bytes
        message = secrets.token_bytes(message_bytes)

    if not 0 <= message_bytes <= profile.maximum_message_bytes:
        parser.error(
            f"{profile.name} message length must be between 0 and "
            f"{profile.maximum_message_bytes} bytes"
        )

    if args.input_layout_bits is not None:
        layout = args.input_layout_bits
    elif args.profile == "all-secret":
        layout = f"secret:0:{message_bytes * 8}" if message_bytes else ""
    elif message_bytes == profile.daa_message_bytes:
        layout = profile.daa_layout
    else:
        parser.error(
            "a custom DAA-profile message length requires --input-layout-bits; "
            "alternatively select --profile all-secret"
        )
    return message, layout


def benchmark_profile(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    binary: Path,
    workspace: Path,
    profile: AlgorithmProfile,
) -> dict[str, str]:
    message, layout = message_and_layout(parser, args, profile)
    message_hex = message.hex()
    digest_hex = hashlib.new(profile.digest_name, message).hexdigest()
    security_bits = args.security or profile.security_bits
    message_bits = len(message) * 8
    compression_blocks = (
        message_bits
        + 1
        + profile.length_field_bits
        + profile.block_bits
        - 1
    ) // profile.block_bits
    circuit_path = workspace / (
        f"{profile.name}-{len(message)}-bytes-{security_bits}.vbc"
    )

    print(f"\n[{profile.name}_configuration]")
    print(f"algorithm={profile.name}")
    print(f"message_bytes={len(message)}")
    print(f"message_bits={message_bits}")
    print(f"input_layout_bits={layout}")
    print(f"compression_block_bits={profile.block_bits}")
    print(f"compression_blocks={compression_blocks}")
    print(f"knowledge_soundness_bits={security_bits}")
    print(f"complete_message_hex={message_hex}")
    print(f"public_{profile.name}={digest_hex}")

    export_command = [
        str(binary),
        profile.export_command,
        "--message-length",
        str(len(message)),
        "--input-layout-bits",
        layout,
        "--circuit",
        str(circuit_path),
    ]
    export_values = parse_key_values(run_command(export_command))
    reported_blocks = export_values.get("sha2_blocks")
    if reported_blocks is not None and int(reported_blocks) != compression_blocks:
        raise RuntimeError("frontend compression-block count disagrees with script")

    partition_command = [
        str(binary),
        profile.partition_command,
        "--message-hex",
        message_hex,
        "--input-layout-bits",
        layout,
    ]
    partition_values = parse_key_values(run_command(partition_command))
    if partition_values.get(profile.digest_output_key) != digest_hex:
        raise RuntimeError(
            f"{profile.name} circuit digest disagrees with Python hashlib"
        )

    private_input_hex = partition_values.get("private_input_hex", "")
    public_input_hex = partition_values.get("public_input_hex", "")
    private_input_bits = int(partition_values["private_input_bits"])
    public_input_bits = int(partition_values["public_input_bits"])

    benchmark_command = [
        str(binary),
        "circuit-benchmark",
        "--circuit",
        str(circuit_path),
    ]
    if private_input_bits:
        benchmark_command.extend(["--private-input-hex", private_input_hex])
    if public_input_bits:
        benchmark_command.extend(["--public-input-hex", public_input_hex])
    benchmark_command.extend(
        [
            "--expected-output-hex",
            digest_hex,
            "--context",
            f"{args.context_prefix}-{profile.name}-v1",
            "--security",
            str(security_bits),
            "--iterations",
            str(args.iterations),
        ]
    )
    benchmark_values = parse_key_values(run_command(benchmark_command))
    benchmark_values.update(
        {
            "algorithm": profile.name,
            "message_bytes": str(len(message)),
            "input_layout_bits": layout,
            "compression_blocks": str(compression_blocks),
            "knowledge_soundness_bits": str(security_bits),
        }
    )
    return benchmark_values


def workspace_context(artifacts_dir: Path | None) -> Iterator[Path]:
    if artifacts_dir is None:
        return tempfile.TemporaryDirectory(prefix="voleith-sha2-benchmark-")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    return nullcontext(artifacts_dir)


def main() -> int:
    source_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark SHA-256/384/512 BinaryCircuit proofs with explicit "
            "visibility, compression-block, and VOLEith security profiles."
        )
    )
    parser.add_argument(
        "--algorithm",
        choices=("all", "sha256", "sha384", "sha512"),
        default="all",
        help="hash algorithm to benchmark (default: all)",
    )
    parser.add_argument(
        "--profile",
        choices=("daa", "all-secret"),
        default="daa",
        help=(
            "daa uses secret-prefix/public-suffix inputs; all-secret uses the "
            "legacy SHA-256 length and DAA SHA-384/SHA-512 lengths"
        ),
    )
    parser.add_argument("--iterations", "-n", type=int, default=10)
    parser.add_argument(
        "--binary",
        type=Path,
        default=source_root / "build-release" / "vole-sha256",
        help="path to the built VOLEith CLI",
    )
    parser.add_argument(
        "--message-bytes",
        type=int,
        help="override message length (single-algorithm mode only)",
    )
    parser.add_argument(
        "--message-hex",
        help="use this complete message instead of random bytes (single algorithm only)",
    )
    parser.add_argument(
        "--input-layout-bits",
        help=(
            "override the complete visibility partition, for example "
            "secret:0:128,public:128:384 (single algorithm only)"
        ),
    )
    parser.add_argument(
        "--security",
        type=int,
        choices=(128, 192, 256),
        help="override VOLEith knowledge soundness (single algorithm only)",
    )
    parser.add_argument(
        "--context-prefix", default="sha2-benchmark", help="Fiat-Shamir context prefix"
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        help="keep generated VBC files in this directory instead of a temporary directory",
    )
    args = parser.parse_args()

    if args.iterations <= 0:
        parser.error("--iterations must be positive")
    if args.algorithm == "all" and any(
        value is not None
        for value in (
            args.message_bytes,
            args.message_hex,
            args.input_layout_bits,
            args.security,
        )
    ):
        parser.error(
            "message, visibility, and security overrides require a single --algorithm"
        )

    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(
            f"CLI binary not found: {binary}; compile build-release first"
        )
    artifacts_dir = (
        args.artifacts_dir.expanduser().resolve()
        if args.artifacts_dir is not None
        else None
    )

    results: list[dict[str, str]] = []
    with workspace_context(artifacts_dir) as workspace_name:
        workspace = Path(workspace_name)
        for profile in selected_profiles(args.algorithm):
            results.append(
                benchmark_profile(parser, args, binary, workspace, profile)
            )

    print("\n[combined_summary]")
    for result in results:
        print(
            " ".join(
                [
                    f"algorithm={result['algorithm']}",
                    f"message_bytes={result['message_bytes']}",
                    f"blocks={result['compression_blocks']}",
                    f"layout={result['input_layout_bits']}",
                    f"security={result['knowledge_soundness_bits']}",
                    f"private_bits={result['private_input_bits']}",
                    f"public_bits={result['public_input_bits']}",
                    f"and_gates={result['multiplication_gates']}",
                    f"proof_bytes={result['proof_bytes']}",
                    f"prove_mean_ms={result['prove_mean_ms']}",
                    f"verify_mean_ms={result['verify_mean_ms']}",
                ]
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
