#!/usr/bin/env python3
"""Verify the persistent parser corpus and run deterministic mutations."""

from __future__ import annotations

import argparse
from pathlib import Path
import random
import struct
import subprocess
import sys


def read_case(path: Path) -> tuple[str, bytes]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise ValueError(f"invalid case syntax: {path.name}")
        values[key] = value
    if set(values) != {"kind", "hex"}:
        raise ValueError(f"invalid case fields: {path.name}")
    if values["kind"] not in {"protocol", "header", "record", "ad", "backup"}:
        raise ValueError(f"invalid parser kind: {path.name}")
    return values["kind"], bytes.fromhex(values["hex"])


def mutate(randomizer: random.Random, seed: bytes) -> bytes:
    data = bytearray(seed)
    operation = randomizer.randrange(5)
    if operation == 0 and data:
        del data[randomizer.randrange(len(data)):]
    elif operation == 1 and data:
        data[randomizer.randrange(len(data))] ^= 1 << randomizer.randrange(8)
    elif operation == 2:
        position = randomizer.randrange(len(data) + 1)
        data[position:position] = randomizer.randbytes(randomizer.randrange(1, 17))
    elif operation == 3 and data:
        start = randomizer.randrange(len(data))
        stop = min(len(data), start + randomizer.randrange(1, 17))
        data[start:stop] = randomizer.randbytes(stop - start)
    else:
        data = bytearray(randomizer.randbytes(randomizer.randrange(0, 513)))
    return bytes(data[:4096])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--cases", type=int, required=True)
    options = parser.parse_args()
    if options.cases <= 0:
        return 2
    harness = Path(options.build_dir).resolve() / "parser-harness"
    corpus_paths = sorted(Path(__file__).with_name("corpus").glob("*.case"))
    passed = 0
    seeds: list[bytes] = []
    for path in corpus_paths:
        try:
            kind, data = read_case(path)
        except (ValueError, OSError) as error:
            print(str(error), file=sys.stderr)
            continue
        completed = subprocess.run([str(harness), f"{kind}-reject"], input=data,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, check=False, timeout=10)
        if completed.returncode == 0:
            passed += 1
        else:
            print(f"FAIL corpus: {path.name}", file=sys.stderr)
        seeds.append(data)
    print(f"negative corpus: {passed}/{len(corpus_paths)} rejected")
    if passed != len(corpus_paths) or not seeds:
        return 1

    randomizer = random.Random(112)
    framed = bytearray()
    for index in range(options.cases):
        item = mutate(randomizer, seeds[index % len(seeds)])
        framed.extend(struct.pack(">I", len(item)))
        framed.extend(item)
    completed = subprocess.run([str(harness), "stream"], input=framed,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               check=False, timeout=120)
    if completed.returncode != 0:
        print("FAIL deterministic mutation stream", file=sys.stderr)
        return 1
    print(f"deterministic mutations: {options.cases}/{options.cases} processed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
