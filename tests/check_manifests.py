#!/usr/bin/env python3
"""Fail closed on baseline, vector, or negative-corpus manifest drift."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys


HEX64 = re.compile(r"^[0-9a-f]{64}$")


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            hasher.update(block)
    return hasher.hexdigest()


def read_manifest(root: Path, manifest_name: str,
                  expected_paths: list[Path]) -> tuple[int, int]:
    manifest = root / manifest_name
    lines = manifest.read_text(encoding="ascii").splitlines()
    entries: list[tuple[str, Path]] = []
    for line in lines:
        checksum, separator, name = line.partition("  ")
        if not separator or not HEX64.fullmatch(checksum):
            raise ValueError(f"invalid manifest line in {manifest_name}")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe manifest path in {manifest_name}")
        entries.append((checksum, relative))
    listed = [relative for _, relative in entries]
    if listed != sorted(listed, key=lambda item: item.as_posix()):
        raise ValueError(f"unsorted manifest: {manifest_name}")
    if listed != expected_paths:
        raise ValueError(f"manifest population mismatch: {manifest_name}")
    passed = 0
    for checksum, relative in entries:
        target = root / relative
        if target.is_symlink() or not target.is_file():
            continue
        if digest(target) == checksum:
            passed += 1
    return passed, len(entries)


def read_baseline(repository: Path) -> tuple[int, int]:
    values: dict[str, str] = {}
    for line in (repository / "BASELINE.sha256").read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values or not HEX64.fullmatch(value):
            raise ValueError("invalid baseline digest record")
        values[key] = value
    expected = {
        "A112_REPORT_SHA256":
            "70ad72d578aa4ccdd81f87cc8d45b4b3360ae80052297c4b2927a3034e2eafb2",
        "IMPLEMENTATION_BASELINE_SHA256":
            digest(repository / "docs" / "IMPLEMENTATION-BASELINE.md"),
    }
    passed = sum(values.get(key) == value for key, value in expected.items())
    return passed, len(expected)


def main() -> int:
    tests = Path(__file__).resolve().parent
    repository = tests.parent
    try:
        vectors = sorted((path.relative_to(tests)
                          for path in (tests / "vectors").iterdir()
                          if path.is_file() and not path.is_symlink()),
                         key=lambda item: item.as_posix())
        corpus = sorted((path.relative_to(tests)
                         for path in (tests / "corpus").glob("*.case")),
                        key=lambda item: item.as_posix())
        baseline_passed, baseline_total = read_baseline(repository)
        vector_passed, vector_total = read_manifest(tests, "VECTORS.sha256", vectors)
        corpus_passed, corpus_total = read_manifest(tests, "CORPUS.sha256", corpus)
    except (OSError, ValueError) as error:
        print(f"manifest failure: {error}", file=sys.stderr)
        return 1
    print(f"baseline digests: {baseline_passed}/{baseline_total} verified")
    print(f"vector manifest: {vector_passed}/{vector_total} verified")
    print(f"corpus manifest: {corpus_passed}/{corpus_total} verified")
    return 0 if (baseline_passed == baseline_total
                 and vector_passed == vector_total
                 and corpus_passed == corpus_total) else 1


if __name__ == "__main__":
    raise SystemExit(main())
