#!/usr/bin/env python3
"""Synthetic integration consumer for descriptor-only delivery."""

import hashlib
import os
import sys


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    descriptor_text = os.environ.get("KILIX_SECRET_FD")
    if descriptor_text is None or not descriptor_text.isdecimal():
        return 3
    descriptor = int(descriptor_text)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 4096)
        if not chunk:
            break
        chunks.append(chunk)
    secret = b"".join(chunks)
    try:
        if hashlib.sha256(secret).hexdigest() != sys.argv[1]:
            return 4
        with open("/proc/self/cmdline", "rb") as handle:
            command_line = handle.read()
        with open("/proc/self/environ", "rb") as handle:
            environment = handle.read()
        if secret in command_line or secret in environment:
            return 5
        if not os.get_inheritable(descriptor):
            return 6
        print("consumer-ok")
        return 0
    finally:
        mutable = bytearray(secret)
        mutable[:] = b"\x00" * len(mutable)


if __name__ == "__main__":
    raise SystemExit(main())
