#!/usr/bin/env python3
"""Check the three kilix-secrets binary packages, then planted defects.

The good packages must pass. Each planted defect is one change to a copy of
those packages and must fail, naming the check that change exists to trip.
"""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


PACKAGES = ("kilix-secrets", "libkilix-secrets0", "libkilix-secrets-dev")
EXEC = ("ExecStart=/usr/bin/kilix-secretsd --systemd "
        "--data-dir %h/.local/share/kilix-secrets")


class Findings(Exception):
    def __init__(self, codes: list[str]) -> None:
        self.codes = codes
        super().__init__(", ".join(codes))


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=False, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=60, **kwargs)


def field(deb: Path, name: str) -> str:
    result = run(["dpkg-deb", "-f", str(deb), name])
    if result.returncode != 0:
        raise Findings([f"control-unreadable:{deb.name}:{name}"])
    return result.stdout.strip()


def members(deb: Path) -> set[str]:
    result = run(["dpkg-deb", "-c", str(deb)])
    if result.returncode != 0:
        raise Findings([f"members-unreadable:{deb.name}"])
    paths = set()
    for line in result.stdout.splitlines():
        # dpkg-deb -c: mode, owner, size, date, time, path
        path = line.split(None, 5)[-1]
        if " -> " in path:
            path = path.split(" -> ", 1)[0]
        paths.add(path[2:] if path.startswith("./") else path)
    return {item.lstrip("./") for item in paths}


def extract(deb: Path, root: Path) -> None:
    result = run(["dpkg-deb", "-x", str(deb), str(root)])
    if result.returncode != 0:
        raise Findings([f"extract-failed:{deb.name}"])
    control = root / "DEBIAN"
    control.mkdir(mode=0o755)
    unpacked = run(["dpkg-deb", "-e", str(deb), str(control)])
    if unpacked.returncode != 0:
        raise Findings([f"control-extract-failed:{deb.name}"])


def payload_text(root: Path) -> str:
    chunks = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if "DEBIAN" in path.parts:
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        chunks.append(data.decode("utf-8", "replace"))
    return "\n".join(chunks)


def check_tree(debs: dict[str, Path], roots: dict[str, Path]) -> list[str]:
    codes: list[str] = []

    def need(condition: bool, code: str) -> None:
        if not condition:
            codes.append(code)

    versions = {name: field(deb, "Version") for name, deb in debs.items()}
    arches = {name: field(deb, "Architecture") for name, deb in debs.items()}
    version = versions["kilix-secrets"]
    need(len(set(versions.values())) == 1 and version != "", "version-mismatch")
    need(len(set(arches.values())) == 1 and arches["kilix-secrets"] not in ("", "all"),
         "arch-mismatch")
    depends = field(debs["kilix-secrets"], "Depends")
    need(f"libkilix-secrets0 (= {version})" in depends, "daemon-depends")
    dev_depends = field(debs["libkilix-secrets-dev"], "Depends")
    need(f"libkilix-secrets0 (= {version})" in dev_depends, "dev-depends")
    breaks = field(debs["libkilix-secrets0"], "Breaks")
    replaces = field(debs["libkilix-secrets0"], "Replaces")
    need(f"kilix-secrets (<< {version})" in breaks
         and f"kilix-secrets (<< {version})" in replaces, "transition")

    daemon_root = roots["kilix-secrets"]
    lib_root = roots["libkilix-secrets0"]
    dev_root = roots["libkilix-secrets-dev"]
    multiarch = run(["dpkg-architecture", "-qDEB_HOST_MULTIARCH"]).stdout.strip()
    library = next(lib_root.glob("usr/lib/*/libkilix-secrets.so.0"), None)
    link = next(dev_root.glob("usr/lib/*/libkilix-secrets.so"), None)
    pc = next(dev_root.glob("usr/lib/*/pkgconfig/kilix-secrets.pc"), None)
    need(library is not None and library.is_file(), "library-missing")
    need(link is not None and link.is_symlink()
         and os.readlink(link) == "libkilix-secrets.so.0", "dev-link")
    need(pc is not None and pc.is_file()
         and f"libdir=${{exec_prefix}}/lib/{multiarch}" in pc.read_text(),
         "pkgconfig")
    unit = daemon_root / "usr/lib/systemd/user/kilix-secrets.service"
    need(unit.is_file() and EXEC in unit.read_text(), "execstart")
    wants = (daemon_root / "usr/lib/systemd/user/sockets.target.wants"
             / "kilix-secrets.socket")
    need(wants.is_symlink() and os.readlink(wants) == "../kilix-secrets.socket",
         "socket-enable")
    service_wants = list(daemon_root.glob(
        "usr/lib/systemd/user/*.wants/kilix-secrets.service"))
    need(service_wants == [], "service-enabled")
    need((daemon_root / "usr/bin/kilix-secretsd").is_file()
         and (daemon_root / "usr/bin/kilix-secrets").is_file(), "commands")
    need((dev_root / "usr/include/kilix_secrets.h").is_file(), "header")
    for root in roots.values():
        text = payload_text(root)
        need("/usr/local" not in text and "/home/" not in text, "developer-path")
    if library is not None and library.is_file():
        needed = run(["readelf", "-d", str(library)]).stdout
        need("libsystemd.so.0" not in needed and "libsodium.so.23" in needed,
             "library-linkage")
    daemon = daemon_root / "usr/bin/kilix-secretsd"
    if daemon.is_file():
        needed = run(["readelf", "-d", str(daemon)]).stdout
        need("libsystemd.so.0" in needed and "libsodium.so.23" in needed
             and "libkilix-secrets.so.0" not in needed, "daemon-linkage")
    return codes


def rebuild(root: Path, destination: Path) -> None:
    result = run([
        "dpkg-deb", "--build", "--root-owner-group", "--uniform-compression",
        str(root), str(destination),
    ])
    if result.returncode != 0:
        raise RuntimeError(result.stderr)


def plant(name: str, roots: dict[str, Path]) -> str:
    """Change one copy. Return the check code this change must trip."""
    daemon = roots["kilix-secrets"]
    library = roots["libkilix-secrets0"]
    dev = roots["libkilix-secrets-dev"]
    if name == "execstart":
        unit = daemon / "usr/lib/systemd/user/kilix-secrets.service"
        unit.write_text(unit.read_text().replace(
            "ExecStart=/usr/bin/", "ExecStart=/usr/local/bin/", 1))
        return "execstart"
    if name == "library-missing":
        found = next(library.glob("usr/lib/*/libkilix-secrets.so.0"))
        found.unlink()
        return "library-missing"
    if name == "dev-link":
        link = next(dev.glob("usr/lib/*/libkilix-secrets.so"))
        link.unlink()
        link.symlink_to("/usr/lib/libkilix-secrets.so.0")
        return "dev-link"
    if name == "pkgconfig":
        pc = next(dev.glob("usr/lib/*/pkgconfig/kilix-secrets.pc"))
        pc.write_text(pc.read_text().replace(
            "libdir=${exec_prefix}/lib/", "libdir=${exec_prefix}/lib"))
        return "pkgconfig"
    if name == "service-enabled":
        wants = daemon / "usr/lib/systemd/user/default.target.wants"
        wants.mkdir(parents=True)
        (wants / "kilix-secrets.service").symlink_to("../kilix-secrets.service")
        return "service-enabled"
    if name == "socket-enable":
        wants = (daemon / "usr/lib/systemd/user/sockets.target.wants"
                 / "kilix-secrets.socket")
        wants.unlink()
        return "socket-enable"
    if name == "developer-path":
        notice = daemon / "usr/share/doc/kilix-secrets/LICENSE"
        gzipped = daemon / "usr/share/doc/kilix-secrets/LICENSE.gz"
        if gzipped.is_file() and not notice.is_file():
            notice.write_bytes(gzip.decompress(gzipped.read_bytes()))
            gzipped.unlink()
        if not notice.is_file():
            raise RuntimeError("LICENSE missing before the developer-path plant")
        notice.write_text(notice.read_text() + "\n# /usr/local/bin/kilix-secretsd\n")
        return "developer-path"
    if name == "daemon-depends":
        control = daemon / "DEBIAN/control"
        control.write_text(control.read_text().replace(
            "libkilix-secrets0 (= ", "libkilix-secrets0 (>= ", 1))
        return "daemon-depends"
    raise RuntimeError(f"unknown plant {name}")


def prepare(debs: list[Path], root: Path) -> tuple[dict[str, Path], dict[str, Path]]:
    found: dict[str, Path] = {}
    for deb in debs:
        name = field(deb, "Package")
        if name not in PACKAGES:
            raise Findings([f"unexpected-package:{name}"])
        if name in found:
            raise Findings([f"duplicate-package:{name}"])
        found[name] = deb
    missing = [name for name in PACKAGES if name not in found]
    if missing:
        raise Findings([f"missing-package:{name}" for name in missing])
    roots = {}
    for name, deb in found.items():
        destination = root / name
        destination.mkdir(parents=True)
        extract(deb, destination)
        roots[name] = destination
    return found, roots


def copy_roots(roots: dict[str, Path], destination: Path) -> dict[str, Path]:
    copied = {}
    for name, root in roots.items():
        target = destination / name
        shutil.copytree(root, target, symlinks=True)
        copied[name] = target
    return copied


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("debs", nargs=3, type=Path)
    parser.add_argument("--skip-plants", action="store_true")
    options = parser.parse_args()
    scratch_parent = Path(os.environ.get("TMPDIR", "/tmp"))
    scratch = Path(tempfile.mkdtemp(prefix="ksec-split.", dir=scratch_parent))
    try:
        debs, roots = prepare(options.debs, scratch / "good")
        good = check_tree(debs, roots)
        if good:
            print("FAIL split: good packages: " + ", ".join(good), file=sys.stderr)
            return 1
        print("split check: good packages passed")
        if options.skip_plants:
            return 0
        plants = (
            "execstart", "library-missing", "dev-link", "pkgconfig",
            "service-enabled", "socket-enable", "developer-path",
            "daemon-depends",
        )
        for name in plants:
            planted_root = scratch / f"plant-{name}"
            planted_root.mkdir()
            copied = copy_roots(roots, planted_root)
            expected = plant(name, copied)
            rebuilt = {}
            out = scratch / f"out-{name}"
            out.mkdir()
            for package, tree in copied.items():
                deb = out / f"{package}.deb"
                rebuild(tree, deb)
                rebuilt[package] = deb
            codes = check_tree(rebuilt, copied)
            if expected not in codes:
                print(f"FAIL split: plant {name} expected {expected}, "
                      f"got {codes or 'nothing'}", file=sys.stderr)
                return 1
            print(f"split check: plant {name} caught ({expected})")
        print(f"split check: {len(plants)}/{len(plants)} planted defects caught")
        return 0
    except Findings as error:
        print(f"FAIL split: {error}", file=sys.stderr)
        return 1
    finally:
        if scratch.name.startswith("ksec-split."):
            shutil.rmtree(scratch)


if __name__ == "__main__":
    raise SystemExit(main())
