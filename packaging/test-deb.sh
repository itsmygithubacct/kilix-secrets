#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp_root=${TMPDIR:-/tmp}
case "$tmp_root" in
    /*) ;;
    *) printf 'TMPDIR must be absolute: %s\n' "$tmp_root" >&2; exit 2 ;;
esac
test -d "$tmp_root" && test ! -L "$tmp_root"

scratch=$(mktemp -d -p "$tmp_root" ksec-deb-test.XXXXXX)
cleanup() {
    case "$scratch" in
        "$tmp_root"/ksec-deb-test.*) rm -rf -- "$scratch" ;;
        *) printf 'refusing unsafe cleanup path: %s\n' "$scratch" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

version_a=0.1.0~package-test-1
version_b=0.1.0~package-test-2
mkdir -p "$scratch/a" "$scratch/a-rebuilt" "$scratch/b" "$scratch/root"
TMPDIR=$tmp_root OUTPUT_DIR=$scratch/a PACKAGE_VERSION=$version_a ALLOW_DIRTY=1 \
    "$here/build-deb.sh" >/dev/null
TMPDIR=$tmp_root OUTPUT_DIR=$scratch/a-rebuilt PACKAGE_VERSION=$version_a ALLOW_DIRTY=1 \
    "$here/build-deb.sh" >/dev/null
package_a=$(find "$scratch/a" -maxdepth 1 -type f -name '*.deb' -print -quit)
package_a_rebuilt=$(find "$scratch/a-rebuilt" -maxdepth 1 -type f -name '*.deb' -print -quit)
test -n "$package_a" && test -n "$package_a_rebuilt"
cmp "$package_a" "$package_a_rebuilt"

test "$(dpkg-deb -f "$package_a" Package)" = kilix-secrets
test "$(dpkg-deb -f "$package_a" Version)" = "$version_a"
test "$(dpkg-deb -f "$package_a" Architecture)" = "$(dpkg-architecture -qDEB_HOST_ARCH)"
test "$(dpkg-deb -f "$package_a" X-Kilix-Source-Commit)" = \
    "$(git -C "$here/.." rev-parse 'HEAD^{commit}')"
test "$(dpkg-deb -f "$package_a" X-Kilix-Source-Tree)" = \
    "$(git -C "$here/.." rev-parse 'HEAD^{tree}')"
depends=$(dpkg-deb -f "$package_a" Depends)
case "$depends" in
    *libc6*libsodium23*libsystemd0*) ;;
    *) printf 'incomplete package dependency closure: %s\n' "$depends" >&2; exit 1 ;;
esac
dpkg-deb -e "$package_a" "$scratch/control"
grep -qx 'activate-noawait ldconfig' "$scratch/control/triggers"

dpkg-deb -x "$package_a" "$scratch/root"
multiarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH)
test -x "$scratch/root/usr/bin/kilix-secrets"
test -x "$scratch/root/usr/bin/kilix-secretsd"
test -f "$scratch/root/usr/lib/$multiarch/libkilix-secrets.so.0"
test -L "$scratch/root/usr/lib/$multiarch/libkilix-secrets.so"
test "$(readlink "$scratch/root/usr/lib/$multiarch/libkilix-secrets.so")" = libkilix-secrets.so.0
test -f "$scratch/root/usr/lib/$multiarch/libkilix-secrets.a"
test -f "$scratch/root/usr/include/kilix_secrets.h"
test -f "$scratch/root/usr/lib/$multiarch/pkgconfig/kilix-secrets.pc"
grep -qx "libdir=\${exec_prefix}/lib/$multiarch" \
    "$scratch/root/usr/lib/$multiarch/pkgconfig/kilix-secrets.pc"
grep -qx 'ExecStart=/usr/bin/kilix-secretsd --systemd --data-dir %h/.local/share/kilix-secrets' \
    "$scratch/root/usr/lib/systemd/user/kilix-secrets.service"
if grep -R -n -E --binary-files=without-match \
        '/usr/local|/home/[^/ ]+' "$scratch/root/usr"; then
    printf 'package payload contains a developer prefix or home path\n' >&2
    exit 1
fi

readelf -d "$scratch/root/usr/bin/kilix-secretsd" | grep -Eq 'libsodium\.so\.23'
readelf -d "$scratch/root/usr/bin/kilix-secretsd" | grep -Eq 'libsystemd\.so\.0'
readelf -d "$scratch/root/usr/lib/$multiarch/libkilix-secrets.so.0" | grep -Eq 'libsodium\.so\.23'
if readelf -d "$scratch/root/usr/lib/$multiarch/libkilix-secrets.so.0" | grep -Eq 'libsystemd\.so\.0'; then
    printf 'client library unexpectedly links libsystemd\n' >&2
    exit 1
fi

verify_dir=$scratch/verify-units
mkdir -p "$verify_dir"
sed 's|^ExecStart=/usr/bin/kilix-secretsd --systemd|ExecStart=/bin/true --systemd|' \
    "$scratch/root/usr/lib/systemd/user/kilix-secrets.service" >"$verify_dir/kilix-secrets.service"
cp "$scratch/root/usr/lib/systemd/user/kilix-secrets.socket" "$verify_dir/"
systemd-analyze verify "$verify_dir/kilix-secrets.socket" \
    "$verify_dir/kilix-secrets.service"

printf 'Debian package checks: 23/23 passed; reproducible builds: 2/2 identical\n'

# Exercise dpkg itself, not just archive extraction. There are deliberately no
# maintainer scripts: package removal and purge must never traverse user homes.
TMPDIR=$tmp_root OUTPUT_DIR=$scratch/b PACKAGE_VERSION=$version_b ALLOW_DIRTY=1 \
    "$here/build-deb.sh" >/dev/null
package_b=$(find "$scratch/b" -maxdepth 1 -type f -name '*.deb' -print -quit)
test -n "$package_b"
dpkg_root=$scratch/dpkg-root
admin_dir=$dpkg_root/var/lib/dpkg
dpkg_log=$dpkg_root/var/log/dpkg.log
dpkg_warnings=$scratch/dpkg-warnings.log
vault=$dpkg_root/synthetic-user-state/vault.ksv
mkdir -p "$admin_dir" "$dpkg_root/var/log" "$(dirname "$vault")"
: >"$admin_dir/status"
printf '%s\n' 'KSV-SYNTHETIC-ENCRYPTED-PRESERVATION-FIXTURE' >"$vault"
chmod 0600 "$vault"

dpkg --root="$dpkg_root" --log="$dpkg_log" --force-not-root --force-depends \
    --install "$package_a" >/dev/null 2>>"$dpkg_warnings"
test "$(dpkg-query --admindir="$admin_dir" -W -f='${Version}' kilix-secrets)" = "$version_a"
dpkg --root="$dpkg_root" --log="$dpkg_log" --force-not-root --force-depends \
    --install "$package_b" >/dev/null 2>>"$dpkg_warnings"
test "$(dpkg-query --admindir="$admin_dir" -W -f='${Version}' kilix-secrets)" = "$version_b"
dpkg --root="$dpkg_root" --log="$dpkg_log" --force-not-root --force-depends \
    --force-downgrade --install "$package_a" >/dev/null 2>>"$dpkg_warnings"
test "$(dpkg-query --admindir="$admin_dir" -W -f='${Version}' kilix-secrets)" = "$version_a"
dpkg --root="$dpkg_root" --log="$dpkg_log" --force-not-root \
    --remove kilix-secrets >/dev/null 2>>"$dpkg_warnings"
test ! -e "$dpkg_root/usr/bin/kilix-secrets"
test "$(cat "$vault")" = 'KSV-SYNTHETIC-ENCRYPTED-PRESERVATION-FIXTURE'
dpkg --root="$dpkg_root" --log="$dpkg_log" --force-not-root --force-depends \
    --install "$package_b" >/dev/null 2>>"$dpkg_warnings"
test -x "$dpkg_root/usr/bin/kilix-secretsd"
dpkg --root="$dpkg_root" --log="$dpkg_log" --force-not-root \
    --purge kilix-secrets >/dev/null 2>>"$dpkg_warnings"
test ! -e "$dpkg_root/usr/bin/kilix-secretsd"
test "$(cat "$vault")" = 'KSV-SYNTHETIC-ENCRYPTED-PRESERVATION-FIXTURE'
test "$(grep -c '^dpkg: kilix-secrets: dependency problems' "$dpkg_warnings")" = 4
test "$(grep -c '^dpkg: warning: downgrading kilix-secrets' "$dpkg_warnings")" = 1

printf 'dpkg lifecycle: install/upgrade/rollback/remove/reinstall/purge 6/6 passed; vault preservation 2/2 passed; expected isolated-root warnings 5/5\n'
