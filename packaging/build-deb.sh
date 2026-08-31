#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source_root=$(cd "$here/.." && pwd)
tmp_root=${TMPDIR:-/tmp}
output_dir=${OUTPUT_DIR:-$source_root/dist}
raw_version=$(tr -d '[:space:]' <"$source_root/VERSION")
package_version=${PACKAGE_VERSION:-${raw_version/-dev/~dev-1}}
architecture=$(dpkg-architecture -qDEB_HOST_ARCH)
multiarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH)
source_epoch=$(git -C "$source_root" show -s --format=%ct HEAD)
source_commit=$(git -C "$source_root" rev-parse 'HEAD^{commit}')
source_tree=$(git -C "$source_root" rev-parse 'HEAD^{tree}')

if test -n "$(git -C "$source_root" status --porcelain)" \
        && test "${ALLOW_DIRTY:-0}" != 1; then
    printf 'refusing package build from a dirty source tree\n' >&2
    exit 2
fi

case "$tmp_root" in
    /*) ;;
    *) printf 'TMPDIR must be absolute: %s\n' "$tmp_root" >&2; exit 2 ;;
esac
test -d "$tmp_root" && test ! -L "$tmp_root"
dpkg --validate-version "$package_version"
case "$architecture" in
    *[!a-z0-9-]*|'') printf 'invalid Debian architecture: %s\n' "$architecture" >&2; exit 2 ;;
esac

stage=$(mktemp -d -p "$tmp_root" ksec-deb.XXXXXX)
cleanup() {
    case "$stage" in
        "$tmp_root"/ksec-deb.*) rm -rf -- "$stage" ;;
        *) printf 'refusing unsafe cleanup path: %s\n' "$stage" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

package_root=$stage/root
build_dir=$source_root/build-deb
mkdir -p "$package_root" "$output_dir"

make -C "$source_root" clean BUILD="$build_dir"
make -C "$source_root" all BUILD="$build_dir" PREFIX=/usr
make -C "$source_root" install BUILD="$build_dir" PREFIX=/usr DESTDIR="$package_root"

# Debian's native library directory is multiarch. The upstream Makefile keeps a
# portable /usr/lib default, so move the package payload without changing local
# /usr/local installs.
mkdir -p "$package_root/usr/lib/$multiarch/pkgconfig"
mv "$package_root/usr/lib/libkilix-secrets.a" \
   "$package_root/usr/lib/libkilix-secrets.so" \
   "$package_root/usr/lib/libkilix-secrets.so.0" \
   "$package_root/usr/lib/$multiarch/"
mv "$package_root/usr/lib/pkgconfig/kilix-secrets.pc" \
   "$package_root/usr/lib/$multiarch/pkgconfig/"
rmdir "$package_root/usr/lib/pkgconfig"
sed -i "s|^libdir=.*|libdir=\${exec_prefix}/lib/$multiarch|" \
    "$package_root/usr/lib/$multiarch/pkgconfig/kilix-secrets.pc"

# The source unit follows PREFIX=/usr/local for developer installs. A Debian
# package owns /usr and must never retain that developer-only executable path.
service=$package_root/usr/lib/systemd/user/kilix-secrets.service
grep -qx 'ExecStart=/usr/local/bin/kilix-secretsd --systemd --data-dir %h/.local/share/kilix-secrets' "$service"
sed -i 's|^ExecStart=/usr/local/bin/|ExecStart=/usr/bin/|' "$service"
grep -qx 'ExecStart=/usr/bin/kilix-secretsd --systemd --data-dir %h/.local/share/kilix-secrets' "$service"

strip --strip-unneeded "$package_root/usr/bin/kilix-secrets" \
    "$package_root/usr/bin/kilix-secretsd" \
    "$package_root/usr/lib/$multiarch/libkilix-secrets.so.0"
strip --strip-debug "$package_root/usr/lib/$multiarch/libkilix-secrets.a"

mkdir -p "$package_root/DEBIAN"
find "$package_root" -type d -exec chmod 0755 {} +
installed_size=$(du -sk "$package_root/usr" | awk '{print $1}')
sed -e "s|@VERSION@|$package_version|g" \
    -e "s|@ARCHITECTURE@|$architecture|g" \
    -e "s|@INSTALLED_SIZE@|$installed_size|g" \
    -e "s|@SOURCE_COMMIT@|$source_commit|g" \
    -e "s|@SOURCE_TREE@|$source_tree|g" \
    "$here/control.in" >"$package_root/DEBIAN/control"
install -m 0644 "$here/triggers" "$package_root/DEBIAN/triggers"

(
    cd "$package_root"
    find usr -type f -print0 | LC_ALL=C sort -z | xargs -0 md5sum >DEBIAN/md5sums
)
find "$package_root" -depth -print0 | xargs -0 touch --no-dereference --date="@$source_epoch"

artifact=$output_dir/kilix-secrets_${package_version}_${architecture}.deb
SOURCE_DATE_EPOCH=$source_epoch dpkg-deb --build --root-owner-group \
    --uniform-compression --threads-max=1 -Zxz -z9 \
    "$package_root" "$artifact" >/dev/null
sha256sum "$artifact"
