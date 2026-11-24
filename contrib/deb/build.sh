#!/usr/bin/env bash
# Build target/packages/vault-server_VERSION_amd64.deb from target/release/vault-server.
#
#   contrib/deb/build.sh [VERSION]
#
# A .deb is an ar archive of debian-binary, control.tar.gz and data.tar.gz, so
# this needs only ar, tar and gzip (no dpkg-deb), and builds the same on any
# Linux. The arch is amd64; for another, set DEB_ARCH.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
ver=${1:-$("$root/contrib/package/version.sh")}
arch=${DEB_ARCH:-amd64}
out=$root/target/packages
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/data" "$work/control" "$out"
"$root/contrib/package/stage.sh" "$work/data"
# Debian puts the docs under /usr/share/doc/PACKAGE and keeps licences there
# too, so move it.
mkdir -p "$work/data/usr/share/doc/vault-server"
mv "$work/data/usr/share/licenses/vault-server/LICENSE.md" "$work/data/usr/share/doc/vault-server/copyright"
rm -rf "$work/data/usr/share/licenses"
gzip -9n "$work/data/usr/share/doc/vault-server/"{release-notes,user-guide,how-it-works}.md

size=$(du -sk "$work/data" | cut -f1)
# The oldest glibc the program runs on is the newest symbol version it uses.
glibc=$(objdump -T "$work/data/usr/bin/vault-server" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1)
[ -n "$glibc" ] || { echo "build.sh: cannot read the glibc version of the program" >&2; exit 1; }
cat >"$work/control/control" <<CONTROL
Package: vault-server
Version: $ver
Section: net
Priority: optional
Architecture: $arch
Installed-Size: $size
Depends: libc6 (>= $glibc), systemd
Maintainer: Nishant <nishant.nkumar@gmail.com>
Homepage: https://github.com/nishantnkumar-cell/vault-server
Description: Sync and backup server for Secret Vault
 Keeps each vault's encrypted file for its devices, speaks the Secret Vault
 sync API 1 over TLS 1.3 with post-quantum key exchange (X25519MLKEM768), has
 its own certificate authority, keeps version history and makes sealed
 backups. It never has a key to any vault.
CONTROL
echo /etc/vault-server/env >"$work/control/conffiles"
for s in postinst prerm postrm; do install -m755 "$here/$s" "$work/control/$s"; done
(cd "$work/data" && find . -type f -exec md5sum {} + | sed 's| \./| |' | LC_ALL=C sort -k2) >"$work/control/md5sums"

tar_opts=(--owner=0 --group=0 --numeric-owner --sort=name --mtime='@0' --format=gnu)
(cd "$work/control" && tar "${tar_opts[@]}" -czf ../control.tar.gz .)
(cd "$work/data" && tar "${tar_opts[@]}" -czf ../data.tar.gz .)
echo 2.0 >"$work/debian-binary"
deb=$out/vault-server_${ver}_${arch}.deb
rm -f "$deb"
(cd "$work" && ar rcD "$deb" debian-binary control.tar.gz data.tar.gz)
ls -l "$deb"
