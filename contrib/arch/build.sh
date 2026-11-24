#!/usr/bin/env bash
# Build the Arch package, as a normal user on Arch (makepkg refuses root):
#
#   contrib/arch/build.sh [VERSION]
#
# writes target/packages/vault-server-VERSION-x86_64.pkg.tar.zst.
# Install it with: sudo pacman -U target/packages/vault-server-*.pkg.tar.zst
set -euo pipefail
cd "$(dirname "$0")"
ver=${1:-$(../package/version.sh)}
export VAULT_PKGVER=${ver//-/}
export VAULT_VERSION=$ver
rm -rf pkg src
# shellcheck disable=SC2086  # MAKEPKG_ARGS is a list of options
PKGDEST=$PWD/out makepkg --force --nodeps --noconfirm ${MAKEPKG_ARGS:-}
mkdir -p ../../target/packages
mv out/vault-server-*.pkg.tar.zst "../../target/packages/vault-server-$ver-x86_64.pkg.tar.zst"
rm -rf out pkg src
ls -l "../../target/packages/vault-server-$ver-x86_64.pkg.tar.zst"
