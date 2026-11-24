#!/usr/bin/env bash
# target/packages/vault-server-VERSION-linux-x86_64.tar.gz: the same files as the
# packages, laid out from the root of the file system. Install with
#   sudo tar -xzf vault-server-VERSION-linux-x86_64.tar.gz -C /
#   sudo systemd-sysusers && sudo systemctl daemon-reload
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
ver=${1:-$("$here/version.sh")}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$root/target/packages"
"$here/stage.sh" "$work"
out=$root/target/packages/vault-server-$ver-linux-x86_64.tar.gz
tar --owner=0 --group=0 --numeric-owner --sort=name --mtime='@0' -C "$work" -czf "$out" .
ls -l "$out"
