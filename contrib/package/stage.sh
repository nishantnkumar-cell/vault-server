#!/usr/bin/env bash
# Lay out the files of a vault-server package under DEST, for the .deb, the
# Arch package and the .tar.gz alike, so they cannot drift apart.
#
#   contrib/package/stage.sh DEST [BINARY]       (default target/release/vault-server)
#
# The service file is the one in contrib/systemd with the path of the program
# changed from /usr/local/bin (a hand install) to /usr/bin (a package).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
dest=${1:?usage: stage.sh DEST [BINARY]}
bin=${2:-$root/target/release/vault-server}
[ -x "$bin" ] || { echo "stage.sh: $bin is not built (cargo build --release --locked)" >&2; exit 1; }

install -Dm755 "$bin" "$dest/usr/bin/vault-server"
sed 's|/usr/local/bin/vault-server|/usr/bin/vault-server|' "$root/contrib/systemd/vault-server.service" \
    | install -Dm644 /dev/stdin "$dest/usr/lib/systemd/system/vault-server.service"
install -Dm644 "$root/contrib/sysusers.d/vault-server.conf" "$dest/usr/lib/sysusers.d/vault-server.conf"
# Read by systemd as root; may hold the admin key, so root only.
install -Dm600 "$here/env" "$dest/etc/vault-server/env"
for f in README.md docs/user-guide.md docs/how-it-works.md docs/release-notes.md; do
    install -Dm644 "$root/$f" "$dest/usr/share/doc/vault-server/$(basename "$f")"
done
install -Dm644 "$root/LICENSE.md" "$dest/usr/share/licenses/vault-server/LICENSE.md"
