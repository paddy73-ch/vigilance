#!/bin/sh
# Put Vigilance's SSH public key into /root/.ssh/authorized_keys of every running LXC container.
# Run on the Proxmox host as root. The key comes from Vigilance itself:
#   docker exec vigilance vigilance ssh-key-show      (or Verwaltung > Einstellungen > Proxmox und SSH)
#
#   sh distribute-ssh-key.sh 'ssh-ed25519 AAAA… vigilance@…'
#
# Adds the key only where it is missing. Remove an old key yourself (see `vigilance ssh-key-rotate`).
set -eu

KEY="${1:-}"
case "$KEY" in
  ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;;
  *) echo "usage: $0 '<public key from: vigilance ssh-key-show>'" >&2; exit 2 ;;
esac

for vmid in $(pct list | awk 'NR>1 && $2=="running" {print $1}'); do
  name=$(pct config "$vmid" | awk '/^hostname:/ {print $2}')
  printf '%s (CT %s): ' "${name:-?}" "$vmid"
  if pct exec "$vmid" -- sh -c '
      umask 077; mkdir -p /root/.ssh; touch /root/.ssh/authorized_keys
      if grep -qxF "$1" /root/.ssh/authorized_keys; then echo "already there"
      else printf "%s\n" "$1" >> /root/.ssh/authorized_keys && echo "added"; fi
      chmod 600 /root/.ssh/authorized_keys' _ "$KEY"; then :; else echo "FAILED"; fi
done
