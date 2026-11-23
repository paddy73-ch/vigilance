#!/bin/bash
# distribute_ssh_key_to_lxc.sh
# Distribute Vigilance SSH public key to all running LXCs via pct exec
# Run this once on the Proxmox host (192.0.2.49)
# After this, the Vigilance Discovery Scan will automatically find and scan all LXCs

VIGILANCE_SSH_PUB_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjAVtnlc+nFT5Aelji4hpGaWA+ghuOA7NDeovNWU4qu root@vigilance"

echo "=== Distributing Vigilance SSH key to all running LXCs ==="

# Get all running LXC VMIDs
vmid_list=$(pct list | awk 'NR>1 && $2=="running" {print $1}')

if [ -z "$vmid_list" ]; then
    echo "No running LXCs found."
    exit 0
fi

for vmid in $vmid_list; do
    name=$(pct config $vmid | awk '/^name:/ {print $2}')
    echo -n "Distributing key to $name (vmid=$vmid)... "
    
    # Create .ssh directory and add key
    pct exec $vmid -- mkdir -p /root/.ssh 2>/dev/null
    pct exec $vmid -- bash -c "echo '$VIGILANCE_SSH_PUB_KEY' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "OK"
    else
        echo "FAILED"
    fi
done

echo ""
echo "=== Done ==="
echo "You can now run the Discovery Scan:"
echo "  curl -X POST http://127.0.0.1:8000/api/scans/trigger"
echo ""
echo "The scan will automatically run every day at 02:00 UTC."
