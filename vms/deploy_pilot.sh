#!/usr/bin/env bash
# One-shot deployer for the Bedrock Echo pilot.
# Deploys the Rust witness binary to bec-witness, Python node package to both
# bec-node-*, and prints the config the harness should use.
#
# Dependencies: ssh keys already work to each node, both nodes booted.

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
ssh_ok() { ssh $SSH_OPTS "root@$1" true 2>/dev/null; }

# ── Discover VM IPs ────────────────────────────────────────────────────────

mgmt_ip() {
    local vm=$1
    local mac
    mac=$(sudo virsh domiflist "$vm" 2>/dev/null | awk '/bedrock-mgmt/ {print $5}')
    [ -z "$mac" ] && return 1
    sudo ip neigh | awk -v m="$mac" 'tolower($5)==m && $4=="lladdr" {print $1; exit}'
}

WITNESS_IP=$(mgmt_ip bec-witness); echo "bec-witness: $WITNESS_IP"
NODE_A_IP=$(mgmt_ip bec-node-a);   echo "bec-node-a:  $NODE_A_IP"
NODE_B_IP=$(mgmt_ip bec-node-b);   echo "bec-node-b:  $NODE_B_IP"
for ip in "$WITNESS_IP" "$NODE_A_IP" "$NODE_B_IP"; do
    [ -z "$ip" ] && { echo "missing IP — VMs may still be booting"; exit 1; }
done
for ip in "$WITNESS_IP" "$NODE_A_IP" "$NODE_B_IP"; do
    ssh_ok "$ip" || { echo "ssh to $ip failed"; exit 1; }
done

# ── Deploy witness binary (if changed) ─────────────────────────────────────

echo "=== deploying Rust witness to bec-witness ==="
ssh $SSH_OPTS "root@$WITNESS_IP" 'systemctl stop bedrock-echo-witness 2>/dev/null || true'
scp $SSH_OPTS "$REPO/target/release/bedrock-echo-witness" "root@$WITNESS_IP:/usr/local/bin/"
ssh $SSH_OPTS "root@$WITNESS_IP" 'chmod +x /usr/local/bin/bedrock-echo-witness && systemctl daemon-reload && systemctl restart bedrock-echo-witness && sleep 1'

# Read witness pubkey from systemd journal
WITNESS_PUB=$(ssh $SSH_OPTS "root@$WITNESS_IP" 'journalctl -u bedrock-echo-witness -n 20 --no-pager | grep "witness pub:" | tail -1' | awk '{print $NF}')
echo "witness pub: $WITNESS_PUB"

# ── Derive per-node config ─────────────────────────────────────────────────

CLUSTER_KEY=$(openssl rand -hex 32)
SID_A=aa11aa22aa33aa44
SID_B=bb11bb22bb33bb44

# ── Deploy to each node ────────────────────────────────────────────────────

deploy_node() {
    local name=$1 peer_name=$2 node_ip=$3 peer_mgmt=$4 peer_drbd=$5 peer_link2=$6 sid=$7 peer_sid=$8

    echo "=== deploying to $name ($node_ip) ==="
    ssh $SSH_OPTS "root@$node_ip" 'mkdir -p /opt/bedrock-echo /etc/bedrock-echo'
    # Copy the `echo` and `node` Python packages as directories.
    rsync -az -e "ssh $SSH_OPTS" \
        "$REPO/python/echo" "$REPO/python/node" "root@$node_ip:/opt/bedrock-echo/"

    # Write the systemd environment file.
    ssh $SSH_OPTS "root@$node_ip" "cat > /etc/bedrock-echo/node.conf" <<EOF
NODE_NAME=$name
PEER_NAME=$peer_name
SENDER_ID_HEX=$sid
PEER_SENDER_ID_HEX=$peer_sid
CLUSTER_KEY_HEX=$CLUSTER_KEY
WITNESS_ADDR=$WITNESS_IP:7337
WITNESS_X25519_PUB_HEX=$WITNESS_PUB
PEER_MGMT_IP=$peer_mgmt
PEER_DRBD_IP=$peer_drbd
PEER_LINK2_IP=$peer_link2
BEC_DRY_RUN=1
EOF

    # Systemd unit for the node daemon.
    ssh $SSH_OPTS "root@$node_ip" "cat > /etc/systemd/system/bedrock-echo-node.service" <<'EOF'
[Unit]
Description=Bedrock Echo node daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/bedrock-echo/node.conf
Environment=PYTHONPATH=/opt/bedrock-echo
ExecStart=/usr/bin/python3 /opt/bedrock-echo/node/main.py
Restart=always
RestartSec=3s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    ssh $SSH_OPTS "root@$node_ip" 'systemctl daemon-reload && systemctl enable --now bedrock-echo-node && sleep 2 && journalctl -u bedrock-echo-node -n 10 --no-pager'
}

deploy_node bec-node-a bec-node-b "$NODE_A_IP" "$NODE_B_IP" 10.99.0.21 10.88.0.21 $SID_A $SID_B
deploy_node bec-node-b bec-node-a "$NODE_B_IP" "$NODE_A_IP" 10.99.0.20 10.88.0.20 $SID_B $SID_A

cat <<EOF

=== deployed ===
witness:      $WITNESS_IP:7337
witness_pub:  $WITNESS_PUB
cluster_key:  $CLUSTER_KEY
sid A:        $SID_A
sid B:        $SID_B

Follow logs:  ssh root@$NODE_A_IP 'journalctl -f -u bedrock-echo-node'
             ssh root@$NODE_B_IP 'journalctl -f -u bedrock-echo-node'

Harness:     harness/scenarios.py list
EOF
