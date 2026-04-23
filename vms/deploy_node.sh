#!/usr/bin/env bash
# Deploy Bedrock Echo node daemon + DRBD config to a bec-node VM.
# Usage: deploy_node.sh <mgmt-ip> <node-name> <peer-name> <drbd-ip-self> \
#                      <drbd-ip-peer> <link2-ip-self> <link2-ip-peer> \
#                      <witness-addr:port> <witness-x25519-pub-hex>
#                      <cluster-key-hex> <sender-id-hex> <peer-sender-id-hex>

set -euo pipefail

MGMT=$1
NODE=$2
PEER=$3
DRBD_SELF=$4
DRBD_PEER=$5
LINK2_SELF=$6
LINK2_PEER=$7
WITNESS_ADDR=$8
WITNESS_PUB=$9
CLUSTER_KEY=${10}
SENDER_ID=${11}
PEER_SENDER_ID=${12}

REPO=$(cd "$(dirname "$0")/.." && pwd)

echo "=== deploying to $NODE ($MGMT) ==="

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH() { ssh $SSH_OPTS "root@$MGMT" "$@"; }
SCP() { scp $SSH_OPTS "$@"; }

# 1. Copy the echo + node Python packages
SSH "mkdir -p /opt/bedrock-echo"
SCP -r "$REPO/python/echo" "$REPO/python/node" "root@$MGMT:/opt/bedrock-echo/"

# 2. Write the config file
SSH "mkdir -p /etc/bedrock-echo"
SSH "cat > /etc/bedrock-echo/node.conf" <<EOF
# Bedrock Echo node daemon config. Keep out of version control.
NODE_NAME="$NODE"
PEER_NAME="$PEER"
SENDER_ID_HEX="$SENDER_ID"
PEER_SENDER_ID_HEX="$PEER_SENDER_ID"
CLUSTER_KEY_HEX="$CLUSTER_KEY"
WITNESS_ADDR="$WITNESS_ADDR"
WITNESS_X25519_PUB_HEX="$WITNESS_PUB"
# Peer addresses across the three rings (mgmt / drbd / link2)
PEER_MGMT_IP="$PEER_MGMT_IP_ENV"
PEER_DRBD_IP="$DRBD_PEER"
PEER_LINK2_IP="$LINK2_PEER"
EOF

# 3. Write the systemd unit
SSH "cat > /etc/systemd/system/bedrock-echo-node.service" <<'EOF'
[Unit]
Description=Bedrock Echo node daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/bedrock-echo/node.conf
ExecStart=/usr/bin/python3 /opt/bedrock-echo/node/main.py
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

# 4. daemon-reload
SSH 'systemctl daemon-reload'
echo "Deployed to $NODE. Service defined but not started (needs main.py + DRBD config first)."
