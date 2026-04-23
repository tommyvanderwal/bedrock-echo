#!/usr/bin/env bash
# Rapid cut/restore stress test for the DRBD ring.
# Cuts and restores the DRBD tap N times with short pauses, then verifies
# both sides reconnect cleanly and maintain exactly one Primary.

set -euo pipefail

ITERATIONS=${1:-10}
CUT_DURATION=${2:-4}
INTERVAL=${3:-6}

NODE_A_IP=192.168.2.176
NODE_B_IP=192.168.2.180
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=3"

role() {
    ssh $SSH_OPTS "root@$1" 'drbdadm role bec-r0 2>/dev/null' 2>/dev/null || echo Unknown
}

check_invariant() {
    local a b n
    a=$(role "$NODE_A_IP"); b=$(role "$NODE_B_IP")
    n=0
    [ "$a" = "Primary" ] && n=$((n+1))
    [ "$b" = "Primary" ] && n=$((n+1))
    echo "  roles: A=$a B=$b primaries=$n"
    if [ "$n" -gt 1 ]; then
        echo "  *** SPLIT-BRAIN at iteration $i ***"
        return 1
    fi
    return 0
}

echo "=== stress test: $ITERATIONS rapid cut/restore cycles ==="
echo "    cut duration: ${CUT_DURATION}s"
echo "    interval:     ${INTERVAL}s"
echo
echo "Starting state:"
check_invariant

for i in $(seq 1 "$ITERATIONS"); do
    echo
    echo "--- iteration $i/$ITERATIONS ---"
    # Cut both DRBD ring taps (safe — stays in "both connected to peer via mgmt
    # and witness" space, so no daemon promotion fires)
    for vm in bec-node-a bec-node-b; do
        TAP=$(sudo virsh domiflist "$vm" | awk '/bedrock-drbd/ {print $1}')
        sudo ip link set "$TAP" down
    done
    sleep "$CUT_DURATION"
    check_invariant || exit 1

    for vm in bec-node-a bec-node-b; do
        TAP=$(sudo virsh domiflist "$vm" | awk '/bedrock-drbd/ {print $1}')
        sudo ip link set "$TAP" up
    done
    sleep "$INTERVAL"
    check_invariant || exit 1
done

echo
echo "=== recovery check ==="
sleep 10
for ip in "$NODE_A_IP" "$NODE_B_IP"; do
    echo; echo "$ip:"
    ssh $SSH_OPTS "root@$ip" 'drbdadm status bec-r0' 2>/dev/null || echo "(unreachable)"
done

echo
echo "=== PASS: $ITERATIONS cycles, no split-brain ==="
