#!/usr/bin/env bash
# Set up DRBD resource bec-r0 on a fresh node. Run on each bec-node-{a,b}.
# Assumes /dev/vdb exists (2 GB raw disk provisioned by virt-install).
set -euo pipefail

POOL_DEV=/dev/vdb
VG=bec_pool
THINPOOL=bec_thin
LV_BACKING=bec-r0
LV_SIZE=64M

if ! vgs $VG &>/dev/null; then
    pvcreate -ff -y "$POOL_DEV"
    vgcreate $VG "$POOL_DEV"
fi
if ! lvs $VG/$THINPOOL &>/dev/null; then
    lvcreate -l 95%VG --thinpool $THINPOOL $VG
fi
if ! lvs $VG/$LV_BACKING &>/dev/null; then
    lvcreate -V $LV_SIZE --thin -n $LV_BACKING $VG/$THINPOOL
fi

# Copy resource config into /etc/drbd.d/
mkdir -p /etc/drbd.d
cp /tmp/bec-r0.res /etc/drbd.d/bec-r0.res

# Initialize metadata (no-op if already done)
if ! drbdadm dump-md bec-r0 >/dev/null 2>&1; then
    drbdadm create-md --force bec-r0 <<< "yes"
fi

drbdadm up bec-r0 || true
drbdadm status bec-r0 || true

echo "DRBD setup on $(hostname) complete."
