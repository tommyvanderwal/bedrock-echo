"""Bedrock Echo node daemon entry point.

Reads config from env (populated via /etc/bedrock-echo/node.conf), builds a
real Daemon, and runs its loop forever.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Make the sibling `echo` package importable when invoked as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from node.daemon import Config, Resource, build_real_daemon


def getenv_required(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        sys.exit(f"missing required env: {name}")
    return v


def main():
    logging.basicConfig(
        level=os.environ.get("BEC_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    addr = getenv_required("WITNESS_ADDR")
    host, port = addr.split(":")
    witness_addr = (host, int(port))

    peer_rings = []
    for var in ("PEER_MGMT_IP", "PEER_DRBD_IP", "PEER_LINK2_IP"):
        v = os.environ.get(var)
        if v:
            peer_rings.append(v)
    if not peer_rings:
        sys.exit("at least one of PEER_MGMT_IP/PEER_DRBD_IP/PEER_LINK2_IP must be set")

    # Resources are hardcoded for v0.001 pilot — just one resource, bec-r0.
    # TODO(v0.2): read from config file for multi-resource clusters.
    resources = [Resource(drbd_resource="bec-r0", vm_name="")]

    cfg = Config(
        node_name=getenv_required("NODE_NAME"),
        peer_name=getenv_required("PEER_NAME"),
        sender_id=bytes.fromhex(getenv_required("SENDER_ID_HEX")),
        peer_sender_id=bytes.fromhex(getenv_required("PEER_SENDER_ID_HEX")),
        cluster_key=bytes.fromhex(getenv_required("CLUSTER_KEY_HEX")),
        witness_addr=witness_addr,
        witness_x25519_pub=bytes.fromhex(getenv_required("WITNESS_X25519_PUB_HEX")),
        peer_rings=peer_rings,
        resources=resources,
        dry_run=os.environ.get("BEC_DRY_RUN") == "1",
    )
    d = build_real_daemon(cfg)
    d.run_forever()


if __name__ == "__main__":
    main()
