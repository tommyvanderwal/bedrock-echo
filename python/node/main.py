"""Bedrock Echo node daemon entry point.

Reads config from env (populated via /etc/bedrock-echo/node.conf), builds a
real Daemon, and runs its loop forever.

Config:
  WITNESS_ADDR              host:port to reach the witness, OR "auto" /
                            unset → discover via mDNS (_echo._udp.local.).
  WITNESS_X25519_PUB_HEX    32-byte hex pubkey — REQUIRED as the trust
                            anchor regardless of how the witness is found.
  SENDER_ID_HEX             1 hex byte (00..FE) per PROTOCOL.md §2.
  PEER_SENDER_ID_HEX        1 hex byte for the peer.
  CLUSTER_KEY_HEX           32 hex bytes, distributed by the operator.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Make the sibling `echo` package importable when invoked as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from node.daemon import Config, Resource, build_real_daemon


log = logging.getLogger("echo.node.main")


def getenv_required(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        sys.exit(f"missing required env: {name}")
    return v


def parse_sender_id(name: str, raw: str) -> int:
    """Accept either a single hex byte (e.g. '01' or '0x01') or a decimal
    integer. Reject anything outside 0x00..0xFE per PROTOCOL.md §2."""
    s = raw.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    try:
        v = int(s, 16) if all(c in "0123456789abcdef" for c in s) else int(s)
    except ValueError:
        sys.exit(f"{name}: cannot parse {raw!r} as hex byte or int")
    if not (0 <= v <= 0xFE):
        sys.exit(f"{name}: must be 0x00..0xFE, got {v:#x}")
    return v


def discover_witness_via_mdns(expected_pubkey: bytes,
                               timeout_s: float = 5.0) -> tuple[str, int]:
    """Browse mDNS for `_echo._udp.local.`, pick the first witness whose
    advertised pubkey matches our trust anchor. Returns (host, port)."""
    try:
        from zeroconf import Zeroconf, ServiceBrowser
    except ImportError:
        sys.exit("WITNESS_ADDR=auto requires the `zeroconf` Python package; "
                 "install it or pin WITNESS_ADDR to host:port")
    import base64
    import time as _t

    found: list[tuple[str, int]] = []

    class _Listener:
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name, timeout=int(timeout_s * 1000))
            if not info:
                return
            txt = {k.decode("ascii", "ignore"): (v.decode("ascii", "ignore") if v else "")
                   for k, v in (info.properties or {}).items()}
            if txt.get("v") != "Echo" or txt.get("k") != "x25519":
                return
            try:
                pub = base64.b64decode(txt.get("p", ""))
            except Exception:
                return
            if pub != expected_pubkey:
                log.warning("mDNS witness %s pubkey mismatch (claims %s, "
                            "expected %s) — ignoring",
                            name, pub.hex(), expected_pubkey.hex())
                return
            host = info.parsed_addresses()[0] if info.parsed_addresses() else None
            if host:
                found.append((host, info.port))

        def update_service(self, *_a, **_kw): pass
        def remove_service(self, *_a, **_kw): pass

    zc = Zeroconf()
    try:
        ServiceBrowser(zc, "_echo._udp.local.", _Listener())
        deadline = _t.time() + timeout_s
        while _t.time() < deadline and not found:
            _t.sleep(0.1)
    finally:
        zc.close()

    if not found:
        sys.exit(f"mDNS browse for _echo._udp.local. found no witness "
                 f"with pubkey {expected_pubkey.hex()} after {timeout_s}s")
    host, port = found[0]
    log.info("mDNS-discovered witness at %s:%d (pubkey verified)", host, port)
    return host, port


def main():
    logging.basicConfig(
        level=os.environ.get("BEC_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    witness_pubkey = bytes.fromhex(getenv_required("WITNESS_X25519_PUB_HEX"))
    if len(witness_pubkey) != 32:
        sys.exit("WITNESS_X25519_PUB_HEX must decode to 32 bytes")

    addr_raw = os.environ.get("WITNESS_ADDR", "").strip().lower()
    if addr_raw and addr_raw != "auto":
        host, port = addr_raw.split(":")
        witness_addr = (host, int(port))
    else:
        witness_addr = discover_witness_via_mdns(witness_pubkey)

    peer_rings = []
    for var in ("PEER_MGMT_IP", "PEER_DRBD_IP", "PEER_LINK2_IP"):
        v = os.environ.get(var)
        if v:
            peer_rings.append(v)
    if not peer_rings:
        sys.exit("at least one of PEER_MGMT_IP/PEER_DRBD_IP/PEER_LINK2_IP must be set")

    # Resources are hardcoded for the pilot — just one resource, bec-r0.
    resources = [Resource(drbd_resource="bec-r0", vm_name="")]

    cfg = Config(
        node_name=getenv_required("NODE_NAME"),
        peer_name=getenv_required("PEER_NAME"),
        sender_id=parse_sender_id("SENDER_ID_HEX", getenv_required("SENDER_ID_HEX")),
        peer_sender_id=parse_sender_id("PEER_SENDER_ID_HEX",
                                        getenv_required("PEER_SENDER_ID_HEX")),
        cluster_key=bytes.fromhex(getenv_required("CLUSTER_KEY_HEX")),
        witness_addr=witness_addr,
        witness_pubkey=witness_pubkey,
        peer_rings=peer_rings,
        resources=resources,
        dry_run=os.environ.get("BEC_DRY_RUN") == "1",
    )
    d = build_real_daemon(cfg)
    d.run_forever()


if __name__ == "__main__":
    main()
