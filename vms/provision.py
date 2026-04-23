#!/usr/bin/env python3
"""Bedrock Echo pilot VMs manager.

Usage:
  provision.py prereqs            # verify tools, create bec-link2 network
  provision.py up witness         # start the witness VM
  provision.py up nodes           # start bec-node-a and bec-node-b
  provision.py up all             # witness + both nodes
  provision.py down {name|all}    # destroy a VM (keeps disks)
  provision.py reset              # destroy all and wipe disks
  provision.py list               # show state
  provision.py ssh <name> [cmd]   # ssh into a VM (DHCP-learned IP)

Notes:
- Reuses AlmaLinux 9 golden image from ../bedrock/testbed/images/ (sibling project).
- Reuses libvirt networks 'bedrock-mgmt' (br0, bridged) and 'bedrock-drbd'
  (10.99.0.0/24 isolated) defined in ../bedrock/testbed/networks/.
- Creates 'bec-link2' (10.88.0.0/24 isolated) here.
- Does NOT touch bedrock-sim-* VMs.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
STATE_DIR = HERE / "state"
CLOUD_INIT = HERE / "cloud-init"
NETWORKS = HERE / "networks"

BEDROCK_SIBLING = REPO.parent / "bedrock"
GOLDEN_IMG = BEDROCK_SIBLING / "testbed" / "images" / "almalinux-9.qcow2"

SSH_KEY_PUB = Path.home() / ".ssh" / "id_ed25519.pub"

VMS = {
    # NB: root_gb must be >= the golden image's virtual size (AlmaLinux 9
    # cloud image = 10 GiB). qcow2 is thin so the extra is only virtual.
    "bec-witness": {
        "role": "witness",
        "ram": 1024,
        "vcpus": 1,
        "root_gb": 10,
        "extra_disks": [],
        "nets": ["bedrock-mgmt"],
        "drbd_ip": None,
        "link2_ip": None,
    },
    "bec-node-a": {
        "role": "node",
        "ram": 2048,
        "vcpus": 2,
        "root_gb": 12,
        "extra_disks": [("pool", 2)],  # 2 GB raw for thin pool
        "nets": ["bedrock-mgmt", "bedrock-drbd", "bec-link2"],
        "drbd_ip": "10.99.0.20",
        "link2_ip": "10.88.0.20",
    },
    "bec-node-b": {
        "role": "node",
        "ram": 2048,
        "vcpus": 2,
        "root_gb": 12,
        "extra_disks": [("pool", 2)],
        "nets": ["bedrock-mgmt", "bedrock-drbd", "bec-link2"],
        "drbd_ip": "10.99.0.21",
        "link2_ip": "10.88.0.21",
    },
}

HOSTS_ENTRIES_TMPL = (
    "      10.99.0.20 bec-node-a-drbd\n"
    "      10.99.0.21 bec-node-b-drbd\n"
    "      10.88.0.20 bec-node-a-link2\n"
    "      10.88.0.21 bec-node-b-link2\n"
)


def run(cmd, check=True, capture=False):
    if isinstance(cmd, str):
        cmd = ["bash", "-c", cmd]
    r = subprocess.run(cmd, capture_output=capture, text=True)
    if check and r.returncode != 0:
        sys.stderr.write(f"FAIL: {cmd}\n{r.stderr}\n")
        sys.exit(r.returncode)
    return r.stdout.strip() if capture else "", r.returncode


def virsh(*args, capture=True, check=False):
    return run(["sudo", "virsh"] + list(args), check=check, capture=capture)


def ensure_tools():
    for tool in ("virsh", "virt-install", "cloud-localds", "qemu-img"):
        if not shutil.which(tool):
            sys.exit(f"missing tool: {tool}")


def ensure_golden():
    if not GOLDEN_IMG.exists():
        sys.exit(
            f"golden image not found: {GOLDEN_IMG}\n"
            f"Run the sibling bedrock testbed prereqs first, or download "
            f"AlmaLinux-9-GenericCloud-latest.x86_64.qcow2 manually to {GOLDEN_IMG}."
        )


def ensure_networks():
    out, _ = virsh("net-list", "--all", "--name")
    existing = out.split()
    for net in ("bedrock-mgmt", "bedrock-drbd"):
        if net not in existing:
            sys.exit(
                f"libvirt network '{net}' missing. Create it via the sibling "
                f"bedrock testbed: `sudo virsh net-define "
                f"{BEDROCK_SIBLING}/testbed/networks/{net}.xml && sudo virsh "
                f"net-start {net} && sudo virsh net-autostart {net}`"
            )
    # create bec-link2 if missing
    if "bec-link2" not in existing:
        print("Creating bec-link2 network ...")
        virsh("net-define", str(NETWORKS / "bec-link2.xml"), check=True)
    # ensure it's active + autostart
    state_out, _ = virsh("net-info", "bec-link2")
    is_active = any(
        line.strip().startswith("Active:") and line.split(":", 1)[1].strip() == "yes"
        for line in state_out.splitlines()
    )
    if not is_active:
        virsh("net-start", "bec-link2", check=True)
    virsh("net-autostart", "bec-link2")


def cmd_prereqs(_):
    ensure_tools()
    ensure_golden()
    STATE_DIR.mkdir(exist_ok=True)
    if not SSH_KEY_PUB.exists():
        sys.exit(f"missing SSH pubkey {SSH_KEY_PUB}")
    ensure_networks()
    print("prereqs OK")


# ── cloud-init ISO per vm ──────────────────────────────────────────────────


def make_seed(name: str) -> Path:
    spec = VMS[name]
    st = STATE_DIR / name
    st.mkdir(parents=True, exist_ok=True)

    tmpl_name = "witness.user-data.tmpl" if spec["role"] == "witness" else "node.user-data.tmpl"
    user_data = (CLOUD_INIT / tmpl_name).read_text()
    user_data = user_data.replace("{HOSTNAME}", name)
    user_data = user_data.replace("{SSH_PUBKEY}", SSH_KEY_PUB.read_text().strip())
    user_data = user_data.replace(
        "{ROOT_PASSWD_HASH}",
        os.environ.get("BEC_ROOT_PASSWD_HASH", "*"),
    )
    if spec["role"] == "node":
        user_data = user_data.replace("{DRBD_IP}", spec["drbd_ip"])
        user_data = user_data.replace("{LINK2_IP}", spec["link2_ip"])
        user_data = user_data.replace("{HOSTS_ENTRIES}", HOSTS_ENTRIES_TMPL)

    (st / "user-data").write_text(user_data)
    meta = (CLOUD_INIT / "meta-data.tmpl").read_text().replace("{HOSTNAME}", name)
    (st / "meta-data").write_text(meta)
    iso = st / "seed.iso"
    run(f"cloud-localds {iso} {st}/user-data {st}/meta-data")
    return iso


# ── Lifecycle ──────────────────────────────────────────────────────────────


def vm_exists(name: str) -> bool:
    out, _ = virsh("list", "--all", "--name")
    return name in out.split()


def create_vm(name: str):
    spec = VMS[name]
    st = STATE_DIR / name
    st.mkdir(parents=True, exist_ok=True)

    root = st / "root.qcow2"
    if not root.exists():
        run(f"qemu-img create -f qcow2 -F qcow2 -b {GOLDEN_IMG} "
            f"{root} {spec['root_gb']}G")

    extra_disk_args = []
    for idx, (label, gb) in enumerate(spec["extra_disks"]):
        path = st / f"disk-{label}.raw"
        if not path.exists():
            run(f"qemu-img create -f raw {path} {gb}G")
        extra_disk_args += ["--disk", f"path={path},format=raw,bus=virtio,cache=none"]

    iso = make_seed(name)

    net_args = []
    for net in spec["nets"]:
        net_args += ["--network", f"network={net},model=virtio"]

    print(f"Spawning {name} ...")
    run([
        "sudo", "virt-install",
        "--name", name,
        "--memory", str(spec["ram"]),
        "--vcpus", str(spec["vcpus"]),
        "--cpu", "host-passthrough",
        "--disk", f"path={root},format=qcow2,bus=virtio",
        *extra_disk_args,
        "--disk", f"path={iso},device=cdrom",
        *net_args,
        "--os-variant", "almalinux9",
        "--graphics", "none",
        "--console", "pty,target_type=serial",
        "--import",
        "--noautoconsole",
        "--noreboot",
    ])
    virsh("start", name)


def destroy_vm(name: str, wipe: bool = False):
    if not vm_exists(name):
        return
    print(f"Destroying {name} ...")
    virsh("destroy", name)
    virsh("undefine", name, "--remove-all-storage", "--nvram")
    if wipe:
        st = STATE_DIR / name
        if st.exists():
            shutil.rmtree(st)


def cmd_up(args):
    ensure_tools()
    ensure_golden()
    ensure_networks()
    STATE_DIR.mkdir(exist_ok=True)
    targets = resolve_targets(args.target)
    for name in targets:
        if vm_exists(name):
            print(f"{name}: already exists")
            continue
        create_vm(name)
    cmd_list(args)


def cmd_down(args):
    for name in resolve_targets(args.target):
        destroy_vm(name)


def cmd_reset(_):
    for name in list(VMS):
        destroy_vm(name, wipe=True)
    print("All Bedrock Echo VMs destroyed and state wiped.")


def cmd_list(_):
    for name in VMS:
        if vm_exists(name):
            state, _ = virsh("domstate", name)
            print(f"  {name}: {state}")
        else:
            print(f"  {name}: absent")


def cmd_ssh(args):
    ip = get_mgmt_ip(args.name)
    if not ip:
        sys.exit(f"no IP for {args.name}")
    os.execvp("ssh", [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        f"root@{ip}", *(args.cmd or []),
    ])


def resolve_targets(arg: str) -> list[str]:
    if arg == "all":
        return list(VMS)
    if arg == "nodes":
        return ["bec-node-a", "bec-node-b"]
    if arg == "witness":
        return ["bec-witness"]
    if arg in VMS:
        return [arg]
    sys.exit(f"unknown target: {arg}")


def get_mgmt_ip(name: str) -> str | None:
    if not vm_exists(name):
        return None
    out, _ = virsh("domiflist", name)
    mgmt_mac = None
    for line in out.split("\n"):
        parts = line.split()
        if len(parts) >= 5 and parts[2] == "bedrock-mgmt":
            mgmt_mac = parts[4].lower()
            break
    if not mgmt_mac:
        return None
    arp_out, _ = run("ip neigh", capture=True)
    for line in arp_out.split("\n"):
        if mgmt_mac in line.lower():
            return line.split()[0]
    return None


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prereqs").set_defaults(func=cmd_prereqs)
    up = sub.add_parser("up")
    up.add_argument("target")
    up.set_defaults(func=cmd_up)
    down = sub.add_parser("down")
    down.add_argument("target")
    down.set_defaults(func=cmd_down)
    sub.add_parser("reset").set_defaults(func=cmd_reset)
    sub.add_parser("list").set_defaults(func=cmd_list)
    ssh = sub.add_parser("ssh")
    ssh.add_argument("name")
    ssh.add_argument("cmd", nargs="*")
    ssh.set_defaults(func=cmd_ssh)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
