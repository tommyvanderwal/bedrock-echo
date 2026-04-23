"""Side-effect adapters: DRBD + virsh + TCP peer ping.

Everything the node daemon does to the world goes through one of these
traits. Mocking them in tests means the harness can run without DRBD.
"""
from __future__ import annotations

import logging
import socket
import subprocess
from dataclasses import dataclass
from typing import Protocol

log = logging.getLogger("echo.node.effects")


class DrbdAdapter(Protocol):
    def role(self, resource: str) -> str: ...
    def cstate(self, resource: str) -> str: ...
    def dstate(self, resource: str) -> str: ...
    def primary(self, resource: str) -> bool: ...
    def secondary(self, resource: str) -> bool: ...


class VirshAdapter(Protocol):
    def running_vms(self) -> set[str]: ...
    def start(self, vm: str) -> bool: ...
    def shutdown(self, vm: str) -> bool: ...


class PeerPing(Protocol):
    def ping(self, address: str, port: int = 22, timeout: float = 2.0) -> bool: ...


# ── Real implementations ──────────────────────────────────────────────────


@dataclass
class RealDrbd:
    """Shells out to `drbdadm`. Install in bec-node VMs."""

    timeout: float = 5.0

    def _run(self, args: list[str]) -> tuple[str, int]:
        try:
            r = subprocess.run(
                ["drbdadm", *args],
                capture_output=True, text=True, timeout=self.timeout,
            )
            return r.stdout.strip(), r.returncode
        except Exception as e:
            log.warning("drbdadm %s failed: %s", args, e)
            return "", 1

    def role(self, resource: str) -> str:
        out, rc = self._run(["role", resource])
        return out if rc == 0 else "Unknown"

    def cstate(self, resource: str) -> str:
        out, rc = self._run(["cstate", resource])
        return out if rc == 0 else "Unknown"

    def dstate(self, resource: str) -> str:
        out, rc = self._run(["dstate", resource])
        return out if rc == 0 else "Unknown"

    def primary(self, resource: str) -> bool:
        # Use --force because with `on-no-quorum suspend-io`, the survivor
        # has no DRBD quorum when the peer is gone. The Bedrock Echo daemon
        # only ever calls primary() after witness-confirmed peer-dead, which
        # is a safer external tiebreaker than DRBD's local quorum math.
        _, rc = self._run(["--force", "primary", resource])
        return rc == 0

    def secondary(self, resource: str) -> bool:
        _, rc = self._run(["secondary", resource])
        return rc == 0


@dataclass
class RealVirsh:
    timeout: float = 15.0

    def _run(self, args: list[str]) -> tuple[str, int]:
        try:
            r = subprocess.run(
                ["virsh", *args],
                capture_output=True, text=True, timeout=self.timeout,
            )
            return r.stdout.strip(), r.returncode
        except Exception as e:
            log.warning("virsh %s failed: %s", args, e)
            return "", 1

    def running_vms(self) -> set[str]:
        out, rc = self._run(["list", "--name", "--state-running"])
        if rc != 0 or not out:
            return set()
        return set(out.split())

    def start(self, vm: str) -> bool:
        _, rc = self._run(["start", vm])
        return rc == 0

    def shutdown(self, vm: str) -> bool:
        _, rc = self._run(["shutdown", vm])
        return rc == 0


@dataclass
class RealPeerPing:
    """TCP-connect a host:port with a strict timeout. We use port 22 (SSH)
    as a proxy for "host is up and the network path works"."""

    def ping(self, address: str, port: int = 22, timeout: float = 2.0) -> bool:
        try:
            s = socket.create_connection((address, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False


# ── Test doubles ──────────────────────────────────────────────────────────


@dataclass
class FakeDrbd:
    _role: dict[str, str]
    primary_calls: list[str] = None
    secondary_calls: list[str] = None

    def __post_init__(self):
        if self.primary_calls is None: self.primary_calls = []
        if self.secondary_calls is None: self.secondary_calls = []

    def role(self, resource: str) -> str: return self._role.get(resource, "Unknown")
    def cstate(self, resource: str) -> str: return "Connected"
    def dstate(self, resource: str) -> str: return "UpToDate"

    def primary(self, resource: str) -> bool:
        self.primary_calls.append(resource)
        self._role[resource] = "Primary"
        return True

    def secondary(self, resource: str) -> bool:
        self.secondary_calls.append(resource)
        self._role[resource] = "Secondary"
        return True


@dataclass
class FakeVirsh:
    _running: set[str]
    starts: list[str] = None

    def __post_init__(self):
        if self.starts is None: self.starts = []

    def running_vms(self) -> set[str]: return set(self._running)

    def start(self, vm: str) -> bool:
        self.starts.append(vm)
        self._running.add(vm)
        return True

    def shutdown(self, vm: str) -> bool:
        self._running.discard(vm)
        return True


@dataclass
class FakePeerPing:
    reachable: set[str]   # set of addresses that should answer

    def ping(self, address: str, port: int = 22, timeout: float = 2.0) -> bool:
        return address in self.reachable
