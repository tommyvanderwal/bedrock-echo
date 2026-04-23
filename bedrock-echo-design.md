# Bedrock Echo Witness - Design Document v0.1 (Pilot)

**Status:** Pilot / Proof of Concept  
**Date:** 2026-04-21  
**Version:** 0.1  
**Goal:** Get a working, useful, minimal witness running on real mini hardware as fast as possible. Everything is allowed to change except the core principles below.

---

## 1. Core Principles (These Will NOT Change)

- **Ephemeral / Stateful but non-persistent**: All cluster state lives in RAM only. Reboot = forget everything. No flash wear, no persistence by design.
- **Useful witness**: Not a dummy. It provides real value to a newly designed cluster setup. And current protocol could adopt it (DRBD, Raft, Corosync, custom protocols, etc.).
- **Mini hardware**: Target is ESP32-POE-ISO class device (or similar). PoE powered or USB powered, optionally battery-backed, physically small. Also as Container on Mikrotik and on any linux machine, very light.
- **Asymmetric crypto bootstrap**: First contact uses Ed25519. No pre-shared secrets on flash except the witness's own permanent async keypair. Optionally locking down to 1 cluster with a shared key is later possible. Trigger is always a smart / big node sending a cluster hello. If this Bedrock Echo just booted and does not know the cluster (and key) yet, it has to ask that node for it with it's init packet. The Node encrypts (asym) with the already trusted Echo Witness public key.  
- **Dumb & reactive**: The witness never initiates, never decides, never votes. It only answers when a real node asks. Sending what is heard from all other nodes(+When and it's own time + uptime) to the asker. All intelligence lives on the real cluster nodes.
- **Protocol first**: The device exists to run the protocol. The protocol must be as simple as possible while still providing that relevant extra perspective. Preventing downtime is nice and good. However, preventing split-brains is paramount. No Split-brain ever is absolutely required and the highest priority. Although most of that is up to the bigger and smarter node actually running a service.

---

## 2. What this PoC Must Deliver

A working end-to-end pilot that can be deployed on real hardware and used with at least one real cluster type - a custom vanilla type that could follow logic and direct a local 2-node DRBD cluster with manual commands to become active or not (manual from DRBD perspective). So a basic example implementation of the smart real node part running on Linux as a service. As small as possible, but able to run local commands "make primary" under the correct condition.

**Must-have features:**
- Single cluster support (multi-cluster comes in 0.2)
- Bootstrap flow with asymmetric crypto + encrypted cluster shared secret
- Node heartbeats response with all relevant details in memory
- Query "what do you see?" (node  witness)
- HMAC authentication for all traffic after bootstrap
- RAM state only - NO disk persistence (only the ASYM key is on disk, next to this application).
- Runs on ESP32-POE-ISO easily, it should be highly efficient with memory and CPU

**optional, nice to have for PoC:**
- Basic rate limiting / silent drop when full
- Discovery could simply be starting the cluster hello on the right UDP port number.  Some way to find it with multicast/broadcast or something could be an option, might not be needed / cleaner without.
- See if you can store 64 nodes across 32 clusters (arbitrairly, first field in the node struct should reference the cluster NR(locally significant cluster nr))
- Dynamic timeout scaling (72h  1h  5min as table fills)
- 3+-witness and 5-witness modes with simple majority on the nodes (should be any number, witnesses don't see another, they only reply to real nodes, so only touched node implementation)
- smart basic Rate limiting per IP to limit DDOS potential.

**Explicitly out of scope for 0.1:**
- no very Advanced crypto (no post-quantum, no key rotation)
- TLS (UDP + HMAC is enough for local lan cluster hello's) - will make the requirement bigger with little benefit.

---

## 3. State Model (RAM only)

use Rust. Figure out the structs that are needed per cluster entry and per node entry


On reboot everything is lost  nodes must re-bootstrap.

---

## 4. Cryptography & Bootstrap (v0.1)

**Permanent on device (flash, generated on first boot):**
- proposed: Ed25519 keypair (private key never leaves the device)

**Bootstrap (one-time per cluster):**
1. Admin manually adds witness public key + IP address to the cluster configuration.


---

## 5. Protocol (UDP, binary)

**Message types (all authenticated with HMAC after bootstrap):**

a heartbeat from a node to the witness is also a request for the information from the node. It will answer with everything it knows about this cluster. Which nodes and when they last said HI and any custom field they have sent. Make the protocol smart for it's purpose and then as small as possible.

The witness is **completely reactive**  it never sends unsolicited messages.

---

## 6. Hardware Target (v0.1)

- **Primary**: Olimex ESP32-POE-ISO or equivalent (PoE + isolated USB, LiPo charger onboard)
- **Fallback**: Any ESP32 with Ethernet, any Mikrotik that can run any tiny container, any actual Linux machine (micro deamon? can it be in inetd something?)

- Or anything small with just enough memory, cpu, flash and an Ethernet RJ45 port. the smaller the better
---

## 7. Non-Goals / Explicitly Not Doing in v0.1

- Any decision logic on the witness itself (no ffsplit, no lms, no heuristics)
- Persistent storage of cluster data (only the permanent Ed25519 keypair lives on flash)
- Encryption of traffic (HMAC only  confidentiality not required for a witness)

---

## 8. Success Criteria for v0.1 Pilot

1. Can bootstrap with a real 2-node DRBD cluster (or equivalent) using the device.
2. After bootstrap, nodes can heartbeat and query successfully.
3. On witness reboot, nodes detect it and re-bootstrap or continue safely.
4. Split-brain test: when network between the two nodes is cut, the side that can still reach the witness stays primary; the other side steps down.
5. Device survives PoE power loss if battery is connected.
6. Code fits comfortably on ESP32-POE-ISO and is readable enough that others can port it.

---

## 9. Implementation Notes for Claude / AI Coder

- Language: Rust (no_std + embassy) is preferred for long-term maintainability.
- Keep the state machine extremely simple
- no dynamic allocation after boot would be a nice to have.
- Bets crypto seems to be `ed25519-dalek` + `hmac` + `sha2` (or the ESP32 hardware acceleration where available). But feel free to improve if possible within the architecture requirements.
- Start with static IP.
- Make the payload completely opaque  do not try to parse DRBD UUIDs or Raft terms inside the witness. There should be no need. It only passes data on.

---

