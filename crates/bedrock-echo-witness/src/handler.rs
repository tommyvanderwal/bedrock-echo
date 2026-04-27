//! Packet dispatch for the witness — pure logic, no socket I/O.
//!
//! `handle(state, data, src_ip, src_port, now_ms)` consumes one inbound
//! UDP datagram and returns 0 or 1 reply bytes. Driving from a UDP loop:
//!     for reply in handle(...) { sock.sendto(reply.as_slice(), src) }
//!
//! Dispatch (post-polish):
//!   - DISCOVER → INIT (with cookie for src_ip).
//!   - BOOTSTRAP → cookie pre-check, then AEAD-decrypt cluster_key,
//!     then create-or-update node entry.
//!   - HEARTBEAT → strict (src_ip, sender_id) match only. No
//!     sender_id-only fallback, no new-node-join AEAD scan. Mismatches
//!     get a rate-limited INIT reply.

use bedrock_echo_proto::constants::*;
use bedrock_echo_proto::msg;

use crate::state::State;

/// Reply buffer (max-MTU-sized).
pub struct Reply {
    pub buf: [u8; MTU_CAP],
    pub len: usize,
}

impl Reply {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

pub fn handle(
    state: &mut State,
    data: &[u8],
    src_ipv4: [u8; 4],
    src_port: u16,
    now_ms: u64,
) -> Option<Reply> {
    if data.len() > MTU_CAP || data.len() < HEADER_LEN {
        return None;
    }
    state.age_out(now_ms);
    if !state.allow(src_ipv4, now_ms) {
        return None;
    }

    let hdr = bedrock_echo_proto::Header::unpack(data).ok()?;
    match hdr.msg_type {
        MSG_DISCOVER => handle_discover(state, data, src_ipv4, now_ms),
        MSG_BOOTSTRAP => handle_bootstrap(state, data, src_ipv4, src_port, now_ms),
        MSG_HEARTBEAT => handle_heartbeat(state, data, src_ipv4, src_port, now_ms),
        _ => None,
    }
}

// ── DISCOVER ──────────────────────────────────────────────────────────────

fn handle_discover(state: &mut State, data: &[u8], src_ipv4: [u8; 4],
                   now_ms: u64) -> Option<Reply> {
    // Currently we ignore the node-side capability_flags from DISCOVER —
    // no capability bits are allocated yet. A future revision can branch
    // on caps to pick a different reply msg_type.
    let (_hdr, _node_caps) = msg::decode_discover(data).ok()?;
    if !state.allow_unknown(src_ipv4, now_ms) {
        return None;
    }
    let cookie = state.cookie_for(&src_ipv4);
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_init(
        &mut out,
        state.uptime_ms(now_ms) as i64,
        &state.witness_pub,
        &cookie,
        0,  // witness capability_flags — none allocated in Draft v0.x
    )
    .ok()?;
    Some(Reply { buf: out, len: n })
}

// ── BOOTSTRAP ─────────────────────────────────────────────────────────────

fn handle_bootstrap(state: &mut State, data: &[u8], src_ipv4: [u8; 4],
                    src_port: u16, now_ms: u64) -> Option<Reply> {
    if data.len() != BOOTSTRAP_LEN {
        return None;
    }
    // Cookie pre-check (PROTOCOL.md §11.2). Done before AEAD/X25519 to
    // keep the witness's CPU budget bounded under spoofed-source storms.
    let cookie_in: &[u8; COOKIE_LEN] =
        data[HEADER_LEN..HEADER_LEN + COOKIE_LEN].try_into().ok()?;
    if !state.cookie_valid(&src_ipv4, cookie_in) {
        return None;
    }

    // We need to copy `data` into a mutable buffer for in-place AEAD decrypt.
    let mut buf = [0u8; MTU_CAP];
    if data.len() > buf.len() {
        return None;
    }
    buf[..data.len()].copy_from_slice(data);
    let work = &mut buf[..data.len()];
    let (hdr, _cookie, cluster_key) =
        msg::decode_bootstrap(work, &state.witness_priv).ok()?;

    // Find existing entry with same (sender_id, cluster_key).
    let mut existing_idx: Option<usize> = None;
    for i in state.find_nodes_by_sender(hdr.sender_id) {
        let cs = state.nodes[i].cluster_slot as usize;
        if state.clusters[cs].cluster_key == cluster_key {
            existing_idx = Some(i);
            break;
        }
    }

    let uptime_ms = state.uptime_ms(now_ms);
    let (cluster_slot, status) = if let Some(idx) = existing_idx {
        let cs = state.nodes[idx].cluster_slot as usize;
        if !state.adapt_cluster_offset(cs, hdr.timestamp_ms, uptime_ms) {
            return None;
        }
        // Idempotent re-bootstrap. MAX-rule on last_rx_timestamp prevents
        // a replay rolling back the anti-replay invariant.
        let n = &mut state.nodes[idx];
        n.sender_ipv4 = src_ipv4;
        n.sender_src_port = src_port;
        n.last_rx_ms = now_ms;
        if hdr.timestamp_ms > n.last_rx_timestamp {
            n.last_rx_timestamp = hdr.timestamp_ms;
        }
        (cs, 0x01u8)
    } else {
        // New node entry. Either: brand-new cluster, or new node joining
        // existing cluster, or sender_id collision with another cluster.
        let cs = if let Some(c) = state.find_cluster_by_key(&cluster_key) {
            // Cluster exists; just adding a new node entry under it.
            if !state.adapt_cluster_offset(c, hdr.timestamp_ms, uptime_ms) {
                return None;
            }
            c
        } else {
            // Brand-new cluster.
            let slot = state.allocate_cluster_slot()?;
            let offset = hdr.timestamp_ms - uptime_ms as i64;
            state.clusters[slot] = crate::state::ClusterEntry {
                in_use: true,
                cluster_key,
                bootstrapped_ms: now_ms,
                num_nodes: 0,
                cluster_offset: offset,
                last_tx_timestamp: 0,
            };
            slot
        };
        let ns = state.allocate_node_slot()?;
        state.nodes[ns] = crate::state::NodeEntry {
            in_use: true,
            sender_id: hdr.sender_id,
            sender_ipv4: src_ipv4,
            sender_src_port: src_port,
            cluster_slot: cs as u16,
            last_rx_ms: now_ms,
            last_rx_timestamp: hdr.timestamp_ms,
            payload_n_blocks: 0,
            payload: [0; PAYLOAD_MAX_BYTES],
        };
        state.clusters[cs].num_nodes = state.clusters[cs].num_nodes.saturating_add(1);
        (cs, 0x00u8)
    };

    // Build BOOTSTRAP_ACK.
    let cluster_key_copy = state.clusters[cluster_slot].cluster_key;
    let ts_out = state.next_tx_timestamp(cluster_slot, uptime_ms);
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_bootstrap_ack(
        &mut out,
        ts_out,
        status,
        (uptime_ms / 1000) as u32,
        &cluster_key_copy,
    )
    .ok()?;
    Some(Reply { buf: out, len: n })
}

// ── HEARTBEAT ─────────────────────────────────────────────────────────────

/// Outcome of a single AEAD trial. AEAD success but rejected (replay,
/// out-of-window timestamp) is `Drop` — the packet is consumed by this
/// candidate and must NOT cascade to a new-node-join.
enum HbOutcome {
    NotMine,
    Drop,
    Reply(Reply),
}

fn handle_heartbeat(state: &mut State, data: &[u8], src_ipv4: [u8; 4],
                    src_port: u16, now_ms: u64) -> Option<Reply> {
    let hdr = bedrock_echo_proto::Header::unpack(data).ok()?;
    let sid = hdr.sender_id;

    // Strict (src_ip, sender_id) match only (PROTOCOL.md §13.4,
    // witness-implementation §1.2). No sender_id-only fallback, no
    // new-node-join AEAD scan — those have been removed in polish.
    if let Some(i) = state.find_node_by_ip_and_sender(&src_ipv4, sid) {
        let cs = state.nodes[i].cluster_slot as usize;
        let cluster_key = state.clusters[cs].cluster_key;
        match try_handle_existing_node(
            state, data, src_ipv4, src_port, now_ms, i, cs, &cluster_key,
        ) {
            HbOutcome::NotMine | HbOutcome::Drop => return None,
            HbOutcome::Reply(r) => return Some(r),
        }
    }

    // No matching entry. Reply INIT (with fresh cookie) so the caller
    // can re-BOOTSTRAP — subject to per-IP 1/s INIT rate limit.
    if !state.allow_unknown(src_ipv4, now_ms) {
        return None;
    }
    let cookie = state.cookie_for(&src_ipv4);
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_init(
        &mut out,
        state.uptime_ms(now_ms) as i64,
        &state.witness_pub,
        &cookie,
        0,  // witness capability_flags — none allocated in Draft v0.x
    )
    .ok()?;
    Some(Reply { buf: out, len: n })
}

fn try_handle_existing_node(
    state: &mut State,
    data: &[u8],
    src_ipv4: [u8; 4],
    src_port: u16,
    now_ms: u64,
    node_idx: usize,
    cluster_slot: usize,
    cluster_key: &[u8; CLUSTER_KEY_LEN],
) -> HbOutcome {
    let mut buf = [0u8; MTU_CAP];
    if data.len() > buf.len() {
        return HbOutcome::NotMine;
    }
    buf[..data.len()].copy_from_slice(data);
    let work = &mut buf[..data.len()];

    let (hdr, qt, payload) = match msg::decode_heartbeat_into(work, cluster_key) {
        Ok(v) => v,
        Err(_) => return HbOutcome::NotMine,
    };

    // AEAD succeeded → this packet IS for this cluster_key. Any further
    // failure is a "drop", not a "try next candidate".
    if hdr.timestamp_ms <= state.nodes[node_idx].last_rx_timestamp {
        return HbOutcome::Drop;
    }
    let uptime_ms = state.uptime_ms(now_ms);
    if !state.adapt_cluster_offset(cluster_slot, hdr.timestamp_ms, uptime_ms) {
        return HbOutcome::Drop;
    }

    let payload_owned = match heapless::Vec::<u8, PAYLOAD_MAX_BYTES>::from_slice(payload) {
        Ok(v) => v,
        Err(_) => return HbOutcome::Drop,
    };

    {
        let n = &mut state.nodes[node_idx];
        n.sender_ipv4 = src_ipv4;
        n.sender_src_port = src_port;
        n.last_rx_ms = now_ms;
        n.last_rx_timestamp = hdr.timestamp_ms;
        n.payload_n_blocks = (payload.len() / PAYLOAD_BLOCK_SIZE) as u8;
        n.payload[..payload.len()].copy_from_slice(&payload_owned);
    }

    HbOutcome::Reply(build_heartbeat_reply(state, qt, cluster_slot, uptime_ms, *cluster_key))
}

fn build_heartbeat_reply(
    state: &mut State,
    query_target_id: u8,
    cluster_slot: usize,
    uptime_ms: u64,
    cluster_key: [u8; CLUSTER_KEY_LEN],
) -> Reply {
    let ts_out = state.next_tx_timestamp(cluster_slot, uptime_ms);
    let mut out = [0u8; MTU_CAP];

    if query_target_id == QUERY_LIST_SENTINEL {
        // Build STATUS_LIST including all members of this cluster.
        let cluster_offset = state.clusters[cluster_slot].cluster_offset;
        let now_cluster_ts = uptime_ms as i64 + cluster_offset;

        let mut entries: heapless::Vec<msg::ListEntry, LIST_MAX_ENTRIES> =
            heapless::Vec::new();
        for n in state.nodes.iter() {
            if !n.in_use || n.cluster_slot as usize != cluster_slot {
                continue;
            }
            let last_seen_ms = (now_cluster_ts - n.last_rx_timestamp).max(0) as u32;
            let _ = entries.push(msg::ListEntry {
                peer_sender_id: n.sender_id,
                last_seen_ms,
            });
            if entries.len() == LIST_MAX_ENTRIES {
                break;
            }
        }
        // Sort: most recently seen first
        entries.sort_by_key(|e| e.last_seen_ms);

        let n = msg::encode_status_list(
            &mut out,
            ts_out,
            (uptime_ms / 1000) as u32,
            &entries,
            &cluster_key,
        )
        .unwrap_or(0);
        return Reply { buf: out, len: n };
    }

    // STATUS_DETAIL for the queried target.
    let target_idx = state
        .nodes
        .iter()
        .position(|n| n.in_use && n.cluster_slot as usize == cluster_slot && n.sender_id == query_target_id);

    let n = if let Some(i) = target_idx {
        let cluster_offset = state.clusters[cluster_slot].cluster_offset;
        let now_cluster_ts = uptime_ms as i64 + cluster_offset;
        let target = &state.nodes[i];
        let peer_seen_ms_ago = (now_cluster_ts - target.last_rx_timestamp).max(0) as u32;
        let payload_len = (target.payload_n_blocks as usize) * PAYLOAD_BLOCK_SIZE;
        msg::encode_status_detail_found(
            &mut out,
            ts_out,
            (uptime_ms / 1000) as u32,
            query_target_id,
            &target.sender_ipv4,
            peer_seen_ms_ago,
            &target.payload[..payload_len],
            &cluster_key,
        )
        .unwrap_or(0)
    } else {
        msg::encode_status_detail_not_found(
            &mut out,
            ts_out,
            (uptime_ms / 1000) as u32,
            query_target_id,
            &cluster_key,
        )
        .unwrap_or(0)
    };
    Reply { buf: out, len: n }
}
