//! Packet dispatch for the witness — pure logic, no socket I/O.
//!
//! `handle(state, data, src_ip, src_port, now_ms)` consumes one inbound
//! UDP datagram and returns 0 or 1 reply bytes. Driving from a UDP loop:
//!     for reply in handle(...) { sock.sendto(reply.as_slice(), src) }
//!
//! Implements the v1 dispatch and lookup chain:
//!   1. IP-first + sender_id → AEAD trial decrypt against cluster_keys
//!   2. Fallback: sender_id only (handles IP change)
//!   3. Fallback: AEAD trial against every cluster_key (new-node-join)

use bedrock_echo_proto::constants::*;
use bedrock_echo_proto::msg;

use crate::state::{State, MAX_NODES};

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
    msg::decode_discover(data).ok()?;
    if !state.allow_unknown(src_ipv4, now_ms) {
        return None;
    }
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_unknown_source(
        &mut out,
        state.uptime_ms(now_ms) as i64,
        &state.witness_pub,
    )
    .ok()?;
    Some(Reply { buf: out, len: n })
}

// ── BOOTSTRAP ─────────────────────────────────────────────────────────────

fn handle_bootstrap(state: &mut State, data: &[u8], src_ipv4: [u8; 4],
                    src_port: u16, now_ms: u64) -> Option<Reply> {
    // We need to copy `data` into a mutable buffer for in-place AEAD decrypt.
    let mut buf = [0u8; MTU_CAP];
    if data.len() > buf.len() {
        return None;
    }
    buf[..data.len()].copy_from_slice(data);
    let work = &mut buf[..data.len()];
    let (hdr, cluster_key) = msg::decode_bootstrap(work, &state.witness_priv).ok()?;

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

/// Outcome of a single AEAD trial in the dispatch chain.
enum HbOutcome {
    NotMine,       // AEAD failed under this cluster_key — try next
    Drop,          // AEAD succeeded but the packet should be silently dropped
    Reply(Reply),  // accepted; here is the reply
}

fn handle_heartbeat(state: &mut State, data: &[u8], src_ipv4: [u8; 4],
                    src_port: u16, now_ms: u64) -> Option<Reply> {
    let hdr = bedrock_echo_proto::Header::unpack(data).ok()?;
    let sid = hdr.sender_id;

    // Pass 1: candidates by (src_ip, sender_id), then sender_id only.
    let mut candidates: heapless::Vec<usize, MAX_NODES> = heapless::Vec::new();
    if let Some(i) = state.find_node_by_ip_and_sender(&src_ipv4, sid) {
        let _ = candidates.push(i);
    }
    if candidates.is_empty() {
        for i in state.find_nodes_by_sender(sid) {
            let _ = candidates.push(i);
        }
    }

    for &cand_idx in candidates.iter() {
        let cs = state.nodes[cand_idx].cluster_slot as usize;
        let cluster_key = state.clusters[cs].cluster_key;
        match try_handle_existing_node(
            state, data, src_ipv4, src_port, now_ms, cand_idx, cs, &cluster_key,
        ) {
            HbOutcome::NotMine => continue,
            HbOutcome::Drop => return None,
            HbOutcome::Reply(r) => return Some(r),
        }
    }

    // Pass 2: new-node-join scan. Try AEAD against every cluster_key.
    let cluster_count = state.clusters.len();
    for cs in 0..cluster_count {
        if !state.clusters[cs].in_use {
            continue;
        }
        let cluster_key = state.clusters[cs].cluster_key;
        match try_handle_new_node(
            state, data, src_ipv4, src_port, now_ms, sid, cs, &cluster_key,
        ) {
            HbOutcome::NotMine => continue,
            HbOutcome::Drop => return None,
            HbOutcome::Reply(r) => return Some(r),
        }
    }

    // Nothing matched — UNKNOWN_SOURCE if rate limit allows.
    if !state.allow_unknown(src_ipv4, now_ms) {
        return None;
    }
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_unknown_source(
        &mut out,
        state.uptime_ms(now_ms) as i64,
        &state.witness_pub,
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

fn try_handle_new_node(
    state: &mut State,
    data: &[u8],
    src_ipv4: [u8; 4],
    src_port: u16,
    now_ms: u64,
    sender_id: u8,
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

    // Belt-and-suspenders: if pass 1 didn't find an entry but one already
    // exists for (sender_id, this cluster), don't double-allocate.
    if state.nodes.iter().any(|n|
        n.in_use && n.sender_id == sender_id && n.cluster_slot as usize == cluster_slot
    ) {
        return HbOutcome::Drop;
    }

    let uptime_ms = state.uptime_ms(now_ms);
    if !state.adapt_cluster_offset(cluster_slot, hdr.timestamp_ms, uptime_ms) {
        return HbOutcome::Drop;
    }

    let ns = match state.allocate_node_slot() {
        Some(s) => s,
        None => return HbOutcome::Drop,
    };
    let payload_owned = match heapless::Vec::<u8, PAYLOAD_MAX_BYTES>::from_slice(payload) {
        Ok(v) => v,
        Err(_) => return HbOutcome::Drop,
    };
    state.nodes[ns] = crate::state::NodeEntry {
        in_use: true,
        sender_id,
        sender_ipv4: src_ipv4,
        sender_src_port: src_port,
        cluster_slot: cluster_slot as u16,
        last_rx_ms: now_ms,
        last_rx_timestamp: hdr.timestamp_ms,
        payload_n_blocks: (payload.len() / PAYLOAD_BLOCK_SIZE) as u8,
        payload: [0; PAYLOAD_MAX_BYTES],
    };
    state.nodes[ns].payload[..payload.len()].copy_from_slice(&payload_owned);
    state.clusters[cluster_slot].num_nodes =
        state.clusters[cluster_slot].num_nodes.saturating_add(1);

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
