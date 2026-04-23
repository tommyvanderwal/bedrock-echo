//! Packet dispatch for the witness. Pure logic — no socket I/O. Takes a
//! packet buffer + source IP + current time; returns a reply (or nothing).

use bedrock_echo_proto::constants::*;
use bedrock_echo_proto::msg;

use crate::state::{State, MAX_NODES, MAX_CLUSTERS};

/// Reply buffer. The outer caller writes these bytes to the UDP socket.
pub struct Reply {
    pub buf: [u8; MTU_CAP],
    pub len: usize,
}

impl Reply {
    pub fn as_slice(&self) -> &[u8] { &self.buf[..self.len] }
}

pub fn handle(state: &mut State, data: &[u8], src_ipv4: [u8; 4], now_ms: u64) -> Option<Reply> {
    if data.len() > MTU_CAP || data.len() < HEADER_LEN { return None; }
    state.age_out(now_ms);
    if !state.allow(src_ipv4, now_ms) { return None; }

    let hdr = bedrock_echo_proto::Header::unpack(data).ok()?;
    let expected = hdr.expected_total_len()?;
    if data.len() != expected { return None; }

    match hdr.msg_type {
        MSG_BOOTSTRAP => handle_bootstrap(state, data, src_ipv4, now_ms),
        MSG_HEARTBEAT => handle_heartbeat(state, data, src_ipv4, now_ms),
        _ => None, // witness doesn't accept other msg types from nodes
    }
}

fn handle_bootstrap(state: &mut State, data: &[u8], src_ipv4: [u8; 4], now_ms: u64) -> Option<Reply> {
    let d = msg::decode_bootstrap(data, &state.witness_priv).ok()?;

    let existing_idx = state.find_node(&d.header.sender_id);
    let (cluster_slot, status) = match existing_idx {
        Some(i) => {
            let cs = state.nodes[i].cluster_slot as usize;
            if cs >= MAX_CLUSTERS || !state.clusters[cs].in_use { return None; }
            if state.clusters[cs].cluster_key != d.plaintext.cluster_key {
                // sender_id collision with different cluster_key → silent drop
                return None;
            }
            // Idempotent re-bootstrap: reset sequence tracking
            state.nodes[i].last_rx_ms = now_ms;
            state.nodes[i].last_rx_sequence = 0;
            state.nodes[i].last_tx_sequence = 0;
            state.nodes[i].sender_ipv4 = src_ipv4;
            (cs, 0x01u8)
        }
        None => {
            if state.node_count() >= MAX_NODES { return None; }
            let cs = if let Some(k) = state.find_cluster_by_key(&d.plaintext.cluster_key) {
                k
            } else {
                let slot = state.allocate_cluster_slot()?;
                state.clusters[slot] = crate::state::ClusterEntry {
                    in_use: true,
                    cluster_key: d.plaintext.cluster_key,
                    bootstrapped_ms: now_ms,
                    num_nodes: 0,
                };
                slot
            };
            let ns = state.allocate_node_slot()?;
            let mut pl = [0u8; NODE_PAYLOAD_MAX];
            let ipl = d.plaintext.init_payload_len;
            pl[..ipl].copy_from_slice(&d.plaintext.init_payload[..ipl]);
            state.nodes[ns] = crate::state::NodeEntry {
                in_use: true,
                sender_id: d.header.sender_id,
                sender_ipv4: src_ipv4,
                cluster_slot: cs as u8,
                last_rx_ms: now_ms,
                last_rx_sequence: 0,
                last_tx_sequence: 0,
                payload_len: ipl as u8,
                payload: pl,
            };
            state.clusters[cs].num_nodes = state.clusters[cs].num_nodes.saturating_add(1);
            (cs, 0x00u8)
        }
    };

    let cluster_key = state.clusters[cluster_slot].cluster_key;
    let node_idx = state.find_node(&d.header.sender_id)?;
    state.nodes[node_idx].last_tx_sequence =
        core::cmp::max(now_ms, state.nodes[node_idx].last_tx_sequence + 1);
    let seq = state.nodes[node_idx].last_tx_sequence;
    let uptime = state.uptime_ms(now_ms);

    let mut reply = Reply { buf: [0u8; MTU_CAP], len: 0 };
    reply.len = msg::encode_bootstrap_ack(
        &mut reply.buf,
        state.witness_sender_id,
        seq,
        now_ms as i64,
        status,
        uptime,
        &cluster_key,
    ).ok()?;
    Some(reply)
}

fn handle_heartbeat(state: &mut State, data: &[u8], src_ipv4: [u8; 4], now_ms: u64) -> Option<Reply> {
    let hdr = bedrock_echo_proto::Header::unpack(data).ok()?;
    let Some(node_idx) = state.find_node(&hdr.sender_id) else {
        return maybe_unknown_source(state, src_ipv4, now_ms);
    };
    let cs = state.nodes[node_idx].cluster_slot as usize;
    if cs >= MAX_CLUSTERS || !state.clusters[cs].in_use {
        state.nodes[node_idx].in_use = false;
        return maybe_unknown_source(state, src_ipv4, now_ms);
    }
    let cluster_key = state.clusters[cs].cluster_key;

    let hb = match msg::decode_heartbeat(data, &cluster_key) {
        Ok(v) => v,
        Err(bedrock_echo_proto::Error::AuthFailed) => {
            return maybe_unknown_source(state, src_ipv4, now_ms);
        }
        Err(_) => return None,
    };

    if hb.header.sequence <= state.nodes[node_idx].last_rx_sequence {
        return None;
    }
    state.nodes[node_idx].last_rx_sequence = hb.header.sequence;
    state.nodes[node_idx].last_rx_ms = now_ms;
    state.nodes[node_idx].sender_ipv4 = src_ipv4;
    let pl_len = hb.own_payload.len();
    state.nodes[node_idx].payload_len = pl_len as u8;
    state.nodes[node_idx].payload[..pl_len].copy_from_slice(hb.own_payload);

    let uptime = state.uptime_ms(now_ms);
    state.nodes[node_idx].last_tx_sequence =
        core::cmp::max(now_ms, state.nodes[node_idx].last_tx_sequence + 1);
    let seq = state.nodes[node_idx].last_tx_sequence;

    let mut reply = Reply { buf: [0u8; MTU_CAP], len: 0 };

    if hb.query_target_id == [0u8; 8] {
        // STATUS_LIST reply — collect entries from this cluster
        let mut entries: [msg::ListEntry; MAX_NODES] = [msg::ListEntry {
            peer_sender_id: [0; 8], peer_ipv4: [0; 4], last_seen_seconds: 0,
        }; MAX_NODES];
        let mut n = 0;
        for p in state.nodes.iter() {
            if p.in_use && p.cluster_slot as usize == cs && n < MAX_NODES {
                entries[n] = msg::ListEntry {
                    peer_sender_id: p.sender_id,
                    peer_ipv4: p.sender_ipv4,
                    last_seen_seconds: ((now_ms.saturating_sub(p.last_rx_ms)) / 1000).min(u32::MAX as u64) as u32,
                };
                n += 1;
            }
        }
        // sort by last_seen_seconds ascending
        entries[..n].sort_by_key(|e| e.last_seen_seconds);

        reply.len = msg::encode_status_list(
            &mut reply.buf,
            state.witness_sender_id,
            seq,
            now_ms as i64,
            uptime,
            &entries[..n],
            &cluster_key,
        ).ok()?;
    } else {
        // STATUS_DETAIL for a specific target in same cluster
        let target = hb.query_target_id;
        let mut found: Option<usize> = None;
        for (i, p) in state.nodes.iter().enumerate() {
            if p.in_use && p.cluster_slot as usize == cs && p.sender_id == target {
                found = Some(i);
                break;
            }
        }
        reply.len = match found {
            Some(i) => msg::encode_status_detail_found(
                &mut reply.buf,
                state.witness_sender_id, seq, now_ms as i64, uptime,
                &target, &state.nodes[i].sender_ipv4,
                ((now_ms.saturating_sub(state.nodes[i].last_rx_ms)) / 1000).min(u32::MAX as u64) as u32,
                &state.nodes[i].payload[..state.nodes[i].payload_len as usize],
                &cluster_key,
            ).ok()?,
            None => msg::encode_status_detail_not_found(
                &mut reply.buf,
                state.witness_sender_id, seq, now_ms as i64, uptime,
                &target, &cluster_key,
            ).ok()?,
        };
    }
    Some(reply)
}

fn maybe_unknown_source(state: &mut State, src_ipv4: [u8; 4], now_ms: u64) -> Option<Reply> {
    if !state.allow_unknown(src_ipv4, now_ms) { return None; }
    let mut reply = Reply { buf: [0u8; MTU_CAP], len: 0 };
    reply.len = msg::encode_unknown_source(
        &mut reply.buf,
        state.witness_sender_id,
        now_ms,
        now_ms as i64,
    ).ok()?;
    Some(reply)
}
