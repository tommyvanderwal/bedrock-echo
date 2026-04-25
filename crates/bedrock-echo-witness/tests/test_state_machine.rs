//! Witness state-machine tests for the Rust impl.
//!
//! Driven by hand-crafted packets through `handle()`. Doesn't open sockets.

use bedrock_echo_proto::*;
use bedrock_echo_witness::handler::handle;
use bedrock_echo_witness::state::State;

const CK: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
    0x2E, 0x2F,
];
const CK2: [u8; 32] = [0x99u8; 32];

const NODE_A: u8 = 0x01;
const NODE_B: u8 = 0x02;

const WITNESS_PRIV: [u8; 32] = [0xAAu8; 32];

fn encode_bootstrap_with_eph(sender_id: u8, ts: i64, cluster_key: &[u8; 32],
                              witness_pubkey: &[u8; 32], eph_priv: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; BOOTSTRAP_LEN];
    msg::encode_bootstrap(&mut out, sender_id, ts, cluster_key, witness_pubkey, eph_priv).unwrap();
    out
}

fn encode_heartbeat(sender_id: u8, ts: i64, query: u8, payload: &[u8],
                     cluster_key: &[u8; 32]) -> Vec<u8> {
    let total = HEADER_LEN + 2 + payload.len() + AEAD_TAG_LEN;
    let mut out = vec![0u8; total];
    msg::encode_heartbeat(&mut out, sender_id, ts, query, payload, cluster_key).unwrap();
    out
}

#[test]
fn bootstrap_creates_cluster_and_node() {
    let mut state = State::new(WITNESS_PRIV, 100_000);
    let pkt = encode_bootstrap_with_eph(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32],
    );
    let reply = handle(&mut state, &pkt, [192, 168, 1, 10], 50000, 100_001).unwrap();
    let mut rb = reply.as_slice().to_vec();
    let ack = msg::decode_bootstrap_ack(&mut rb, &CK).unwrap();
    assert_eq!(ack.status, 0x00); // new
    assert_eq!(state.node_count(), 1);
    assert_eq!(state.cluster_count(), 1);
}

#[test]
fn idempotent_rebootstrap_returns_status_01() {
    let mut state = State::new(WITNESS_PRIV, 100_000);
    let pkt1 = encode_bootstrap_with_eph(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32],
    );
    handle(&mut state, &pkt1, [192, 168, 1, 10], 50000, 100_001).unwrap();
    let pkt2 = encode_bootstrap_with_eph(
        NODE_A, 1_700_000_001_000, &CK, &state.witness_pub.clone(), &[0xCCu8; 32],
    );
    let reply = handle(&mut state, &pkt2, [192, 168, 1, 10], 50000, 101_001).unwrap();
    let mut rb = reply.as_slice().to_vec();
    let ack = msg::decode_bootstrap_ack(&mut rb, &CK).unwrap();
    assert_eq!(ack.status, 0x01); // idempotent
    assert_eq!(state.node_count(), 1);
}

#[test]
fn collision_resolution_creates_second_entry() {
    let mut state = State::new(WITNESS_PRIV, 100_000);
    let p1 = encode_bootstrap_with_eph(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32],
    );
    handle(&mut state, &p1, [192, 168, 1, 10], 50000, 100_001).unwrap();
    let p2 = encode_bootstrap_with_eph(
        NODE_A, 1_700_000_001_000, &CK2, &state.witness_pub.clone(), &[0xCCu8; 32],
    );
    handle(&mut state, &p2, [192, 168, 1, 20], 50000, 101_001).unwrap();
    assert_eq!(state.node_count(), 2);
    assert_eq!(state.cluster_count(), 2);
}

#[test]
fn heartbeat_unknown_sender_returns_unknown_source_with_pubkey() {
    let mut state = State::new(WITNESS_PRIV, 100_000);
    let pkt = encode_heartbeat(NODE_A, 1_700_000_000_000, 0xFF, &[], &CK);
    let reply = handle(&mut state, &pkt, [192, 168, 1, 10], 50000, 100_001).unwrap();
    let r = msg::decode_unknown_source(reply.as_slice()).unwrap();
    assert_eq!(r.witness_pubkey, &state.witness_pub);
}

#[test]
fn new_node_join_existing_cluster_via_heartbeat() {
    let mut state = State::new(WITNESS_PRIV, 100_000);
    // Node A bootstraps.
    let p_bs = encode_bootstrap_with_eph(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32],
    );
    handle(&mut state, &p_bs, [192, 168, 1, 10], 50000, 100_001).unwrap();
    // Node B sends a HEARTBEAT directly — no BOOTSTRAP.
    let p_hb = encode_heartbeat(NODE_B, 1_700_000_001_000, 0xFF, &[], &CK);
    let reply = handle(&mut state, &p_hb, [192, 168, 1, 20], 50000, 101_001).unwrap();
    // Witness should have added B and replied with STATUS_LIST.
    assert_eq!(state.node_count(), 2);
    let mut rb = reply.as_slice().to_vec();
    let r = msg::decode_status_list_into(&mut rb, &CK).unwrap();
    assert_eq!(r.num_entries, 2);
}

#[test]
fn anti_replay_blocks_duplicate_timestamp() {
    let mut state = State::new(WITNESS_PRIV, 100_000);
    let p_bs = encode_bootstrap_with_eph(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32],
    );
    handle(&mut state, &p_bs, [192, 168, 1, 10], 50000, 100_001).unwrap();
    let p1 = encode_heartbeat(NODE_A, 1_700_000_000_100, 0xFF, &[], &CK);
    assert!(handle(&mut state, &p1, [192, 168, 1, 10], 50000, 100_002).is_some());
    // Replay same packet → silently dropped (no reply).
    assert!(handle(&mut state, &p1, [192, 168, 1, 10], 50000, 100_003).is_none());
    // Older timestamp → also dropped.
    let p_old = encode_heartbeat(NODE_A, 1_700_000_000_050, 0xFF, &[], &CK);
    assert!(handle(&mut state, &p_old, [192, 168, 1, 10], 50000, 100_004).is_none());
    // Newer → accepted.
    let p_new = encode_heartbeat(NODE_A, 1_700_000_000_200, 0xFF, &[], &CK);
    assert!(handle(&mut state, &p_new, [192, 168, 1, 10], 50000, 100_005).is_some());
}

#[test]
fn discover_replies_with_pubkey() {
    let mut state = State::new(WITNESS_PRIV, 100_000);
    let mut out = vec![0u8; HEADER_LEN];
    msg::encode_discover(&mut out, NODE_A, 1_700_000_000_000).unwrap();
    let reply = handle(&mut state, &out, [192, 168, 1, 10], 50000, 100_001).unwrap();
    let r = msg::decode_unknown_source(reply.as_slice()).unwrap();
    assert_eq!(r.witness_pubkey, &state.witness_pub);
    // Must NOT create a node entry.
    assert_eq!(state.node_count(), 0);
}

#[test]
fn full_discover_bootstrap_heartbeat_flow() {
    let mut state = State::new(WITNESS_PRIV, 100_000);
    let src = [192, 168, 1, 10];

    // 1. DISCOVER → UNKNOWN_SOURCE with pubkey.
    let mut d_out = vec![0u8; HEADER_LEN];
    msg::encode_discover(&mut d_out, NODE_A, 1_700_000_000_000).unwrap();
    let r1 = handle(&mut state, &d_out, src, 50000, 100_001).unwrap();
    let pub_from_witness = msg::decode_unknown_source(r1.as_slice())
        .unwrap()
        .witness_pubkey
        .clone();

    // 2. BOOTSTRAP using discovered pubkey → ACK.
    let bs_pkt = encode_bootstrap_with_eph(
        NODE_A, 1_700_000_000_100, &CK, &pub_from_witness, &[0xBBu8; 32],
    );
    let r2 = handle(&mut state, &bs_pkt, src, 50000, 100_101).unwrap();
    let mut r2b = r2.as_slice().to_vec();
    let ack = msg::decode_bootstrap_ack(&mut r2b, &CK).unwrap();
    assert!(status_is_new(ack.status));

    // 3. HEARTBEAT → STATUS_LIST with self-entry.
    let payload: Vec<u8> = (0..32).map(|i| i as u8).collect();
    let hb_pkt = encode_heartbeat(NODE_A, 1_700_000_000_200, 0xFF, &payload, &CK);
    let r3 = handle(&mut state, &hb_pkt, src, 50000, 100_201).unwrap();
    let mut r3b = r3.as_slice().to_vec();
    let r = msg::decode_status_list_into(&mut r3b, &CK).unwrap();
    assert_eq!(r.num_entries, 1);
    assert_eq!(r.entry(0).unwrap().peer_sender_id, NODE_A);
}

fn status_is_new(status: u8) -> bool {
    msg::status_is_new(status)
}
