//! Witness state-machine tests for the Rust impl.
//!
//! Driven by hand-crafted packets through `handle()`. Doesn't open sockets.
//! Cookies are deterministic in tests via `State::new_with_cookies` with
//! fixed secrets.

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
const COOKIE_SECRET: [u8; 32] = [0xCCu8; 32];
const PREV_COOKIE_SECRET: [u8; 32] = [0xDDu8; 32];

fn fresh_state(t0: u64) -> State {
    State::new_with_cookies(WITNESS_PRIV, t0, COOKIE_SECRET, PREV_COOKIE_SECRET)
}

fn cookie_for(ip: [u8; 4]) -> [u8; 16] {
    crypto::derive_cookie(&COOKIE_SECRET, &ip)
}

fn cookie_for_with_secret(ip: [u8; 4], secret: &[u8; 32]) -> [u8; 16] {
    crypto::derive_cookie(secret, &ip)
}

fn encode_bootstrap_for(
    sender_id: u8,
    ts: i64,
    cluster_key: &[u8; 32],
    witness_pubkey: &[u8; 32],
    eph_priv: &[u8; 32],
    src_ip: [u8; 4],
) -> Vec<u8> {
    let cookie = cookie_for(src_ip);
    let mut out = vec![0u8; BOOTSTRAP_LEN];
    msg::encode_bootstrap(
        &mut out, sender_id, ts, cluster_key, witness_pubkey, eph_priv, &cookie,
    )
    .unwrap();
    out
}

fn encode_bootstrap_with_cookie(
    sender_id: u8,
    ts: i64,
    cluster_key: &[u8; 32],
    witness_pubkey: &[u8; 32],
    eph_priv: &[u8; 32],
    cookie: &[u8; 16],
) -> Vec<u8> {
    let mut out = vec![0u8; BOOTSTRAP_LEN];
    msg::encode_bootstrap(
        &mut out, sender_id, ts, cluster_key, witness_pubkey, eph_priv, cookie,
    )
    .unwrap();
    out
}

fn encode_heartbeat(
    sender_id: u8,
    ts: i64,
    query: u8,
    payload: &[u8],
    cluster_key: &[u8; 32],
) -> Vec<u8> {
    let total = HEADER_LEN + 2 + payload.len() + AEAD_TAG_LEN;
    let mut out = vec![0u8; total];
    msg::encode_heartbeat(&mut out, sender_id, ts, query, payload, cluster_key).unwrap();
    out
}

#[test]
fn bootstrap_creates_cluster_and_node() {
    let mut state = fresh_state(100_000);
    let src = [192, 168, 1, 10];
    let pkt = encode_bootstrap_for(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32], src,
    );
    let reply = handle(&mut state, &pkt, src, 50000, 100_001).unwrap();
    let mut rb = reply.as_slice().to_vec();
    let ack = msg::decode_bootstrap_ack(&mut rb, &CK).unwrap();
    assert_eq!(ack.status, 0x00); // new
    assert_eq!(state.node_count(), 1);
    assert_eq!(state.cluster_count(), 1);
}

#[test]
fn idempotent_rebootstrap_returns_status_01() {
    let mut state = fresh_state(100_000);
    let src = [192, 168, 1, 10];
    let pkt1 = encode_bootstrap_for(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32], src,
    );
    handle(&mut state, &pkt1, src, 50000, 100_001).unwrap();
    let pkt2 = encode_bootstrap_for(
        NODE_A, 1_700_000_001_000, &CK, &state.witness_pub.clone(), &[0xCCu8; 32], src,
    );
    let reply = handle(&mut state, &pkt2, src, 50000, 101_001).unwrap();
    let mut rb = reply.as_slice().to_vec();
    let ack = msg::decode_bootstrap_ack(&mut rb, &CK).unwrap();
    assert_eq!(ack.status, 0x01); // idempotent
    assert_eq!(state.node_count(), 1);
}

#[test]
fn collision_resolution_creates_second_entry() {
    let mut state = fresh_state(100_000);
    let src1 = [192, 168, 1, 10];
    let src2 = [192, 168, 1, 20];
    let p1 = encode_bootstrap_for(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32], src1,
    );
    handle(&mut state, &p1, src1, 50000, 100_001).unwrap();
    let p2 = encode_bootstrap_for(
        NODE_A, 1_700_000_001_000, &CK2, &state.witness_pub.clone(), &[0xCCu8; 32], src2,
    );
    handle(&mut state, &p2, src2, 50000, 101_001).unwrap();
    assert_eq!(state.node_count(), 2);
    assert_eq!(state.cluster_count(), 2);
}

#[test]
fn heartbeat_unknown_sender_returns_init_with_pubkey_and_cookie() {
    let mut state = fresh_state(100_000);
    let src = [192, 168, 1, 10];
    let pkt = encode_heartbeat(NODE_A, 1_700_000_000_000, 0xFF, &[], &CK);
    let reply = handle(&mut state, &pkt, src, 50000, 100_001).unwrap();
    let r = msg::decode_init(reply.as_slice()).unwrap();
    assert_eq!(r.witness_pubkey, &state.witness_pub);
    assert_eq!(r.cookie, &cookie_for(src));
}

#[test]
fn new_node_via_heartbeat_alone_returns_init_no_state() {
    // polish: no new-node-join via HEARTBEAT. Node B's HEARTBEAT,
    // even with valid cluster_key, MUST NOT create an entry.
    let mut state = fresh_state(100_000);
    let src_a = [192, 168, 1, 10];
    let src_b = [192, 168, 1, 20];
    let p_bs = encode_bootstrap_for(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32], src_a,
    );
    handle(&mut state, &p_bs, src_a, 50000, 100_001).unwrap();
    let p_hb = encode_heartbeat(NODE_B, 1_700_000_001_000, 0xFF, &[], &CK);
    let reply = handle(&mut state, &p_hb, src_b, 50000, 101_001).unwrap();
    assert_eq!(state.node_count(), 1); // only A
    let r = msg::decode_init(reply.as_slice()).unwrap();
    assert_eq!(r.cookie, &cookie_for(src_b));
}

#[test]
fn new_node_joins_via_bootstrap() {
    // The supported flow: new node joins by BOOTSTRAP, then HEARTBEATs.
    let mut state = fresh_state(100_000);
    let pubkey = state.witness_pub;
    let src_a = [192, 168, 1, 10];
    let src_b = [192, 168, 1, 20];
    let p_a = encode_bootstrap_for(
        NODE_A, 1_700_000_000_000, &CK, &pubkey, &[0xBBu8; 32], src_a,
    );
    let p_b = encode_bootstrap_for(
        NODE_B, 1_700_000_001_000, &CK, &pubkey, &[0xCCu8; 32], src_b,
    );
    handle(&mut state, &p_a, src_a, 50000, 100_001).unwrap();
    handle(&mut state, &p_b, src_b, 50000, 101_001).unwrap();
    assert_eq!(state.node_count(), 2);
    assert_eq!(state.cluster_count(), 1); // shared cluster
    // B's heartbeat now lists both
    let p_hb = encode_heartbeat(NODE_B, 1_700_000_001_100, 0xFF, &[], &CK);
    let r = handle(&mut state, &p_hb, src_b, 50000, 101_101).unwrap();
    let mut rb = r.as_slice().to_vec();
    let sl = msg::decode_status_list_into(&mut rb, &CK).unwrap();
    assert_eq!(sl.num_entries, 2);
}

#[test]
fn anti_replay_blocks_duplicate_timestamp() {
    let mut state = fresh_state(100_000);
    let src = [192, 168, 1, 10];
    let p_bs = encode_bootstrap_for(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(), &[0xBBu8; 32], src,
    );
    handle(&mut state, &p_bs, src, 50000, 100_001).unwrap();
    let p1 = encode_heartbeat(NODE_A, 1_700_000_000_100, 0xFF, &[], &CK);
    assert!(handle(&mut state, &p1, src, 50000, 100_002).is_some());
    // Replay same packet → silently dropped (no reply).
    assert!(handle(&mut state, &p1, src, 50000, 100_003).is_none());
    // Older timestamp → also dropped.
    let p_old = encode_heartbeat(NODE_A, 1_700_000_000_050, 0xFF, &[], &CK);
    assert!(handle(&mut state, &p_old, src, 50000, 100_004).is_none());
    // Newer → accepted.
    let p_new = encode_heartbeat(NODE_A, 1_700_000_000_200, 0xFF, &[], &CK);
    assert!(handle(&mut state, &p_new, src, 50000, 100_005).is_some());
}

#[test]
fn discover_replies_with_pubkey_and_cookie() {
    let mut state = fresh_state(100_000);
    let src = [192, 168, 1, 10];
    let mut out = vec![0u8; DISCOVER_LEN];
    msg::encode_discover(&mut out, NODE_A, 1_700_000_000_000).unwrap();
    let reply = handle(&mut state, &out, src, 50000, 100_001).unwrap();
    let r = msg::decode_init(reply.as_slice()).unwrap();
    assert_eq!(r.witness_pubkey, &state.witness_pub);
    assert_eq!(r.cookie, &cookie_for(src));
    // DISCOVER must NOT create a node entry.
    assert_eq!(state.node_count(), 0);
}

#[test]
fn discover_request_size_equals_init_reply_size() {
    // Anti-amp invariant (PROTOCOL.md §1 principle 13).
    let mut state = fresh_state(100_000);
    let src = [192, 168, 1, 10];
    let mut out = vec![0u8; DISCOVER_LEN];
    msg::encode_discover(&mut out, NODE_A, 1_700_000_000_000).unwrap();
    let reply = handle(&mut state, &out, src, 50000, 100_001).unwrap();
    assert_eq!(out.len(), 62);
    assert_eq!(reply.as_slice().len(), 62);
}

#[test]
fn bootstrap_with_bad_cookie_silently_dropped() {
    let mut state = fresh_state(100_000);
    let src = [192, 168, 1, 10];
    let bad_cookie = [0xAAu8; 16]; // not derived from any known secret
    let pkt = encode_bootstrap_with_cookie(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(),
        &[0xBBu8; 32], &bad_cookie,
    );
    let reply = handle(&mut state, &pkt, src, 50000, 100_001);
    assert!(reply.is_none());
    assert_eq!(state.node_count(), 0);
    assert_eq!(state.cluster_count(), 0);
}

#[test]
fn bootstrap_with_previous_cookie_secret_accepted() {
    let mut state = fresh_state(100_000);
    let src = [192, 168, 1, 10];
    let prev_cookie = cookie_for_with_secret(src, &PREV_COOKIE_SECRET);
    let pkt = encode_bootstrap_with_cookie(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(),
        &[0xBBu8; 32], &prev_cookie,
    );
    let reply = handle(&mut state, &pkt, src, 50000, 100_001).unwrap();
    let mut rb = reply.as_slice().to_vec();
    msg::decode_bootstrap_ack(&mut rb, &CK).unwrap();
    assert_eq!(state.node_count(), 1);
}

#[test]
fn cookie_bound_to_src_ip_not_just_secret() {
    // Cookie computed for one IP must NOT validate when sent from another.
    let mut state = fresh_state(100_000);
    let real_src = [192, 168, 1, 10];
    let attacker_src = [192, 168, 1, 99];
    let cookie_for_real = cookie_for(real_src);
    // Attacker sniffed/replays the cookie but sends from their own IP
    let pkt = encode_bootstrap_with_cookie(
        NODE_A, 1_700_000_000_000, &CK, &state.witness_pub.clone(),
        &[0xBBu8; 32], &cookie_for_real,
    );
    let reply = handle(&mut state, &pkt, attacker_src, 50000, 100_001);
    assert!(reply.is_none());
    assert_eq!(state.node_count(), 0);
}

#[test]
fn full_discover_bootstrap_heartbeat_flow() {
    let mut state = fresh_state(100_000);
    let src = [192, 168, 1, 10];

    // 1. DISCOVER → INIT with pubkey + cookie.
    let mut d_out = vec![0u8; DISCOVER_LEN];
    msg::encode_discover(&mut d_out, NODE_A, 1_700_000_000_000).unwrap();
    let r1 = handle(&mut state, &d_out, src, 50000, 100_001).unwrap();
    let init = msg::decode_init(r1.as_slice()).unwrap();
    let pubkey: [u8; 32] = *init.witness_pubkey;
    let cookie: [u8; 16] = *init.cookie;

    // 2. BOOTSTRAP carrying the witness's cookie → ACK.
    let bs_pkt = encode_bootstrap_with_cookie(
        NODE_A, 1_700_000_000_100, &CK, &pubkey, &[0xBBu8; 32], &cookie,
    );
    let r2 = handle(&mut state, &bs_pkt, src, 50000, 100_101).unwrap();
    let mut r2b = r2.as_slice().to_vec();
    let ack = msg::decode_bootstrap_ack(&mut r2b, &CK).unwrap();
    assert!(msg::status_is_new(ack.status));

    // 3. HEARTBEAT → STATUS_LIST with self-entry.
    let payload: Vec<u8> = (0..32).map(|i| i as u8).collect();
    let hb_pkt = encode_heartbeat(NODE_A, 1_700_000_000_200, 0xFF, &payload, &CK);
    let r3 = handle(&mut state, &hb_pkt, src, 50000, 100_201).unwrap();
    let mut r3b = r3.as_slice().to_vec();
    let r = msg::decode_status_list_into(&mut r3b, &CK).unwrap();
    assert_eq!(r.num_entries, 1);
    assert_eq!(r.entry(0).unwrap().peer_sender_id, NODE_A);
}

#[test]
fn ip_change_via_rebootstrap_updates_entry() {
    let mut state = fresh_state(100_000);
    let pubkey = state.witness_pub;
    let src1 = [192, 168, 1, 10];
    let src2 = [192, 168, 1, 99]; // simulated DHCP renewal
    let p1 = encode_bootstrap_for(
        NODE_A, 1_700_000_000_000, &CK, &pubkey, &[0xBBu8; 32], src1,
    );
    handle(&mut state, &p1, src1, 50000, 100_001).unwrap();
    // Re-BOOTSTRAP from new IP (cookie derived for that IP).
    let p2 = encode_bootstrap_for(
        NODE_A, 1_700_000_000_100, &CK, &pubkey, &[0xCCu8; 32], src2,
    );
    let r = handle(&mut state, &p2, src2, 50000, 100_101).unwrap();
    let mut rb = r.as_slice().to_vec();
    let ack = msg::decode_bootstrap_ack(&mut rb, &CK).unwrap();
    assert!(msg::status_is_idempotent(ack.status));
    assert_eq!(state.node_count(), 1);
    let n = state.nodes.iter().find(|n| n.in_use).unwrap();
    assert_eq!(n.sender_ipv4, src2);
}

#[test]
fn heartbeat_from_new_ip_does_not_silently_take_over() {
    // Strict (src_ip, sender_id) match: a HEARTBEAT spoofing the
    // sender_id from a DIFFERENT IP must NOT update the stored IP.
    let mut state = fresh_state(100_000);
    let pubkey = state.witness_pub;
    let real_src = [192, 168, 1, 10];
    let attacker_src = [192, 168, 1, 99];
    let p_bs = encode_bootstrap_for(
        NODE_A, 1_700_000_000_000, &CK, &pubkey, &[0xBBu8; 32], real_src,
    );
    handle(&mut state, &p_bs, real_src, 50000, 100_001).unwrap();
    let p_hb = encode_heartbeat(NODE_A, 1_700_000_000_100, 0xFF, &[], &CK);
    let reply = handle(&mut state, &p_hb, attacker_src, 50000, 100_002);
    // Witness replied INIT (offering a fresh cookie for the new IP).
    let r = reply.unwrap();
    msg::decode_init(r.as_slice()).unwrap();
    // But the original entry's stored IP is unchanged.
    let n = state.nodes.iter().find(|n| n.in_use).unwrap();
    assert_eq!(n.sender_ipv4, real_src);
}
