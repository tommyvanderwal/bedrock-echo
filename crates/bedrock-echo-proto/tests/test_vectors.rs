//! Cross-language test-vector validation for the Rust implementation.
//!
//! Loads each `.in.json` + `.out.bin` pair from `testvectors/`, verifies
//! that the Rust encoder produces byte-exact `.out.bin`, and that decoding
//! `.out.bin` round-trips to the same fields.

use std::fs;
use std::path::PathBuf;

use bedrock_echo_proto::*;
use serde_json::Value;

fn vector_dir() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent().unwrap().parent().unwrap().join("testvectors")
}

fn load_vector(name: &str) -> (Value, Vec<u8>) {
    let dir = vector_dir();
    let json_path = dir.join(format!("{name}.in.json"));
    let bin_path = dir.join(format!("{name}.out.bin"));
    let json = serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
    let bin = fs::read(&bin_path).unwrap();
    (json, bin)
}

fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn hex_to_arr32(s: &str) -> [u8; 32] {
    let v = hex_to_vec(s);
    assert_eq!(v.len(), 32);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn ipv4_str_to_bytes(s: &str) -> [u8; 4] {
    let parts: Vec<u8> = s.split('.').map(|p| p.parse().unwrap()).collect();
    [parts[0], parts[1], parts[2], parts[3]]
}

fn hex_to_arr16(s: &str) -> [u8; 16] {
    let v = hex_to_vec(s);
    assert_eq!(v.len(), 16);
    let mut a = [0u8; 16];
    a.copy_from_slice(&v);
    a
}

#[test]
fn vector_01_heartbeat_list_query() {
    let (j, expected) = load_vector("01_heartbeat_list_query");
    let ck = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let payload = hex_to_vec(j["own_payload"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    let n = msg::encode_heartbeat(
        &mut out,
        j["sender_id"].as_u64().unwrap() as u8,
        j["timestamp_ms"].as_i64().unwrap(),
        j["query_target_id"].as_u64().unwrap() as u8,
        &payload,
        &ck,
    )
    .unwrap();
    assert_eq!(n, expected.len());
    assert_eq!(out, expected);

    // round-trip decode
    let mut buf = expected.clone();
    let (hdr, qt, pl) = msg::decode_heartbeat_into(&mut buf, &ck).unwrap();
    assert_eq!(hdr.sender_id, j["sender_id"].as_u64().unwrap() as u8);
    assert_eq!(qt, j["query_target_id"].as_u64().unwrap() as u8);
    assert_eq!(pl, payload.as_slice());
}

#[test]
fn vector_02_heartbeat_detail_query() {
    let (j, expected) = load_vector("02_heartbeat_detail_query");
    let ck = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let payload = hex_to_vec(j["own_payload"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    msg::encode_heartbeat(
        &mut out,
        j["sender_id"].as_u64().unwrap() as u8,
        j["timestamp_ms"].as_i64().unwrap(),
        j["query_target_id"].as_u64().unwrap() as u8,
        &payload,
        &ck,
    )
    .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn vector_03_heartbeat_self_query() {
    let (j, expected) = load_vector("03_heartbeat_self_query");
    let ck = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let payload = hex_to_vec(j["own_payload"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    msg::encode_heartbeat(
        &mut out,
        j["sender_id"].as_u64().unwrap() as u8,
        j["timestamp_ms"].as_i64().unwrap(),
        j["query_target_id"].as_u64().unwrap() as u8,
        &payload,
        &ck,
    )
    .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn vector_04_status_list_two_nodes() {
    let (j, expected) = load_vector("04_status_list_two_nodes");
    let ck = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let entries: Vec<msg::ListEntry> = j["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| msg::ListEntry {
            peer_sender_id: e["peer_sender_id"].as_u64().unwrap() as u8,
            last_seen_ms: e["last_seen_ms"].as_u64().unwrap() as u32,
        })
        .collect();
    let mut out = vec![0u8; expected.len()];
    msg::encode_status_list(
        &mut out,
        j["timestamp_ms"].as_i64().unwrap(),
        j["witness_uptime_seconds"].as_u64().unwrap() as u32,
        &entries,
        &ck,
    )
    .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn vector_05_status_list_empty() {
    let (j, expected) = load_vector("05_status_list_empty");
    let ck = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    msg::encode_status_list(
        &mut out,
        j["timestamp_ms"].as_i64().unwrap(),
        j["witness_uptime_seconds"].as_u64().unwrap() as u32,
        &[],
        &ck,
    )
    .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn vector_06_status_detail_found() {
    let (j, expected) = load_vector("06_status_detail_found");
    let ck = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let peer_payload = hex_to_vec(j["peer_payload"].as_str().unwrap());
    let peer_ipv4 = ipv4_str_to_bytes(j["peer_ipv4"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    msg::encode_status_detail_found(
        &mut out,
        j["timestamp_ms"].as_i64().unwrap(),
        j["witness_uptime_seconds"].as_u64().unwrap() as u32,
        j["target_sender_id"].as_u64().unwrap() as u8,
        &peer_ipv4,
        j["peer_seen_ms_ago"].as_u64().unwrap() as u32,
        &peer_payload,
        &ck,
    )
    .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn vector_07_status_detail_not_found() {
    let (j, expected) = load_vector("07_status_detail_not_found");
    let ck = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    msg::encode_status_detail_not_found(
        &mut out,
        j["timestamp_ms"].as_i64().unwrap(),
        j["witness_uptime_seconds"].as_u64().unwrap() as u32,
        j["target_sender_id"].as_u64().unwrap() as u8,
        &ck,
    )
    .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn vector_08_discover() {
    let (j, expected) = load_vector("08_discover");
    let mut out = vec![0u8; expected.len()];
    msg::encode_discover(
        &mut out,
        j["sender_id"].as_u64().unwrap() as u8,
        j["timestamp_ms"].as_i64().unwrap(),
        j["capability_flags"].as_u64().unwrap() as u16,
    )
    .unwrap();
    assert_eq!(out, expected);

    let (_hdr, caps) = msg::decode_discover(&expected).unwrap();
    assert_eq!(caps as u64, j["capability_flags"].as_u64().unwrap());
}

#[test]
fn vector_09_init() {
    let (j, expected) = load_vector("09_init");
    let pub_arr = hex_to_arr32(j["witness_pubkey"].as_str().unwrap());
    let cookie = hex_to_arr16(j["cookie"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    msg::encode_init(
        &mut out,
        j["timestamp_ms"].as_i64().unwrap(),
        &pub_arr,
        &cookie,
        j["capability_flags"].as_u64().unwrap() as u16,
    )
    .unwrap();
    assert_eq!(out, expected);

    // Cross-check: cookie is SHA-256(witness_cookie_secret || src_ip)[:16].
    let secret = hex_to_arr32(j["witness_cookie_secret"].as_str().unwrap());
    let src_ip = ipv4_str_to_bytes(j["src_ip"].as_str().unwrap());
    let derived = crypto::derive_cookie(&secret, &src_ip);
    assert_eq!(derived, cookie);

    // Round-trip decode
    let r = msg::decode_init(&expected).unwrap();
    assert_eq!(r.cookie, &cookie);
    assert_eq!(r.witness_pubkey, &pub_arr);
    assert_eq!(r.capability_flags as u64, j["capability_flags"].as_u64().unwrap());
}

#[test]
fn vector_10_bootstrap() {
    let (j, expected) = load_vector("10_bootstrap");
    let cluster_key = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let witness_pubkey = hex_to_arr32(j["witness_pubkey"].as_str().unwrap());
    let eph_priv = hex_to_arr32(j["eph_priv"].as_str().unwrap());
    let cookie = hex_to_arr16(j["cookie"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    msg::encode_bootstrap(
        &mut out,
        j["sender_id"].as_u64().unwrap() as u8,
        j["timestamp_ms"].as_i64().unwrap(),
        &cluster_key,
        &witness_pubkey,
        &eph_priv,
        &cookie,
    )
    .unwrap();
    assert_eq!(out, expected);

    // Decode requires witness_priv (deterministic seed used in the generator).
    let witness_priv = [0xAAu8; 32];
    let mut buf = expected.clone();
    let (_hdr, decoded_cookie, decoded_ck) =
        msg::decode_bootstrap(&mut buf, &witness_priv).unwrap();
    assert_eq!(decoded_ck, cluster_key);
    assert_eq!(decoded_cookie, cookie);
}

#[test]
fn vector_11_bootstrap_ack_new() {
    let (j, expected) = load_vector("11_bootstrap_ack_new");
    let ck = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    msg::encode_bootstrap_ack(
        &mut out,
        j["timestamp_ms"].as_i64().unwrap(),
        j["status"].as_u64().unwrap() as u8,
        j["witness_uptime_seconds"].as_u64().unwrap() as u32,
        &ck,
    )
    .unwrap();
    assert_eq!(out, expected);
}

#[test]
fn vector_12_bootstrap_ack_rebootstrap() {
    let (j, expected) = load_vector("12_bootstrap_ack_rebootstrap");
    let ck = hex_to_arr32(j["cluster_key"].as_str().unwrap());
    let mut out = vec![0u8; expected.len()];
    msg::encode_bootstrap_ack(
        &mut out,
        j["timestamp_ms"].as_i64().unwrap(),
        j["status"].as_u64().unwrap() as u8,
        j["witness_uptime_seconds"].as_u64().unwrap() as u32,
        &ck,
    )
    .unwrap();
    assert_eq!(out, expected);
}

// ── nonce derivation unit tests ──────────────────────────────────────────

#[test]
fn nonce_derivation_layout() {
    let n = derive_nonce(0x01, 0x0102030405060708);
    assert_eq!(n[0], 0x01);
    assert_eq!(&n[1..4], &[0u8, 0u8, 0u8]);
    assert_eq!(&n[4..12], &0x0102030405060708i64.to_be_bytes());
}

#[test]
fn nonce_distinguishes_witness_vs_node() {
    let nn = derive_nonce(0x01, 1234);
    let nw = derive_nonce(0xFF, 1234);
    assert_ne!(nn, nw);
}

#[test]
fn nonce_distinguishes_consecutive_packets() {
    let n1 = derive_nonce(0x01, 1234);
    let n2 = derive_nonce(0x01, 1235);
    assert_ne!(n1, n2);
}
