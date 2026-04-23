//! Interop test: the Rust proto crate MUST produce (and accept) the exact
//! same byte sequences as the Python reference impl, for every checked-in
//! test vector under `testvectors/`.
//!
//! If this test fails, either the Python or Rust impl has drifted from
//! PROTOCOL.md — and both are presumed broken until the drift is resolved.

use std::fs;
use std::path::PathBuf;

use bedrock_echo_proto::{constants::*, msg};

use serde_json::Value;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()  // crates/
        .parent().unwrap()  // repo root
        .join("testvectors")
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn hex_arr<const N: usize>(v: &Value) -> [u8; N] {
    let h = hex::decode(v.as_str().unwrap()).unwrap();
    assert_eq!(h.len(), N, "hex length {} != {}", h.len(), N);
    let mut out = [0u8; N];
    out.copy_from_slice(&h);
    out
}

fn parse_ipv4(v: &Value) -> [u8; 4] {
    let s = v.as_str().unwrap();
    let parts: Vec<u8> = s.split('.').map(|p| p.parse::<u8>().unwrap()).collect();
    [parts[0], parts[1], parts[2], parts[3]]
}

fn load_pair(name: &str) -> (Value, Vec<u8>) {
    let dir = vectors_dir();
    let json = fs::read_to_string(dir.join(format!("{}.in.json", name))).unwrap();
    let wire = fs::read(dir.join(format!("{}.out.bin", name))).unwrap();
    (serde_json::from_str(&json).unwrap(), wire)
}

// ─── Encoders must match wire bytes exactly ─────────────────────────────────

#[test]
fn v01_heartbeat_list_query_encode_matches() {
    let (inp, wire) = load_pair("01_heartbeat_list_query");
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_heartbeat(
        &mut out,
        hex_arr::<8>(&inp["sender_id"]),
        inp["sequence"].as_u64().unwrap(),
        inp["timestamp_ms"].as_i64().unwrap(),
        &hex_arr::<8>(&inp["query_target_id"]),
        &hex_bytes(&inp["own_payload"]),
        &hex_bytes(&inp["cluster_key"]),
    ).unwrap();
    assert_eq!(&out[..n], &wire[..], "heartbeat list-query encoding differs");
}

#[test]
fn v02_heartbeat_detail_query_encode_matches() {
    let (inp, wire) = load_pair("02_heartbeat_detail_query");
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_heartbeat(
        &mut out,
        hex_arr::<8>(&inp["sender_id"]),
        inp["sequence"].as_u64().unwrap(),
        inp["timestamp_ms"].as_i64().unwrap(),
        &hex_arr::<8>(&inp["query_target_id"]),
        &hex_bytes(&inp["own_payload"]),
        &hex_bytes(&inp["cluster_key"]),
    ).unwrap();
    assert_eq!(&out[..n], &wire[..]);
}

#[test]
fn v03_status_list_two_nodes_encode_matches() {
    let (inp, wire) = load_pair("03_status_list_two_nodes");
    let entries: Vec<msg::ListEntry> = inp["entries"].as_array().unwrap().iter()
        .map(|e| msg::ListEntry {
            peer_sender_id: hex_arr::<8>(&e["peer_sender_id"]),
            peer_ipv4: parse_ipv4(&e["peer_ipv4"]),
            last_seen_seconds: e["last_seen_seconds"].as_u64().unwrap() as u32,
        }).collect();
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_status_list(
        &mut out,
        hex_arr::<8>(&inp["witness_sender_id"]),
        inp["sequence"].as_u64().unwrap(),
        inp["timestamp_ms"].as_i64().unwrap(),
        inp["witness_uptime_ms"].as_u64().unwrap(),
        &entries,
        &hex_bytes(&inp["cluster_key"]),
    ).unwrap();
    assert_eq!(&out[..n], &wire[..]);
}

#[test]
fn v04_status_detail_found_encode_matches() {
    let (inp, wire) = load_pair("04_status_detail_found");
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_status_detail_found(
        &mut out,
        hex_arr::<8>(&inp["witness_sender_id"]),
        inp["sequence"].as_u64().unwrap(),
        inp["timestamp_ms"].as_i64().unwrap(),
        inp["witness_uptime_ms"].as_u64().unwrap(),
        &hex_arr::<8>(&inp["target_sender_id"]),
        &parse_ipv4(&inp["peer_ipv4"]),
        inp["last_seen_seconds"].as_u64().unwrap() as u32,
        &hex_bytes(&inp["peer_payload"]),
        &hex_bytes(&inp["cluster_key"]),
    ).unwrap();
    assert_eq!(&out[..n], &wire[..]);
}

#[test]
fn v05_status_detail_not_found_encode_matches() {
    let (inp, wire) = load_pair("05_status_detail_not_found");
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_status_detail_not_found(
        &mut out,
        hex_arr::<8>(&inp["witness_sender_id"]),
        inp["sequence"].as_u64().unwrap(),
        inp["timestamp_ms"].as_i64().unwrap(),
        inp["witness_uptime_ms"].as_u64().unwrap(),
        &hex_arr::<8>(&inp["target_sender_id"]),
        &hex_bytes(&inp["cluster_key"]),
    ).unwrap();
    assert_eq!(&out[..n], &wire[..]);
}

#[test]
fn v06_unknown_source_encode_matches() {
    let (inp, wire) = load_pair("06_unknown_source");
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_unknown_source(
        &mut out,
        hex_arr::<8>(&inp["witness_sender_id"]),
        inp["sequence"].as_u64().unwrap(),
        inp["timestamp_ms"].as_i64().unwrap(),
    ).unwrap();
    assert_eq!(&out[..n], &wire[..]);
}

#[test]
fn v07_bootstrap_encode_matches() {
    let (inp, wire) = load_pair("07_bootstrap");
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_bootstrap(
        &mut out,
        hex_arr::<8>(&inp["sender_id"]),
        inp["sequence"].as_u64().unwrap(),
        inp["timestamp_ms"].as_i64().unwrap(),
        &hex_arr::<32>(&inp["witness_x25519_pub"]),
        &hex_arr::<32>(&inp["eph_priv"]),
        &hex_arr::<32>(&inp["cluster_key"]),
        &hex_bytes(&inp["init_payload"]),
    ).unwrap();
    assert_eq!(&out[..n], &wire[..]);
}

#[test]
fn v08_bootstrap_ack_new_encode_matches() {
    let (inp, wire) = load_pair("08_bootstrap_ack_new");
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_bootstrap_ack(
        &mut out,
        hex_arr::<8>(&inp["witness_sender_id"]),
        inp["sequence"].as_u64().unwrap(),
        inp["timestamp_ms"].as_i64().unwrap(),
        inp["status"].as_u64().unwrap() as u8,
        inp["witness_uptime_ms"].as_u64().unwrap(),
        &hex_bytes(&inp["cluster_key"]),
    ).unwrap();
    assert_eq!(&out[..n], &wire[..]);
}

#[test]
fn v09_bootstrap_ack_rebootstrap_encode_matches() {
    let (inp, wire) = load_pair("09_bootstrap_ack_rebootstrap");
    let mut out = [0u8; MTU_CAP];
    let n = msg::encode_bootstrap_ack(
        &mut out,
        hex_arr::<8>(&inp["witness_sender_id"]),
        inp["sequence"].as_u64().unwrap(),
        inp["timestamp_ms"].as_i64().unwrap(),
        inp["status"].as_u64().unwrap() as u8,
        inp["witness_uptime_ms"].as_u64().unwrap(),
        &hex_bytes(&inp["cluster_key"]),
    ).unwrap();
    assert_eq!(&out[..n], &wire[..]);
}

// ─── Decoders must round-trip the same wire bytes ───────────────────────────

#[test]
fn v01_heartbeat_list_query_decode_matches() {
    let (inp, wire) = load_pair("01_heartbeat_list_query");
    let view = msg::decode_heartbeat(&wire, &hex_bytes(&inp["cluster_key"])).unwrap();
    assert_eq!(view.header.sender_id, hex_arr::<8>(&inp["sender_id"]));
    assert_eq!(view.query_target_id, hex_arr::<8>(&inp["query_target_id"]));
    assert_eq!(view.own_payload, &hex_bytes(&inp["own_payload"])[..]);
}

#[test]
fn v07_bootstrap_decode_matches() {
    let (inp, wire) = load_pair("07_bootstrap");
    let d = msg::decode_bootstrap(&wire, &hex_arr::<32>(&inp["witness_x25519_priv"])).unwrap();
    assert_eq!(d.plaintext.cluster_key, hex_arr::<32>(&inp["cluster_key"]));
    let expected_init = hex_bytes(&inp["init_payload"]);
    assert_eq!(&d.plaintext.init_payload[..d.plaintext.init_payload_len],
               &expected_init[..]);
}

#[test]
fn v03_status_list_decode_matches() {
    let (inp, wire) = load_pair("03_status_list_two_nodes");
    let view = msg::decode_status_list(&wire, &hex_bytes(&inp["cluster_key"])).unwrap();
    assert_eq!(view.witness_uptime_ms, inp["witness_uptime_ms"].as_u64().unwrap());
    let expected = inp["entries"].as_array().unwrap();
    assert_eq!(view.num_entries as usize, expected.len());
    for (i, e) in expected.iter().enumerate() {
        let got = view.entry(i).unwrap();
        assert_eq!(got.peer_sender_id, hex_arr::<8>(&e["peer_sender_id"]));
        assert_eq!(got.peer_ipv4, parse_ipv4(&e["peer_ipv4"]));
        assert_eq!(got.last_seen_seconds as u64, e["last_seen_seconds"].as_u64().unwrap());
    }
}

#[test]
fn v04_status_detail_found_decode_matches() {
    let (inp, wire) = load_pair("04_status_detail_found");
    let view = msg::decode_status_detail(&wire, &hex_bytes(&inp["cluster_key"])).unwrap();
    match view {
        msg::StatusDetailView::Found { peer_payload, peer_ipv4, target_sender_id, .. } => {
            assert_eq!(peer_payload, &hex_bytes(&inp["peer_payload"])[..]);
            assert_eq!(peer_ipv4, parse_ipv4(&inp["peer_ipv4"]));
            assert_eq!(target_sender_id, hex_arr::<8>(&inp["target_sender_id"]));
        }
        _ => panic!("expected Found"),
    }
}
