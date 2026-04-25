//! In-RAM witness state (Linux profile).
//!
//! Mirrors the Python reference implementation:
//!   - Multiple node entries may share the same `sender_id` if they're in
//!     different clusters; collision is resolved by AEAD trial decrypt.
//!   - Per-cluster `cluster_offset` tracks the cluster's wall-clock frame.
//!   - Per-cluster `last_tx_timestamp` ensures strict-monotonic outgoing
//!     timestamps for AEAD nonce uniqueness.

use bedrock_echo_proto::constants::*;

// "Tiny" profile defaults for the Linux witness binary.
// ESP32 has its own compile-time constants in firmware/esp32-c/main/echo.h.
pub const MAX_NODES: usize = 64;
pub const MAX_CLUSTERS: usize = 32;
pub const MAX_TRACKED_IPS: usize = 128;

#[derive(Clone, Copy, Default)]
pub struct ClusterEntry {
    pub in_use: bool,
    pub cluster_key: [u8; CLUSTER_KEY_LEN],
    pub bootstrapped_ms: u64,
    pub num_nodes: u8,
    pub cluster_offset: i64,        // cluster wall-clock-ms = uptime_ms + cluster_offset
    pub last_tx_timestamp: i64,     // strict-monotonic outgoing ts in cluster frame
}

#[derive(Clone, Copy)]
pub struct NodeEntry {
    pub in_use: bool,
    pub sender_id: u8,
    pub sender_ipv4: [u8; 4],
    pub sender_src_port: u16,
    pub cluster_slot: u16,
    pub last_rx_ms: u64,            // witness uptime ms when last accepted packet arrived
    pub last_rx_timestamp: i64,     // cluster-frame ts of last accepted pkt (anti-replay)
    pub payload_n_blocks: u8,       // 0..36
    pub payload: [u8; PAYLOAD_MAX_BYTES],
}

impl Default for NodeEntry {
    fn default() -> Self {
        Self {
            in_use: false,
            sender_id: 0,
            sender_ipv4: [0; 4],
            sender_src_port: 0,
            cluster_slot: 0,
            last_rx_ms: 0,
            last_rx_timestamp: 0,
            payload_n_blocks: 0,
            payload: [0; PAYLOAD_MAX_BYTES],
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct RateEntry {
    pub in_use: bool,
    pub ipv4: [u8; 4],
    pub tokens: f32,
    pub last_refill_ms: u64,
    pub last_unknown_ms: u64,
}

pub const RL_RATE_PER_SEC: f32 = 10.0;
pub const RL_BURST: f32 = 20.0;
pub const RL_UNKNOWN_MIN_INTERVAL_MS: u64 = 1000;

pub const MAX_BACKWARD_JUMP_MS: i64 = 1000;
pub const MAX_BACKWARD_STEP_MS: i64 = 10;

pub struct State {
    pub witness_priv: [u8; 32],
    pub witness_pub: [u8; 32],
    pub start_ms: u64,
    pub clusters: [ClusterEntry; MAX_CLUSTERS],
    pub nodes: [NodeEntry; MAX_NODES],
    pub rate_limits: [RateEntry; MAX_TRACKED_IPS],
}

impl State {
    pub fn new(witness_priv: [u8; 32], now_ms: u64) -> Self {
        let witness_pub = bedrock_echo_proto::crypto::x25519_pub_from_priv(&witness_priv);
        Self {
            witness_priv,
            witness_pub,
            start_ms: now_ms,
            clusters: [ClusterEntry::default(); MAX_CLUSTERS],
            nodes: [NodeEntry::default(); MAX_NODES],
            rate_limits: [RateEntry::default(); MAX_TRACKED_IPS],
        }
    }

    pub fn uptime_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.start_ms)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.in_use).count()
    }

    pub fn cluster_count(&self) -> usize {
        self.clusters.iter().filter(|c| c.in_use).count()
    }

    /// Find any node entry matching (src_ip, sender_id). Returns the index.
    pub fn find_node_by_ip_and_sender(&self, ipv4: &[u8; 4], sid: u8) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.in_use && &n.sender_ipv4 == ipv4 && n.sender_id == sid)
    }

    /// Find any node entry matching sender_id (used as fallback if IP changed).
    /// Returns indices of all matches; multiple entries may share sender_id
    /// across different clusters.
    pub fn find_nodes_by_sender(&self, sid: u8) -> impl Iterator<Item = usize> + '_ {
        self.nodes
            .iter()
            .enumerate()
            .filter_map(move |(i, n)| (n.in_use && n.sender_id == sid).then_some(i))
    }

    pub fn find_cluster_by_key(&self, key: &[u8; CLUSTER_KEY_LEN]) -> Option<usize> {
        self.clusters
            .iter()
            .position(|c| c.in_use && &c.cluster_key == key)
    }

    pub fn allocate_cluster_slot(&self) -> Option<usize> {
        self.clusters.iter().position(|c| !c.in_use)
    }

    pub fn allocate_node_slot(&self) -> Option<usize> {
        self.nodes.iter().position(|n| !n.in_use)
    }

    /// Apply asymmetric per-cluster offset adaptation (PROTOCOL.md §6.2).
    /// Returns false if the packet timestamp is too far behind the cluster
    /// frame (caller should silent-drop).
    pub fn adapt_cluster_offset(&mut self, cluster_slot: usize,
                                pkt_ts: i64, uptime_ms: u64) -> bool {
        let c = &mut self.clusters[cluster_slot];
        let expected = uptime_ms as i64 + c.cluster_offset;
        let delta = pkt_ts - expected;
        if delta > 0 {
            c.cluster_offset += delta;
        } else if delta > -MAX_BACKWARD_JUMP_MS {
            let step = delta.max(-MAX_BACKWARD_STEP_MS);
            c.cluster_offset += step;
        } else {
            return false;
        }
        true
    }

    /// Compute outgoing timestamp_ms for a reply in this cluster's frame,
    /// enforcing strict-monotonic. Updates `last_tx_timestamp`.
    pub fn next_tx_timestamp(&mut self, cluster_slot: usize, uptime_ms: u64) -> i64 {
        let c = &mut self.clusters[cluster_slot];
        let candidate = uptime_ms as i64 + c.cluster_offset;
        let ts = candidate.max(c.last_tx_timestamp + 1);
        c.last_tx_timestamp = ts;
        ts
    }

    /// Age out stale node entries. Timeout depends on fill ratio (§10).
    pub fn age_out(&mut self, now_ms: u64) {
        let n = self.node_count();
        let tier_80 = (MAX_NODES * 80) / 100;
        let tier_90 = (MAX_NODES * 90) / 100;
        let timeout_ms: u64 = if n <= tier_80 {
            72 * 3600 * 1000
        } else if n <= tier_90 {
            4 * 3600 * 1000
        } else {
            5 * 60 * 1000
        };
        for i in 0..MAX_NODES {
            if !self.nodes[i].in_use {
                continue;
            }
            if now_ms.saturating_sub(self.nodes[i].last_rx_ms) > timeout_ms {
                let cs = self.nodes[i].cluster_slot as usize;
                self.nodes[i].in_use = false;
                if cs < MAX_CLUSTERS && self.clusters[cs].in_use {
                    self.clusters[cs].num_nodes =
                        self.clusters[cs].num_nodes.saturating_sub(1);
                    if self.clusters[cs].num_nodes == 0 {
                        self.clusters[cs].in_use = false;
                    }
                }
            }
        }
    }

    /// Token-bucket admission check. Returns false if packet should be dropped.
    pub fn allow(&mut self, ipv4: [u8; 4], now_ms: u64) -> bool {
        let idx = self.get_or_create_rate_entry(ipv4, now_ms);
        let rl = &mut self.rate_limits[idx];
        let dt_s = (now_ms.saturating_sub(rl.last_refill_ms)) as f32 / 1000.0;
        rl.tokens = (rl.tokens + dt_s * RL_RATE_PER_SEC).min(RL_BURST);
        rl.last_refill_ms = now_ms;
        if rl.tokens < 1.0 {
            return false;
        }
        rl.tokens -= 1.0;
        true
    }

    /// 1/s/IP cap on UNKNOWN_SOURCE replies. Returns false to silent-drop.
    pub fn allow_unknown(&mut self, ipv4: [u8; 4], now_ms: u64) -> bool {
        let idx = self.get_or_create_rate_entry(ipv4, now_ms);
        let rl = &mut self.rate_limits[idx];
        if now_ms.saturating_sub(rl.last_unknown_ms) < RL_UNKNOWN_MIN_INTERVAL_MS {
            return false;
        }
        rl.last_unknown_ms = now_ms;
        true
    }

    fn get_or_create_rate_entry(&mut self, ipv4: [u8; 4], now_ms: u64) -> usize {
        if let Some(i) = self.rate_limits.iter().position(|r| r.in_use && r.ipv4 == ipv4) {
            return i;
        }
        if let Some(i) = self.rate_limits.iter().position(|r| !r.in_use) {
            self.rate_limits[i] = RateEntry {
                in_use: true,
                ipv4,
                tokens: RL_BURST,
                last_refill_ms: now_ms,
                last_unknown_ms: 0,
            };
            return i;
        }
        let oldest = self
            .rate_limits
            .iter()
            .enumerate()
            .min_by_key(|(_, r)| r.last_refill_ms)
            .unwrap()
            .0;
        self.rate_limits[oldest] = RateEntry {
            in_use: true,
            ipv4,
            tokens: RL_BURST,
            last_refill_ms: now_ms,
            last_unknown_ms: 0,
        };
        oldest
    }
}
