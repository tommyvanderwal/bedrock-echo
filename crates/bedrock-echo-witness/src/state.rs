//! In-RAM witness state, fixed-size arrays. Mirrors the Python impl so the
//! two track the same failure modes.

use bedrock_echo_proto::constants::*;

pub const MAX_NODES: usize = 64;
pub const MAX_CLUSTERS: usize = 32;
pub const MAX_TRACKED_IPS: usize = 128;

#[derive(Clone, Copy, Default)]
pub struct ClusterEntry {
    pub in_use: bool,
    pub cluster_key: [u8; 32],
    pub bootstrapped_ms: u64,
    pub num_nodes: u8,
}

#[derive(Clone, Copy)]
pub struct NodeEntry {
    pub in_use: bool,
    pub sender_id: [u8; 8],
    pub sender_ipv4: [u8; 4],
    pub cluster_slot: u8,
    pub last_rx_ms: u64,
    pub last_rx_sequence: u64,
    pub last_tx_sequence: u64,
    pub payload_len: u8,
    pub payload: [u8; NODE_PAYLOAD_MAX],
}

impl Default for NodeEntry {
    fn default() -> Self {
        Self {
            in_use: false,
            sender_id: [0; 8],
            sender_ipv4: [0; 4],
            cluster_slot: 0,
            last_rx_ms: 0,
            last_rx_sequence: 0,
            last_tx_sequence: 0,
            payload_len: 0,
            payload: [0; NODE_PAYLOAD_MAX],
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

pub struct State {
    pub witness_priv: [u8; 32],
    pub witness_pub: [u8; 32],
    pub witness_sender_id: [u8; 8],
    pub start_ms: u64,
    pub clusters: [ClusterEntry; MAX_CLUSTERS],
    pub nodes: [NodeEntry; MAX_NODES],
    pub rate_limits: [RateEntry; MAX_TRACKED_IPS],
}

impl State {
    pub fn new(witness_priv: [u8; 32], now_ms: u64) -> Self {
        let witness_pub = bedrock_echo_proto::crypto::x25519_pub_from_priv(&witness_priv);
        let witness_sender_id = default_witness_sender_id(&witness_pub);
        Self {
            witness_priv,
            witness_pub,
            witness_sender_id,
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

    pub fn find_node(&self, sender_id: &[u8; 8]) -> Option<usize> {
        self.nodes.iter().position(|n| n.in_use && &n.sender_id == sender_id)
    }

    pub fn find_cluster_by_key(&self, key: &[u8; 32]) -> Option<usize> {
        self.clusters.iter().position(|c| c.in_use && &c.cluster_key == key)
    }

    pub fn allocate_cluster_slot(&self) -> Option<usize> {
        self.clusters.iter().position(|c| !c.in_use)
    }

    pub fn allocate_node_slot(&self) -> Option<usize> {
        self.nodes.iter().position(|n| !n.in_use)
    }

    /// Age out stale node entries. Timeout depends on fill ratio (§10).
    pub fn age_out(&mut self, now_ms: u64) {
        let n = self.node_count();
        let timeout_ms: u64 = if n < 16 {
            72 * 3600 * 1000
        } else if n <= 48 {
            60 * 60 * 1000
        } else {
            5 * 60 * 1000
        };
        for i in 0..MAX_NODES {
            if !self.nodes[i].in_use { continue; }
            if now_ms.saturating_sub(self.nodes[i].last_rx_ms) > timeout_ms {
                let cs = self.nodes[i].cluster_slot as usize;
                self.nodes[i].in_use = false;
                if cs < MAX_CLUSTERS && self.clusters[cs].in_use {
                    self.clusters[cs].num_nodes = self.clusters[cs].num_nodes.saturating_sub(1);
                    if self.clusters[cs].num_nodes == 0 {
                        self.clusters[cs].in_use = false;
                    }
                }
            }
        }
    }

    /// Token-bucket admission check. Returns false if the packet should be dropped.
    pub fn allow(&mut self, ipv4: [u8; 4], now_ms: u64) -> bool {
        let idx = self.get_or_create_rate_entry(ipv4, now_ms);
        let rl = &mut self.rate_limits[idx];
        let dt_s = (now_ms.saturating_sub(rl.last_refill_ms)) as f32 / 1000.0;
        rl.tokens = (rl.tokens + dt_s * RL_RATE_PER_SEC).min(RL_BURST);
        rl.last_refill_ms = now_ms;
        if rl.tokens < 1.0 { return false; }
        rl.tokens -= 1.0;
        true
    }

    /// Check-and-update the UNKNOWN_SOURCE reply rate-limit (1/s/ip).
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
        // find a free slot
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
        // evict oldest (smallest last_refill_ms)
        let oldest = self.rate_limits.iter().enumerate()
            .min_by_key(|(_, r)| r.last_refill_ms).unwrap().0;
        self.rate_limits[oldest] = RateEntry {
            in_use: true, ipv4, tokens: RL_BURST,
            last_refill_ms: now_ms, last_unknown_ms: 0,
        };
        oldest
    }
}

pub fn default_witness_sender_id(pub_key: &[u8; 32]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pub_key);
    let out = h.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&out[..8]);
    id
}
