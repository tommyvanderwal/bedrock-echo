//! LAN service-discovery announcement via mDNS (RFC 6762/6763).
//!
//! Advertises this witness as `_echo._udp.local.` with a TXT record
//! mirroring the DNSSEC-hosted scheme in
//! `docs/witness-implementation.md` §6.1. Operators on the same L2
//! segment can find the witness via:
//!   - `avahi-browse -tr _echo._udp` (Linux)
//!   - `dns-sd -B _echo._udp`        (macOS)
//!   - `ping bedrock-echo-witness.local` (any OS with mDNS resolver)
//!
//! **Security note:** mDNS on LAN is unauthenticated — any device on
//! the same broadcast domain can advertise a fake `_echo._udp` service
//! with their own pubkey. The pubkey advertised here is a UX
//! convenience, not a trust anchor. Operators MUST cross-check the
//! witness pubkey against an out-of-band source before trusting any
//! witness regardless of how it was discovered.

use std::net::IpAddr;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mdns_sd::{ServiceDaemon, ServiceInfo};

const SERVICE_TYPE: &str = "_echo._udp.local.";
const HOSTNAME: &str = "bedrock-echo-witness.local.";
const INSTANCE: &str = "Bedrock Echo witness";

/// Holds the daemon so the announcement stays alive for the witness's
/// lifetime. Drop unregisters cleanly.
pub struct MdnsAnnouncement {
    _daemon: ServiceDaemon,
}

/// Register the `_echo._udp` service on every reachable LAN interface.
/// Best-effort: returns `Err` on init/registration failure but the
/// caller can continue running without mDNS.
pub fn announce(
    bind_ip: IpAddr,
    port: u16,
    witness_pub: &[u8; 32],
) -> Result<MdnsAnnouncement, mdns_sd::Error> {
    let daemon = ServiceDaemon::new()?;

    // Same TXT format as the DNSSEC hosted scheme.
    let pub_b64 = STANDARD.encode(witness_pub);
    let txt: [(&str, &str); 3] = [
        ("v", "Echo"),
        ("k", "x25519"),
        ("p", &pub_b64),
    ];

    // If the operator bound to 0.0.0.0, mdns-sd auto-discovers usable
    // interfaces. If they bound to a specific IP, advertise only that.
    let addrs: Vec<IpAddr> = if bind_ip.is_unspecified() {
        Vec::new()  // empty → mdns-sd uses all interfaces
    } else {
        vec![bind_ip]
    };

    let info = ServiceInfo::new(
        SERVICE_TYPE,
        INSTANCE,
        HOSTNAME,
        &addrs[..],
        port,
        &txt[..],
    )?
    .enable_addr_auto();

    daemon.register(info)?;

    Ok(MdnsAnnouncement { _daemon: daemon })
}
