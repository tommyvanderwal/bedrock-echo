//! Bedrock Echo witness — Linux UDP binary.
//!
//! Binds a UDP socket, runs the packet dispatcher, responds. RAM-only.
//! The X25519 private key is persisted to a single file (default
//! `/var/lib/bedrock-echo/witness.x25519.key`, override with `BEDROCK_ECHO_KEY`).

use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use bedrock_echo_proto::constants::MTU_CAP;
use bedrock_echo_witness::{handle, State};
use rand_core::{OsRng, RngCore};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn load_or_generate_priv(path: &PathBuf) -> [u8; 32] {
    match fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            k
        }
        Ok(_) => panic!("{}: expected 32 raw bytes", path.display()),
        Err(_) => {
            // Generate fresh X25519 privkey: 32 bytes of OS randomness,
            // clamp to be a valid X25519 scalar is not needed for X25519 — the
            // `StaticSecret::from(bytes)` does that internally.
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            // mkdir -p
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).ok();
            }
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            let mut f = opts.open(path).expect("open keyfile for write");
            f.write_all(&k).expect("write keyfile");
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            k
        }
    }
}

fn parse_bind() -> SocketAddr {
    let host = std::env::var("BEDROCK_ECHO_BIND").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = std::env::var("BEDROCK_ECHO_PORT").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(12321);
    let ip: IpAddr = host.parse().expect("BEDROCK_ECHO_BIND must parse as IP");
    SocketAddr::new(ip, port)
}

fn key_path() -> PathBuf {
    std::env::var_os("BEDROCK_ECHO_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/bedrock-echo/witness.x25519.key"))
}

fn main() {
    let bind = parse_bind();
    let key_path = key_path();
    let priv_key = load_or_generate_priv(&key_path);
    // Generate two random cookie secrets at boot — current and previous
    // both fresh, so all in-flight cookies from a (rare) prior witness
    // session are invalidated. Hourly rotation runs lazily in the
    // packet handler.
    let mut current = [0u8; 32];
    let mut previous = [0u8; 32];
    OsRng.fill_bytes(&mut current);
    OsRng.fill_bytes(&mut previous);
    let mut state = State::new_with_cookies(priv_key, now_ms(), current, previous);

    eprintln!("bedrock-echo-witness v{} starting", env!("CARGO_PKG_VERSION"));
    eprintln!("  bind:           {}", bind);
    eprintln!("  keyfile:        {}", key_path.display());
    eprintln!("  witness pub:    {}", hex_encode(&state.witness_pub));

    let sock = UdpSocket::bind(bind).expect("bind UDP socket");

    // Optional LAN mDNS announce. Default ON; disable with
    // `BEDROCK_ECHO_MDNS=0`. Stored so the daemon stays alive for the
    // process lifetime — drop unregisters cleanly on shutdown.
    #[cfg(feature = "mdns")]
    let _mdns = if std::env::var("BEDROCK_ECHO_MDNS").as_deref() != Ok("0") {
        match bedrock_echo_witness::mdns::announce(bind.ip(), bind.port(), &state.witness_pub) {
            Ok(h) => {
                eprintln!("  mdns:           advertising _echo._udp as bedrock-echo-witness.local");
                Some(h)
            }
            Err(e) => {
                eprintln!("  mdns:           failed ({}), continuing without LAN announce", e);
                None
            }
        }
    } else {
        eprintln!("  mdns:           disabled via BEDROCK_ECHO_MDNS=0");
        None
    };

    let mut buf = [0u8; MTU_CAP + 64];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((len, src)) => {
                let t = now_ms();
                if state.cookie_rotation_due(t) {
                    let mut next = [0u8; 32];
                    OsRng.fill_bytes(&mut next);
                    state.maybe_rotate_cookie(t, next);
                }
                let ipv4 = match src.ip() {
                    IpAddr::V4(v4) => v4.octets(),
                    IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                        Some(v4) => v4.octets(),
                        None => {
                            eprintln!("dropping v6 packet from {}: v6-only not yet supported", src);
                            continue;
                        }
                    },
                };
                if let Some(reply) = handle(&mut state, &buf[..len], ipv4, src.port(), now_ms()) {
                    if let Err(e) = sock.send_to(reply.as_slice(), src) {
                        eprintln!("sendto {}: {}", src, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("recvfrom error: {}", e);
            }
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
