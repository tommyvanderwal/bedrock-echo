// LAN service-discovery announcement via mDNS (RFC 6762/6763).
//
// Advertises this witness as `_echo._udp.local.` with TXT records carrying
// the pubkey, mirroring the DNSSEC scheme in docs/witness-implementation.md
// §6.1. Operators on the same L2 segment can find the witness via:
//   avahi-browse -tr _echo._udp     (Linux)
//   dns-sd -B _echo._udp            (macOS)
//   ping bedrock-echo-witness.local (any OS with mDNS resolver)
//
// SECURITY NOTE: mDNS on LAN is unauthenticated — any device on the same
// broadcast domain can advertise a fake `_echo._udp` service with their
// own pubkey. The pubkey advertised here is a UX convenience, NOT a
// trust anchor. Operators MUST cross-check the witness pubkey against
// an out-of-band source (the serial-console print at first boot, or the
// value in cluster config) before trusting any witness regardless of
// how it was discovered.

#pragma once

#include "echo.h"

// Initialise mDNS and register the `_echo._udp` service.
// Call once, after DHCP has succeeded.
//   state: witness state (used to read the pubkey for the TXT record).
// Returns true on success, false on any mDNS init/registration failure.
bool echo_mdns_announce(const echo_state_t *state);
