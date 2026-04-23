resource bec-r0 {
    protocol C;

    device    /dev/drbd0;
    disk      /dev/bec_pool/bec-r0;
    meta-disk internal;

    # Fail-safe: if the peer is gone, the Primary loses quorum (only 1 of 2
    # votes) and DRBD suspends all I/O. Writes BLOCK instead of completing
    # locally, so the application never sees "OK" for a write the peer
    # doesn't have. No silent divergence possible.
    #
    # Re-enabling writes on the survivor is the daemon's job: once the
    # witness confirms the peer is dead, the daemon does
    # `drbdadm primary --force`, which overrides the quorum check.
    options {
        quorum majority;
        on-no-quorum suspend-io;
    }

    net {
        verify-alg sha256;
        # After-split-brain policies:
        # * Both-Secondary divergence: demand an operator (unlikely to happen
        #   with self-fence, but the conservative default).
        after-sb-0pri disconnect;
        # * One-Primary case — the expected shape when self-fence has run
        #   (demoted side reconnects to current Primary). Discard the
        #   Secondary's unreplicated local bits, keep the Primary's data.
        after-sb-1pri discard-secondary;
        # * Both-Primary — should never happen with self-fence; demand
        #   operator if it does.
        after-sb-2pri disconnect;
    }

    on bec-node-a {
        address 10.99.0.20:7788;
        node-id 0;
    }
    on bec-node-b {
        address 10.99.0.21:7788;
        node-id 1;
    }

    # v0.001: single replication path on ring A (10.99.0.x).
    # Ring B (10.88.0.x) is used by the node daemon for peer heartbeats;
    # multi-path DRBD over both rings is a v0.2 refinement.
}
