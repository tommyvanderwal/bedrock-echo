"""Bedrock Echo node daemon.

Successor to /home/tommy/pythonprojects/bedrock/bedrock-failover.py.
Main differences:
  * Talks the Bedrock Echo UDP/Echo protocol to the witness (not HTTP).
  * Dual-ring peer heartbeats: tries to reach the peer via mgmt + DRBD ring A
    + DRBD ring B (bec-link2).
  * DRBD / virsh effects are behind an adapter so unit tests can run on the
    host without touching real DRBD.
"""
