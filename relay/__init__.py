"""Hardened single-process relay (V2): WebSocket relay + REST directory.

Decentralized trust: the relay is a dumb pipe with smart edges — it
never sees private keys and cannot forge envelopes. All shared state
lives in Postgres from line one (queue, dedup UNIQUE constraint,
presence, challenges) so a second replica can appear without redesign.
"""

__all__ = []
