# Limits

This is the Python reference for the channel, the HTTP 402 wire, the routed client and the hub.
The limits of the design, and what no review has covered, are stated once, in `docs/LIMITS.md` of
the Rust workspace (Lightning Stream). Every sentence there about the channel, the transport, the
routed client and the hub holds here too, unless this file says otherwise. Read that file first.

Status: reference, test networks only. Nobody outside the project has reviewed the fixes that
followed the external review of October 2026.

A limit marked *(test)* is pinned by a test named `test_limit_...` under `tests/security/`: it
passes while the limit holds and fails when someone lifts it.

## What differs in the Python reference

### Funding

- The wallet hook is a bare function (`fund`): it cannot say whether a call that raised had
  already sent. A retry after such a call pays the same script again, in the library client and in
  the routed client; the key is on the books, so every output is refundable after the expiry, but
  the client holds a refund for the last one only and its budget counts one. An embedder whose
  `fund` can fail after it sent must make it answer the send it made when asked again for the same
  address. The Rust routed client asks its wallet instead and does not fund twice. *(test)*
- A hub channel that was recorded and never funded, and is too near its expiry, is derived again
  and funded by the same call; the Rust routed client refuses to open until its owner removes the
  record.
- A signer here does not record what it funded, so a funding whose answer was lost is not found
  again through the signer, as it is in the Rust workspace.

### Library client

- After a second forged refusal every call on that channel is refused until its owner closes it
  and removes its record; `close()` alone leaves the record. *(test)*
- A URL whose host could be read two ways is refused before anything is paid or sent, by the same
  rule as in the Rust workspace; a trailing dot on a name is a separate origin, so a seller reached
  under both spellings can be funded once per spelling, up to the payer's budget. *(test)*
- The Rust client rebuilds the URL it hands its transport; this client sends the caller's string,
  because `urllib` reads the strings the rule lets through as the client does. An embedder that
  uses another HTTP library must check that it does too. For an IPv4-mapped IPv6 literal each
  language accepts the spelling its own standard library prints.
- The client's refund file is renamed into place without a directory sync, so a power loss can
  undo the last save.
- Keys cannot be wiped from memory in Python.

### Hub

- The Python hub has no start-up checks and no status page: it does not refuse a node on the
  wrong chain, and `python -m xbt402.hub` leaves the funding fee to the node wallet (on a node
  with no estimate, its fallback rate).
- The hub's question to a provider about a lock is bounded per socket read by the shipped
  transport, not for the whole answer.
- The two hub limits the Rust tests pin (a close mined, reorganised out and mined again with a
  scan that gives no depth; a completion the hub's own ledger did not take on a close already six
  blocks deep) hold here from reading; no Python test pins them.
- Nine of the 22 hub tests of the fifth fix round have no twin here.

### Server

- The ASGI adapter has no connection cap and no deadlines; put a server with its own limits in
  front of it.

## Open items

None is marked in this repository. The two open items of the project are in the Rust workspace's
`docs/LIMITS.md`; both are in the agent wallets.

## Not reviewed by anyone

The project's audits read the Python hub where it mirrors the Rust changes, not whole, and did not
read the MCP server beyond the lines a fix changed.
Nothing here has run against a real network.
