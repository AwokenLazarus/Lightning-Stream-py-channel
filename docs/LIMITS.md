# Limits

This is the Python reference for the on-chain one-way channel and its HTTP 402 wire. The limits
of the design, and what no review has covered, are stated once, in `docs/LIMITS.md` of the Rust
workspace (Lightning Stream). Every sentence there about the channel and the transport holds here
too, unless this file says otherwise. Read that file first.

Direction, decided on 2026-10-11: Lightning Stream is being rebuilt on Lightning (stream tickets
on ordinary XBT Lightning channels, in design). The channel this repository implements is
**frozen**: kept and tested, off the main path, with no new work. The hub and the routed client
were retired on that day and removed from this tree; the limits stated for them here went with
them. That code is in the git history, last at commit `dfd6791`.

Status: reference, test networks only. Nobody outside the project has reviewed the fixes that
followed the external review of October 2026.

A limit marked *(test)* is pinned by a test named `test_limit_...` under `tests/security/`: it
passes while the limit holds and fails when someone lifts it.

## What differs in the Python reference

### Funding

- The wallet hook is a bare function (`fund`): it cannot say whether a call that raised had
  already sent. A retry after such a call pays the same script again; the key is on the books, so every output is refundable after the expiry, but
  the client holds a refund for the last one only and its budget counts one. An embedder whose
  `fund` can fail after it sent must make it answer the send it made when asked again for the same
  address. *(test)*
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

### Retired with the hub

- An open request that still carries a `hub` field is opened as an ordinary channel; the field is
  ignored. `/x402/xbt-channel/lock` answers 404.
- A provider ledger written by an earlier version, with channels a hub funded or routed locks
  recorded on them, loads, and those channels are treated as ordinary ones.
- `/x402/xbt-channel/terms` of a provider with default settings now says `closeFeePayer: "payer"`;
  it said `"payee"`, the default for channels a hub funded.

### Server

- The ASGI adapter has no connection cap and no deadlines; put a server with its own limits in
  front of it.

## Open items

None is marked in this repository. The open items of the project are in the Rust workspace's
`docs/LIMITS.md`.

## Not reviewed by anyone

The project's audits did not read the MCP server beyond the lines a fix changed. Nobody has
reviewed the removal of the hub (2026-10-11): what was cut from the provider and the signer, and
how records of the removed features are treated.
Nothing here has run against a real network.
