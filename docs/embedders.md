# xbt402 for embedders (AGP-059)

For an application that meters a channel itself (xbt-compute, CMP-051): its own request headers and
cumulative amount on the payer, closing one channel on the provider, and what a provider restart
does to a call that was in flight. The same surface is in xbt-rs `agp-059` (README, "The embedder
surface").

## Payer: your own headers and your own cumulative amount

```python
status, hdrs, out = client.request("POST", url, frame,
                                   headers={"X-CMP-Payer": identity},
                                   cum=meter.payer_sats)          # sats, cumulative
done = client.close(origin, cum=meter.payer_sats)
```

`headers` go with every request of the call (the unpaid try and the paid retry). A
`PAYMENT-SIGNATURE`, an empty name, a non-string or a CR/LF/NUL raises `ChannelError("bad_header")`
and nothing is sent.

`cum` replaces only the amount `XbtChannelClient` works out from its receipts. The offer checks, the
price pinned at open, request auth and the receipt checks still run. The amount is bounded before
anything is signed or a seq is spent:

| a chosen `cum` | `ChannelError` |
|---|---|
| not a non-negative `int`, or below the last signed state | `bad_amount` (a state never goes down) |
| above `params.max_amount` (capacity less the payer's close fee) | `exhausted` |
| above `ceil(receipted spentMsat / 1000)` + one call at the price pinned at open | `too_expensive` |
| its increase over the last signed state exceeds what is left of `daily_budget` | `budget` |
| under `params.min_amount` while nothing is signed yet | none: sent unsigned (cum 0), never rounded up |

The third bound is the one the client has always had implicitly: it signs what its verified receipts
show, plus (prepay) the call it is making. A metering embedder can sign ahead of its receipts by at
most one call, which is what a lost answer needs.

`Xbt402Transport` (httpx) is unchanged: it sends no extra headers and no chosen cum.

## Provider: close one channel now

```python
st = provider.ledger.channels[chan]
if idle and provider.settle_due(st.params, st.best_cum, provider.height()):
    try:
        r = provider.close_channel(chan)     # {chan, txid, cum, unpaidMsat[, payeeFee, payeeNet]}
    except ChannelError as e:
        if e.code not in ("call_in_flight", "lock_pending", "hub_channel", "channel_closed", "no_state"):
            raise
```

It is the watcher's margin close (`close_due`) for one named channel: the same write-ahead intent,
broadcast, record and hash-lock claim (`_close_locked`), with the best signed state (the conditional
state when that pays more). Refused, with nothing changed:

| code | when |
|---|---|
| `unknown_channel` | not in this provider's ledger |
| `channel_closed` | already closed or rolled over |
| `lock_pending` | a routed lock is open on it (`route_lock`, `stale_locks`: a hub's ch1) |
| `hub_channel` | a hub-funded ch2: its hub rolls it over or closes it, and the margin close still protects it |
| `call_in_flight` | a paid call is between its reservation and its settlement: the best state does not cover it yet |
| `no_state` | the payer has signed nothing |
| `close_failed` | the node refused the broadcast (the intent stays; a later call or the watcher adopts or replaces it) |

## Provider: a call in flight at a crash

A direct call reserves its maximum price in `spent_msat` before the handler runs (saved, with the
payer's state and the seq) and refunds the difference once the charge is known. A process that died
in between used to restart with `spent_msat` above what it had billed, and a payer signing its own
meter was refused `insufficient_payment` on every later call of that channel.

* A metered call (a provider with `charge=`) records its reservation in its row:
  `extra["resv"] = {"<seq>": msat}`. Its settlement is always saved before the answer leaves (also
  when the charge equals the price), which removes the record.
* `XbtChannelProvider.__init__` refunds every reservation still recorded and saves the rows;
  `provider.recovered_reservations` is the list of `(chan, msat)`. After a restart `spent_msat` is
  what was charged. A metered call in flight at the crash is charged nothing: its charge was never
  durable and its answer never left.
* An unmetered call's reservation is its exact charge: nothing is recorded, a paid call is still one
  save, and in flight at a crash it stays charged once at its price, as before.
* A handler or `charge` that raises refunds its reservation before the exception leaves `serve`.

There is no setter for `spent_msat`, and an embedder needs none: do not write `ledger.channels`
rows yourself (cmp's `reconcile_direct` / `_reconcile_chan` can go). A row written by an older build
that crashed mid-call still holds its reservation unrecorded; nothing in the row tells it from a
charge, so it is not touched.

## API changes

All additive: `XbtChannelClient.request(..., headers=None, cum=None)`, `.close(origin, cum=None)`;
`XbtChannelProvider.close_channel(chan)`, `.recovered_reservations`. Behaviour: a metered provider
saves once more per call when the charge equals the price; a handler that raises no longer leaves
its reservation in `spent_msat`; a row may carry `extra["resv"]` while a call is in flight.
Tests: `tests/security/test_agp059_embedder_api.py`.
