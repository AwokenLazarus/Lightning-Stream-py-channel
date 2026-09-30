# Scheme: `xbt-channel` — superseded name

This file used to be the x402 scheme proposal. The decided name is the XBT
network binding of upstream `batch-settlement`, not a new scheme.

**Read [`scheme_batch_settlement_xbt.md`](scheme_batch_settlement_xbt.md).**

The live wire is `scheme: "batch-settlement"` with `extra.assetTransferMethod: "channel"`. Servers and
clients accept `"xbt-channel"` as an input alias for one release. The derivation tag
`xbt-channel/payee/v2` and the control paths `/x402/xbt-channel/*` are unchanged.
