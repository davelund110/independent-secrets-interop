# Simple taproot channels under option_unified_sigs: lnd on a BLAKE2b regtest

`taproot_regtest.py` runs two Lightning Fork (lnd) nodes on a BLAKE2b regtest
with simple taproot channels that carry `option_unified_sigs`, as proposed in
the BOLT 3 section "Simple taproot channels"
(davelund110/bolts, branch `taproot-unified-sigs`, for
lightning-blake2b/bolts#13).

Bitcoin Knots runs with BLAKE2b active from block 1, so every transaction is
checked against the unified signature hash by the node before it confirms.

| Scenario | What happens |
|---|---|
| `coop` | open, keysend both ways, cooperative close |
| `success` | bob holds an HTLC, force closes, then settles: bob's HTLC-success transaction |
| `timeout` | bob holds an HTLC, alice force closes and waits out the expiry: alice's HTLC-timeout transaction |
| `breach` | bob broadcasts a revoked commitment (his channel.db restored from an earlier copy); alice's breach arbiter sweeps it |

For each, the script checks on chain that:

- the channel is a taproot channel with `option_unified_sigs`;
- the funding output's key-path signature, on the commitment and on the
  cooperative close, is 65 bytes ending in `0x21`;
- in each HTLC-success and HTLC-timeout transaction the peer's signature ends
  in `0xa3` and the broadcaster's in `0x21`;
- for the breach, the revoked output is swept by alice's breach arbiter.

## What it needs

| Piece | Version | Where |
|---|---|---|
| Bitcoin Knots with BLAKE2b | v29.4.1.knots20260508, `bitcoind` only (the script talks JSON-RPC itself, so no `bitcoin-cli` or ZMQ is needed) | `$REGTEST_BIN/bitcoind` |
| Lightning Fork | davelund110/lightning-fork, branch `taproot-unified-sigs` | `$REGTEST_BIN/lnd`, `$REGTEST_BIN/lncli` |
| Python 3 | standard library only | |

lnd is built with the release tags:

```
TAGS=autopilotrpc,signrpc,walletrpc,chainrpc,invoicesrpc,watchtowerrpc,neutrinorpc,monitoring,peersrpc,offersrpc,bridgerpc,routerrpc
go build -tags=$TAGS -o $REGTEST_BIN/lnd   ./cmd/lnd
go build -tags=$TAGS -o $REGTEST_BIN/lncli ./cmd/lncli
```

The script starts bitcoind with `-testactivationheight=blake2b@1`, and lnd
with `--bitcoind.rpcpolling`, `--bitcoin.blake2b-activation-height=1` and
`--protocol.simple-taproot-chans`. `REGTEST_BIN` defaults to `./bin` and
`REGTEST_RUN` (data directories, kept for inspection) to `./run`. It uses fixed
local ports (28443, 28444, 29735, 29736, 20009, 20010), so run one copy at a
time.

`BITCOIND_EXTRA` adds options to bitcoind:

- `-rdtsexpiry=4000000000` applies the BIP-110 rules from block 1 to the
  regtest (they apply on mainnet from the BLAKE2b height). `getdeploymentinfo`
  then shows `reduced_data` active from height 1.
- `-acceptnonstddatacarrier=1` lets the breach scenario's justice transaction
  through (below).

## Running

```
./taproot_regtest.py                 # all four
./taproot_regtest.py breach          # one
BITCOIND_EXTRA="-rdtsexpiry=4000000000 -acceptnonstddatacarrier=1" ./taproot_regtest.py
```

## Results (25 Oct 2026)

Lightning Fork at `325d979` (`blake2b` at `ea58263` plus the change), Knots
v29.4.1.knots20260508:

| Scenario | Default policy | BIP-110 on | BIP-110 on, `-acceptnonstddatacarrier=1` |
|---|---|---|---|
| `coop` | pass | pass | pass |
| `success` | pass | pass | pass |
| `timeout` | pass | pass | pass |
| `breach` | **fails** | not run | pass |

No simple taproot channel script uses `OP_IF` or `OP_NOTIF`, and no push in
them is over 32 bytes, so the BIP-110 rules do not affect these transactions.

## Knots refuses the taproot justice transaction

With Knots' default policy, alice's breach arbiter detects the revoked
commitment and broadcasts its justice transaction at once, but every attempt is
refused with `txn-datacarrier-nonstandard`. After the CSV delay bob sweeps his
own output and the breach goes unpunished.

The justice transaction spends the `to_local` output through its revocation
leaf, which bolt-simple-taproot.md defines as:

```
<local_delayedpubkey> OP_DROP <revocationkey> OP_CHECKSIG
```

Knots' `CScript::DatacarrierBytes` counts a push followed by `OP_DROP` as
datacarrier bytes, and a transaction with such bytes in an input is refused
unless `-acceptnonstddatacarrier` is set (`validation.cpp`, the
`txn-datacarrier-nonstandard` check). No other simple taproot channel script
has a push followed by `OP_DROP`, which is why the other scenarios confirm.
With `-acceptnonstddatacarrier=1` alice's justice transaction confirms and
takes bob's revoked output.

The Lightning scripts Knots relays are also the subject of
bitcoinknots/bitcoin#481 (known input script shapes), where the taproot anchor
leaf came up.
