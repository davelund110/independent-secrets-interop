# option_independent_secrets interop: Lightning Fork and the CLN fork

`interop.py` runs nine scenarios between one CLN node and one lnd node on a
BLAKE2b regtest, each on a fresh chain. The scenarios are listed in the
script's docstring. All nine take about 6 minutes; `interop.py lnd-cheats`
runs one. The script prints PASS or FAIL per scenario and exits non-zero if
any fails. Each run's data directories stay under `$INTEROP_RUN/<scenario>`
for inspection.

## What it needs

| Piece | Version | Set |
|---|---|---|
| Bitcoin Knots with BLAKE2b | any build that takes `-testactivationheight=blake2b@N` on regtest (we used v29.4.1.knots20260508) | `BITCOIN_BIN`: a directory with `bitcoind` and `bitcoin-cli` |
| Lightning Fork | paulscode/lightning-fork, branch `blake2b` (PR #7 is merged there), built twice | `LND_INTEGRATION` and `LND_RELEASE`: directories with `lnd` and `lncli` |
| CLN fork | davelund110/lightning, branch `independent-secrets-blip` (PR #48), built in its tree | `CLN_SRC`: the source tree |
| Python 3 | with pyln-client's dependencies (coincurve, base58, bitstring) | `PYDEPS`: a site directory holding them, if they aren't installed |

`INTEROP_RUN` (default `~/interop/run`) is where the runs go.

### bitcoind

`interop.py` starts `$BITCOIN_BIN/bitcoind` with plain regtest flags. Put
`bitcoind-blake2b.sh` there as `bitcoind`, with the path inside it pointing at
your Knots BLAKE2b binary, so BLAKE2b is active from block 1. `bitcoin-cli`
can be the normal one.

### lnd

Both builds come from the same commit:

```
TAGS=autopilotrpc,signrpc,walletrpc,chainrpc,invoicesrpc,watchtowerrpc,neutrinorpc,monitoring,peersrpc,offersrpc,bridgerpc
go build -tags=integration,$TAGS -o $LND_INTEGRATION/lnd   ./cmd/lnd
go build -tags=integration,$TAGS -o $LND_INTEGRATION/lncli ./cmd/lncli
go build -tags=$TAGS             -o $LND_RELEASE/lnd       ./cmd/lnd
go build -tags=$TAGS             -o $LND_RELEASE/lncli     ./cmd/lncli
```

The integration build has `--dev.independent-secrets-sender`, used where lnd
sends independent secrets (the `lnd-*` scenarios). The release build is used
where CLN sends them and in `shachain-peer`. The script starts lnd with
`--protocol.independent-secrets`, since the add-on is off by default from
commit `7dbdb32` on.

### CLN

`./configure && make` in the branch. The script runs it with `--developer`
(for `--dev-independent-secrets-sender` and `dev-sign-last-tx`) and
`--independent-secrets`. `hold.py`, next to `interop.py`, is a plugin that
holds incoming HTLCs for the `-htlc` scenarios.

## Running

```
export BITCOIN_BIN=... LND_INTEGRATION=... LND_RELEASE=... CLN_SRC=... PYDEPS=...
./interop.py                 # all nine
./interop.py cln-cheats      # one
```

It uses fixed local ports (28332, 28333, 28443, 28444, 29735, 29736, 20009,
28080), so run one copy at a time.

## How the breaches are made

These are test-only paths. lnd's breach is its database restored from a copy
taken earlier in the scenario. CLN's is `dev-sign-last-tx`, which needs
`--developer`. Neither works on a release build.

## Results on the current branches

All nine pass with CLN at `383eace` and lnd at `9b0d0b3`, which is what PR #7 merged into `blake2b`.
In every breach, the honest node takes the cheater's balance: CLN with the
secret it stored, lnd with its breach arbiter. `lnd-long` has CLN store 399
secrets and punish a breach of state 200 of 400.

The PRs: [privkeyio/lightning#48](https://github.com/privkeyio/lightning/pull/48)
(CLN), [paulscode/lightning-fork#7](https://github.com/paulscode/lightning-fork/pull/7)
(lnd) and the spec,
[lightning-blake2b/bolts#17](https://github.com/lightning-blake2b/bolts/pull/17).
