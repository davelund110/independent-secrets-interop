#!/bin/sh
# interop.py runs $BITCOIN_BIN/bitcoind: put this script there as `bitcoind`,
# pointing at a BLAKE2b Knots build, so regtest has BLAKE2b from block 1.
exec /path/to/knots-blake2b/bin/bitcoind \
    -testactivationheight=blake2b@${BLAKE2B_ACTIVATION_HEIGHT:-1} \
    -rejectparasites=0 "$@"
