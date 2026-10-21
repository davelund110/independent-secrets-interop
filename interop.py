#!/usr/bin/env python3
"""Interop test of option_independent_secrets between the lnd fork (Lightning
Fork) and the Core Lightning BLAKE2b fork, on a Bitcoin Knots BLAKE2b regtest.

Each scenario runs on a fresh chain.  "KDF secrets" are per-commitment secrets
from the dev senders (lnd --dev.independent-secrets-sender, CLN
--dev-independent-secrets-sender), which no shachain would accept.

lnd sends KDF secrets, CLN keeps them:
  lnd-cheats       lnd broadcasts a revoked commitment (its channel.db restored
                   from a copy); CLN takes everything with the stored secret.
  lnd-cheats-htlc  The same with an HTLC in flight on the revoked commitment,
                   and CLN restarted while its penalties are unconfirmed.
  lnd-long         About 100 rounds of payments with restarts of each side in
                   between, then lnd broadcasts a state from the middle.
  lnd-coop         A cooperative close, after which CLN keeps one secret.

CLN sends KDF secrets, lnd keeps them:
  cln-cheats       CLN broadcasts a revoked commitment (dev-sign-last-tx), after
                   both restart; lnd's breach arbiter takes everything.
  cln-cheats-htlc  The same with an HTLC in flight, broadcast while lnd is
                   down, so lnd finds the breach when it starts.
  cln-long         As lnd-long, the other way round.
  cln-coop         A cooperative close.

A peer which uses a shachain:
  shachain-peer    lnd sends ordinary secrets: CLN keeps them all in its
                   shachain, stores none, and punishes from the shachain.

Payments are keysend, so neither side needs the other's invoices.

Only lnd's integration build (go build -tags=integration) has its dev sender,
so the lnd-* scenarios use it.  That build offers anchors only with
--protocol.anchors and never signs with the unified sighash, so CLN runs
there with --dev-force-features=-515: it requires option_unified_sigs on new
channels while it offers it.  The cln-* and shachain-peer scenarios use a
release build of lnd and an unmodified CLN, so their channels have
option_unified_sigs as well.

hold.py, next to this script, is a CLN plugin that holds incoming HTLCs for
the -htlc scenarios.  The paths below default to directories under $HOME;
set CLN_SRC, LND_INTEGRATION and LND_RELEASE (directories holding lnd and
lncli), BITCOIN_BIN (holding bitcoind and bitcoin-cli), PYDEPS and
INTEROP_RUN to run it elsewhere.

Usage: interop.py [scenario...]     (all by default)
"""
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time

HOME = os.path.expanduser('~')
CLN_SRC = os.environ.get('CLN_SRC', HOME + '/privkeyio/lightning')
LIGHTNINGD = CLN_SRC + '/lightningd/lightningd'
LIGHTNING_CLI = CLN_SRC + '/cli/lightning-cli'
BITCOIN_BIN = os.environ.get('BITCOIN_BIN', HOME + '/bin')
BITCOIND = BITCOIN_BIN + '/bitcoind'     # wrapper: -testactivationheight=blake2b@1
BITCOIN_CLI = BITCOIN_BIN + '/bitcoin-cli'
LND_INTEGRATION = os.environ.get('LND_INTEGRATION', HOME + '/interop/bin')      # go build -tags=integration
LND_RELEASE = os.environ.get('LND_RELEASE', HOME + '/interop/bin-release')  # the release tags, no dev ones
HOLD_PLUGIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hold.py')
PLUGIN_PYTHONPATH = ':'.join([CLN_SRC + '/contrib/pyln-client',
                              CLN_SRC + '/contrib/pyln-proto',
                              os.environ.get('PYDEPS', HOME + '/pydeps/site')]
                             + sorted(glob.glob(CLN_SRC + '/contrib/pyln-spec/bolt*')))

BASE = os.environ.get('INTEROP_RUN', HOME + '/interop/run')
RPCPORT, P2PPORT = 28443, 28444
ZMQBLOCK, ZMQTX = 28332, 28333
CLN_PORT = 29735
LND_PORT, LND_RPC, LND_REST = 29736, 20009, 28080

OPT_UNIFIED_SIGS = 514
OPT_INDEPENDENT_SECRETS = int(os.environ.get("INDEPENDENT_SECRETS_BIT", "266"))
CHANNEL_SAT = 1_000_000
PUSH_SAT = 200_000


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def run(cmd, check=True, timeout=120, env=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed ({p.returncode}): {p.stdout}{p.stderr}")
    return p.stdout


class Died(Exception):
    pass


def wait_for(fn, what, timeout=120, interval=0.5):
    start = time.time()
    last = None
    while time.time() - start < timeout:
        try:
            if fn():
                return
        except Died:
            raise
        except Exception as e:  # noqa: B902
            last = e
        time.sleep(interval)
    raise TimeoutError(f'timed out waiting for {what} (last error: {last})')


class Bitcoind:
    def __init__(self, d):
        self.dir = d
        os.makedirs(d, exist_ok=True)

    def start(self):
        run([BITCOIND, '-regtest', f'-datadir={self.dir}', '-daemon', '-server',
             '-txindex', '-fallbackfee=0.0002', '-rpcuser=u', '-rpcpassword=p',
             f'-rpcport={RPCPORT}', f'-port={P2PPORT}', '-listen=0', '-debug=0',
             f'-zmqpubrawblock=tcp://127.0.0.1:{ZMQBLOCK}',
             f'-zmqpubrawtx=tcp://127.0.0.1:{ZMQTX}'])
        wait_for(lambda: self.cli('getblockchaininfo'), 'bitcoind')
        self.cli('createwallet', 'w')
        self.addr = self.cli('getnewaddress', parse=False).strip()
        self.mine(101)

    def cli(self, *args, parse=True):
        out = run([BITCOIN_CLI, '-regtest', f'-datadir={self.dir}', '-rpcuser=u',
                   '-rpcpassword=p', f'-rpcport={RPCPORT}'] + [str(a) for a in args])
        return json.loads(out) if parse and out.strip() else out

    def mine(self, n):
        return self.cli('generatetoaddress', n, self.addr)

    def mempool(self):
        return self.cli('getrawmempool')

    def stop(self):
        try:
            self.cli('stop', parse=False)
        except Exception:
            pass

        # The next scenario reuses the ports: wait until this one has gone.
        def gone():
            try:
                self.cli('getblockcount')
                return False
            except Exception:
                return not os.path.exists(f'{self.dir}/regtest/bitcoind.pid')
        wait_for(gone, 'bitcoind to stop', timeout=60)


class Cln:
    def __init__(self, d, btcdir, extra=()):
        self.dir = d
        self.btcdir = btcdir
        self.extra = list(extra)
        self.proc = None
        os.makedirs(d, exist_ok=True)

    def start(self):
        cmd = [LIGHTNINGD, '--network=regtest', f'--lightning-dir={self.dir}',
               f'--bitcoin-datadir={self.btcdir}', f'--bitcoin-cli={BITCOIN_CLI}',
               f'--bitcoin-rpcport={RPCPORT}', '--bitcoin-rpcuser=u',
               '--bitcoin-rpcpassword=p', f'--addr=127.0.0.1:{CLN_PORT}',
               '--log-level=debug', f'--log-file={self.dir}/log',
               '--developer', '--dev-bitcoind-poll=1', '--dev-fast-gossip',
               '--funding-confirms=1', '--ignore-fee-limits=true',
               '--force-feerates=7500', '--dev-no-version-checks',
               # Off by default: every scenario wants CLN to offer it.
               '--independent-secrets',
               f'--plugin={HOLD_PLUGIN}'] + self.extra
        env = dict(os.environ, PYTHONPATH=PLUGIN_PYTHONPATH)
        self.out = open(f'{self.dir}/stdout', 'a')
        self.proc = subprocess.Popen(cmd, stdout=self.out, stderr=subprocess.STDOUT, env=env)
        wait_for(lambda: self.alive() and self.rpc('getinfo')['blockheight'] > 0, 'lightningd')
        self.id = self.rpc('getinfo')['id']

    def alive(self):
        if self.proc.poll() is not None:
            raise Died(f'lightningd exited ({self.proc.returncode}): see {self.dir}/log')
        return True

    def rpc(self, method, *args, **kwargs):
        cmd = [LIGHTNING_CLI, '--network=regtest', f'--lightning-dir={self.dir}', '-J']
        if kwargs:
            cmd += ['-k', method] + [f'{k}={v}' for k, v in kwargs.items()]
        else:
            cmd += [method] + [str(a) for a in args]
        # Progress notifications come first, as '#' lines.
        out = '\n'.join(line for line in run(cmd).splitlines() if not line.startswith('#'))
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            raise RuntimeError(f'{method}: not JSON: {out!r}')

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.rpc('stop')
            except Exception:
                self.proc.terminate()
            self.proc.wait(60)
        self.proc = None

    def restart(self):
        self.stop()
        self.start()

    def logs(self):
        with open(f'{self.dir}/log') as f:
            return f.read()

    def db_query(self, q):
        # A copy, so we never touch the live database.
        copy = f'{self.dir}/query.sqlite3'
        shutil.copyfile(f'{self.dir}/regtest/lightningd.sqlite3', copy)
        db = sqlite3.connect(copy)
        try:
            return db.execute(q).fetchall()
        finally:
            db.close()


class Lnd:
    def __init__(self, d, extra=(), release=False):
        self.dir = d
        self.extra = list(extra)
        self.release = release
        bindir = LND_RELEASE if release else LND_INTEGRATION
        self.lnd, self.lncli = f'{bindir}/lnd', f'{bindir}/lncli'
        self.proc = None
        os.makedirs(d, exist_ok=True)

    def start(self):
        cmd = [self.lnd, f'--lnddir={self.dir}', '--bitcoin.active', '--bitcoin.regtest',
               '--bitcoin.node=bitcoind', f'--bitcoind.rpchost=127.0.0.1:{RPCPORT}',
               '--bitcoind.rpcuser=u', '--bitcoind.rpcpass=p',
               f'--bitcoind.zmqpubrawblock=tcp://127.0.0.1:{ZMQBLOCK}',
               f'--bitcoind.zmqpubrawtx=tcp://127.0.0.1:{ZMQTX}',
               '--bitcoin.blake2b-activation-height=1', '--bitcoin.defaultchanconfs=1',
               '--noseedbackup', '--accept-keysend', '--debuglevel=debug',
               f'--listen=127.0.0.1:{LND_PORT}', f'--rpclisten=127.0.0.1:{LND_RPC}',
               f'--restlisten=127.0.0.1:{LND_REST}', '--trickledelay=50',
               '--norest', '--nobootstrap',
               # Off by default in Lightning Fork.
               '--protocol.independent-secrets'] + self.extra
        if not self.release:
            # Opt-in in the integration build, the default in a release.
            cmd.append('--protocol.anchors')
        self.out = open(f'{self.dir}/stdout', 'a')
        self.proc = subprocess.Popen(cmd, stdout=self.out, stderr=subprocess.STDOUT)
        wait_for(lambda: self.alive() and self.cli('getinfo')['synced_to_chain'],
                 'lnd synced', timeout=180)
        self.id = self.cli('getinfo')['identity_pubkey']

    def alive(self):
        if self.proc.poll() is not None:
            raise Died(f'lnd exited ({self.proc.returncode}): see {self.dir}/stdout')
        return True

    def cli_cmd(self, *args):
        return [self.lncli, f'--lnddir={self.dir}', '--network=regtest',
                f'--rpcserver=127.0.0.1:{LND_RPC}'] + [str(a) for a in args]

    def cli(self, *args):
        out = run(self.cli_cmd(*args))
        # Some commands stream several JSON objects: return the last.
        dec, pos, last = json.JSONDecoder(), 0, {}
        out = out.strip()
        while pos < len(out):
            start = out.find('{', pos)
            if start < 0:
                break
            last, pos = dec.raw_decode(out, start)
        return last

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.cli('stop')
            except Exception:
                self.proc.terminate()
            self.proc.wait(120)
        self.proc = None

    def restart(self):
        self.stop()
        self.start()

    def channel_db(self):
        return f'{self.dir}/data/graph/regtest/channel.db'

    def logs(self):
        with open(f'{self.dir}/logs/bitcoin/regtest/lnd.log') as f:
            return f.read()

    def wallet(self):
        return int(self.cli('walletbalance')['confirmed_balance'])


def fund_cln(btc, cln, sats=2_000_000):
    r = cln.rpc('newaddr')
    addr = r.get('p2tr') or r['bech32']
    btc.cli('sendtoaddress', addr, sats / 1e8, parse=False)
    btc.mine(1)
    wait_for(lambda: len(cln.rpc('listfunds')['outputs']) > 0, 'CLN funds')


def fund_lnd(btc, lnd, sats=2_000_000):
    addr = lnd.cli('newaddress', 'p2wkh')['address']
    btc.cli('sendtoaddress', addr, sats / 1e8, parse=False)
    btc.mine(1)
    wait_for(lambda: lnd.wallet() > 0, 'lnd funds')


def cln_channel(cln, lnd):
    chans = cln.rpc('listpeerchannels', lnd.id)['channels']
    assert len(chans) == 1, chans
    return chans[0]


def lnd_channel(lnd):
    chans = lnd.cli('listchannels')['channels']
    assert len(chans) == 1, chans
    return chans[0]


def both_active(cln, lnd):
    c = cln_channel(cln, lnd)
    return (c['state'] == 'CHANNELD_NORMAL' and c['peer_connected']
            and lnd.cli('listchannels')['channels']
            and lnd_channel(lnd)['active'])


def reconnect(cln, lnd):
    """After either side restarts, CLN dials lnd (lnd can't dial back: CLN
    doesn't announce a localhost address)."""
    def go():
        if not cln_channel(cln, lnd)['peer_connected']:
            cln.rpc('connect', lnd.id, '127.0.0.1', LND_PORT)
        return both_active(cln, lnd)
    wait_for(go, 'channel active again', timeout=180, interval=1)


def keysend_cln_to_lnd(cln, lnd, msat):
    r = cln.rpc('xkeysend', lnd.id, msat)
    assert r['successful_parts'] > 0 and 'payment_preimage' in r, r


def keysend_lnd_to_cln(cln, lnd, sat):
    # Just after the channel comes up lnd may not route over it yet, which it
    # reports as a failure.
    for attempt in range(30):
        try:
            r = lnd.cli('sendpayment', '--dest', cln.id, '--amt', sat, '--keysend',
                        '--force', '--json')
        except RuntimeError as e:
            if 'FAILURE_REASON_' in str(e) and attempt < 29:
                time.sleep(1)
                continue
            raise
        assert r.get('status') == 'SUCCEEDED', r
        return


def keysend_lnd_to_cln_async(cln, lnd, sat):
    """Start a payment which CLN will hold, without waiting for it."""
    return subprocess.Popen(lnd.cli_cmd('sendpayment', '--dest', cln.id, '--amt', sat,
                                        '--keysend', '--force', '--json'),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def settle(cln, lnd):
    wait_for(lambda: cln_channel(cln, lnd)['htlcs'] == []
             and lnd_channel(lnd)['pending_htlcs'] == [], 'HTLCs settled')


def pay_back_and_forth(cln, lnd, rounds, lnd_sat=20_000, cln_msat=5_000_000):
    for _ in range(rounds):
        keysend_lnd_to_cln(cln, lnd, lnd_sat)
        keysend_cln_to_lnd(cln, lnd, cln_msat)
    settle(cln, lnd)


def hold_one_htlc(cln, lnd, sat=30_000):
    """An lnd->CLN payment, committed on both sides and held there."""
    cln.rpc('hold_htlcs')
    proc = keysend_lnd_to_cln_async(cln, lnd, sat)
    wait_for(lambda: [h for h in cln_channel(cln, lnd)['htlcs']
                      if h['state'] == 'RCVD_ADD_ACK_REVOCATION']
             and lnd_channel(lnd)['pending_htlcs']
             and 'holding htlc' in cln.logs(), 'HTLC committed and held')
    return proc


def release_htlcs(cln, lnd, proc):
    assert cln.rpc('release_htlcs')['released'] == 1
    settle(cln, lnd)
    if proc.poll() is None:
        proc.wait(60)


def check_types(cln, lnd):
    ctype = cln_channel(cln, lnd)['channel_type']
    log('CLN channel_type', ctype['bits'], ctype['names'])
    assert OPT_INDEPENDENT_SECRETS in ctype['bits']
    assert 'independent_secrets/even' in ctype['names']
    # The integration build of lnd doesn't offer option_unified_sigs.
    assert (OPT_UNIFIED_SIGS in ctype['bits']) == lnd.release, ctype
    ch = lnd_channel(lnd)
    log('lnd channel: independent_secrets =', ch.get('independent_secrets'),
        'commitment_type =', ch.get('commitment_type'))
    assert ch.get('independent_secrets') is True
    assert ch.get('commitment_type') == 'ANCHORS'


def cln_stored(cln):
    return [r[0] for r in cln.db_query(
        'SELECT commitnum FROM channel_revocation_secrets ORDER BY commitnum')]


def assert_stored_from_1(cln):
    """With a KDF sender, secret 0 fits an empty shachain and secret 1 can't
    extend it: CLN stores every secret from 1 on, without gaps."""
    n = cln_stored(cln)
    assert n == list(range(1, len(n) + 1)) and len(n) > 0, n
    assert "Per-commitment secret 1 doesn't fit a shachain" in cln.logs()
    return n


def assert_cln_calm(cln):
    logs = cln.logs()
    for bad in ('Bad per_commitment_secret', 'No per-commitment secret stored',
                'bad reestablish', 'Wrong privkey'):
        assert bad not in logs, bad


def open_from_lnd(btc, cln, lnd):
    fund_lnd(btc, lnd)
    lnd.cli('connect', f'{cln.id}@127.0.0.1:{CLN_PORT}')
    lnd.cli('openchannel', '--node_key', cln.id, '--local_amt', CHANNEL_SAT,
            '--push_amt', PUSH_SAT)
    wait_for(lambda: len(btc.mempool()) > 0, 'funding tx')
    btc.mine(6)
    wait_for(lambda: both_active(cln, lnd), 'channel active', timeout=180)
    check_types(cln, lnd)


def open_from_cln(btc, cln, lnd):
    fund_cln(btc, cln)
    cln.rpc('connect', lnd.id, '127.0.0.1', LND_PORT)
    cln.rpc('fundchannel', id=lnd.id, amount=CHANNEL_SAT, push_msat=PUSH_SAT * 1000)
    btc.mine(6)
    wait_for(lambda: both_active(cln, lnd), 'channel active', timeout=180)
    check_types(cln, lnd)


def snapshot_lnd(base, lnd, cln):
    """lnd's state as of now, for it to broadcast once that state is revoked."""
    lnd.stop()
    shutil.copyfile(lnd.channel_db(), f'{base}/channel.db.old')
    lnd.start()
    reconnect(cln, lnd)


def lnd_broadcasts_snapshot(base, btc, cln, lnd):
    """lnd force-closes with its old state while CLN is down."""
    cln.stop()
    lnd.stop()
    shutil.copyfile(f'{base}/channel.db.old', lnd.channel_db())
    lnd.start()
    txid, vout = lnd_channel(lnd)['channel_point'].split(':')
    lnd.cli('closechannel', '--force', '--funding_txid', txid, '--output_index', vout)
    wait_for(lambda: len(btc.mempool()) > 0, 'revoked commitment in mempool')
    log('lnd broadcast', btc.mempool())
    btc.mine(1)


def cln_penalises(btc, cln, outputs, restart_midway=False):
    """CLN, started after the breach confirmed, takes every output.

    An HTLC output can instead be spent first by the cheater's own
    HTLC-timeout transaction, once the HTLC expires: CLN then takes that
    transaction's output with a second penalty.  Either way CLN gets it."""
    cln.start()
    wait_for(lambda: 'THEIR_REVOKED_UNILATERAL' in cln.logs(), 'CLN sees the cheat')
    for out in outputs:
        wait_for(lambda: ('Telling lightningd about OUR_PENALTY_TX to resolve '
                          f'THEIR_REVOKED_UNILATERAL/{out}') in cln.logs(),
                 f'CLN proposes a penalty for {out}')
    log('CLN:', [line.split('onchaind-chan#1: ')[-1] for line in cln.logs().splitlines()
                 if 'commitnum = ' in line][-1])
    if restart_midway:
        log('restarting CLN before its penalties confirm')
        cln.restart()

    def taken(out):
        logs = cln.logs()
        if f'Resolved THEIR_REVOKED_UNILATERAL/{out} by our proposal OUR_PENALTY_TX' in logs:
            return 'penalty'
        if (out == 'THEIR_HTLC'
                and 'Resolved THEIR_REVOKED_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM' in logs
                and 'Resolved THEIR_HTLC_TIMEOUT_TO_THEM/DELAYED_CHEAT_OUTPUT_TO_THEM by our proposal OUR_PENALTY_TX' in logs):
            return 'penalty of their HTLC-timeout'
        return None

    def resolved():
        btc.mine(1)
        return all(taken(out) for out in outputs)
    wait_for(resolved, 'CLN takes every output', timeout=300, interval=1)
    for out in outputs:
        log(f'CLN took {out} by', taken(out))
    assert_cln_calm(cln)


def cln_forgets(btc, cln):
    btc.mine(110)
    wait_for(lambda: cln.rpc('listpeerchannels')['channels'] == [],
             'CLN forgets the channel', timeout=180)


def lnd_closed_as(lnd, close_type):
    return any(c.get('close_type') == close_type
               for c in lnd.cli('closedchannels').get('channels', []))


def assert_lnd_closed_independent(lnd):
    # closedchannels reports the add-on, since a closed channel with it
    # still keeps the database at version 39.
    closed = lnd.cli('closedchannels').get('channels', [])
    assert closed and all(c.get('independent_secrets') for c in closed), closed


def mine_until(btc, fn, what, timeout=180):
    def go():
        if fn():
            return True
        btc.mine(1)
        return False
    wait_for(go, what, timeout=timeout, interval=2)


def lnd_takes_everything(btc, lnd):
    # A release build waits for the breach to have a few confirmations.
    mine_until(btc, lambda: 'Broadcasting justice tx' in lnd.logs(), 'lnd justice tx')

    mine_until(btc, lambda: lnd_closed_as(lnd, 'BREACH_CLOSE'), 'lnd records a breach close')
    log('lnd closedchannels', [(c['close_type'], c['settled_balance'])
                               for c in lnd.cli('closedchannels')['channels']])
    # lnd funded nothing: everything in its wallet came from the channel.
    wait_for(lambda: lnd.wallet() > CHANNEL_SAT * 0.98, 'lnd swept the channel',
             timeout=60)
    log('lnd wallet', lnd.wallet(), 'of the', CHANNEL_SAT, 'sat channel')


def long_run(btc, cln, lnd, on_round):
    """About 100 rounds of small payments, about 400 revocations each way."""
    for r in range(1, 101):
        keysend_lnd_to_cln(cln, lnd, 2_000)
        keysend_cln_to_lnd(cln, lnd, 1_500_000)
        on_round(r)
    settle(cln, lnd)


class Nodes:
    def __init__(self, base, cln_extra=(), lnd_extra=(), release=False):
        self.btc = Bitcoind(f'{base}/btc')
        self.cln = Cln(f'{base}/cln', f'{base}/btc', cln_extra)
        self.lnd = Lnd(f'{base}/lnd', lnd_extra, release=release)

    def __enter__(self):
        self.btc.start()
        self.cln.start()
        self.lnd.start()
        return self.btc, self.cln, self.lnd

    def __exit__(self, *exc):
        for n in (self.cln, self.lnd):
            try:
                n.stop()
            except Exception as e:
                log('stop failed', e)
        self.btc.stop()


# lnd's dev sender needs its integration build, which CLN only opens new
# channels with when it doesn't offer option_unified_sigs.
LND_SENDS = dict(cln_extra=['--dev-force-features=-515'],
                 lnd_extra=['--dev.independent-secrets-sender'])
CLN_SENDS = dict(cln_extra=['--dev-independent-secrets-sender'], release=True)


def scenario_lnd_cheats(base):
    with Nodes(base, **LND_SENDS) as (btc, cln, lnd):
        open_from_lnd(btc, cln, lnd)
        pay_back_and_forth(cln, lnd, 3)
        log('CLN holds lnd secrets for commitments', assert_stored_from_1(cln))
        snapshot_lnd(base, lnd, cln)
        pay_back_and_forth(cln, lnd, 4)
        n1 = assert_stored_from_1(cln)
        log('after the snapshot, CLN holds', len(n1), 'secrets')
        lnd_broadcasts_snapshot(base, btc, cln, lnd)
        cln_penalises(btc, cln, ['DELAYED_CHEAT_OUTPUT_TO_THEM'])
        cln_forgets(btc, cln)
        log('CLN keeps', cln_stored(cln), 'once the channel is closed')
        assert cln_stored(cln) == [n1[-1]]


def scenario_lnd_cheats_htlc(base):
    with Nodes(base, **LND_SENDS) as (btc, cln, lnd):
        open_from_lnd(btc, cln, lnd)
        pay_back_and_forth(cln, lnd, 3)
        proc = hold_one_htlc(cln, lnd)
        snapshot_lnd(base, lnd, cln)
        release_htlcs(cln, lnd, proc)
        pay_back_and_forth(cln, lnd, 3)
        n1 = assert_stored_from_1(cln)
        lnd_broadcasts_snapshot(base, btc, cln, lnd)
        cln_penalises(btc, cln, ['DELAYED_CHEAT_OUTPUT_TO_THEM', 'THEIR_HTLC'],
                      restart_midway=True)
        cln_forgets(btc, cln)
        assert cln_stored(cln) == [n1[-1]]


def scenario_lnd_long(base):
    with Nodes(base, **LND_SENDS) as (btc, cln, lnd):
        open_from_lnd(btc, cln, lnd)

        def on_round(r):
            if r == 25:
                cln.restart()
                reconnect(cln, lnd)
            elif r == 50:
                settle(cln, lnd)
                snapshot_lnd(base, lnd, cln)
                log('snapshot at round 50: CLN holds', len(cln_stored(cln)), 'secrets')
            elif r == 75:
                cln.restart()
                lnd.restart()
                reconnect(cln, lnd)
        long_run(btc, cln, lnd, on_round)
        n = assert_stored_from_1(cln)
        log('after 100 rounds CLN holds', len(n), 'secrets')
        assert len(n) > 300, len(n)
        lnd_broadcasts_snapshot(base, btc, cln, lnd)
        cln_penalises(btc, cln, ['DELAYED_CHEAT_OUTPUT_TO_THEM'])
        cln_forgets(btc, cln)
        assert cln_stored(cln) == [n[-1]]


def scenario_lnd_coop(base):
    with Nodes(base, **LND_SENDS) as (btc, cln, lnd):
        open_from_lnd(btc, cln, lnd)
        pay_back_and_forth(cln, lnd, 3)
        cln.restart()
        lnd.restart()
        reconnect(cln, lnd)
        pay_back_and_forth(cln, lnd, 2)
        n = assert_stored_from_1(cln)
        txid, vout = lnd_channel(lnd)['channel_point'].split(':')
        lnd.cli('closechannel', '--funding_txid', txid, '--output_index', vout)
        wait_for(lambda: len(btc.mempool()) > 0, 'mutual close in mempool')
        btc.mine(6)
        mine_until(btc, lambda: lnd_closed_as(lnd, 'COOPERATIVE_CLOSE'),
                   'lnd records a cooperative close')
        assert_lnd_closed_independent(lnd)
        cln_forgets(btc, cln)
        assert cln_stored(cln) == [n[-1]]
        assert 'THEIR_REVOKED_UNILATERAL' not in cln.logs()
        assert_cln_calm(cln)
        closed = cln.rpc('listclosedchannels')['closedchannels']
        log('CLN closed channel:', closed[0]['close_cause'], closed[0]['channel_type']['names'])


def scenario_cln_cheats(base):
    with Nodes(base, **CLN_SENDS) as (btc, cln, lnd):
        open_from_cln(btc, cln, lnd)
        pay_back_and_forth(cln, lnd, 3)
        old_tx = cln.rpc('dev-sign-last-tx', lnd.id)['tx']
        # lnd checks your_last_per_commitment_secret against the secret CLN's
        # hsmd made, and CLN against its own.
        cln.stop()
        lnd.restart()
        cln.start()
        reconnect(cln, lnd)
        pay_back_and_forth(cln, lnd, 4)
        # lnd's own secrets come from its shachain, so CLN keeps them in one.
        assert cln_stored(cln) == [], cln_stored(cln)
        btc.cli('sendrawtransaction', old_tx, parse=False)
        btc.mine(1)
        lnd_takes_everything(btc, lnd)
        assert_cln_calm(cln)


def scenario_cln_cheats_htlc(base):
    with Nodes(base, **CLN_SENDS) as (btc, cln, lnd):
        open_from_cln(btc, cln, lnd)
        pay_back_and_forth(cln, lnd, 3)
        proc = hold_one_htlc(cln, lnd)
        old_tx = cln.rpc('dev-sign-last-tx', lnd.id)['tx']
        release_htlcs(cln, lnd, proc)
        pay_back_and_forth(cln, lnd, 3)
        # The breach confirms while lnd is down.
        lnd.stop()
        btc.cli('sendrawtransaction', old_tx, parse=False)
        btc.mine(1)
        lnd.start()
        lnd_takes_everything(btc, lnd)


def scenario_cln_long(base):
    with Nodes(base, **CLN_SENDS) as (btc, cln, lnd):
        open_from_cln(btc, cln, lnd)
        old = {}

        def on_round(r):
            if r == 25:
                lnd.restart()
                reconnect(cln, lnd)
            elif r == 50:
                settle(cln, lnd)
                old['tx'] = cln.rpc('dev-sign-last-tx', lnd.id)['tx']
                cln.restart()
                reconnect(cln, lnd)
            elif r == 75:
                cln.restart()
                lnd.restart()
                reconnect(cln, lnd)
        long_run(btc, cln, lnd, on_round)
        updates = int(lnd_channel(lnd)['num_updates'])
        log('after 100 rounds lnd has', updates, 'channel updates')
        assert updates > 300, updates
        assert cln_stored(cln) == [], cln_stored(cln)
        btc.cli('sendrawtransaction', old['tx'], parse=False)
        btc.mine(1)
        lnd_takes_everything(btc, lnd)
        assert_cln_calm(cln)


def scenario_cln_coop(base):
    with Nodes(base, **CLN_SENDS) as (btc, cln, lnd):
        open_from_cln(btc, cln, lnd)
        pay_back_and_forth(cln, lnd, 3)
        cln.restart()
        lnd.restart()
        reconnect(cln, lnd)
        pay_back_and_forth(cln, lnd, 2)
        cln.rpc('close', lnd.id)
        btc.mine(6)
        mine_until(btc, lambda: lnd_closed_as(lnd, 'COOPERATIVE_CLOSE'),
                   'lnd records a cooperative close')
        assert_lnd_closed_independent(lnd)
        cln_forgets(btc, cln)
        assert cln_stored(cln) == []
        assert_cln_calm(cln)


def scenario_shachain_peer(base):
    with Nodes(base, release=True) as (btc, cln, lnd):
        open_from_lnd(btc, cln, lnd)
        pay_back_and_forth(cln, lnd, 3)
        snapshot_lnd(base, lnd, cln)
        pay_back_and_forth(cln, lnd, 4)
        assert cln_stored(cln) == [], cln_stored(cln)
        lnd_broadcasts_snapshot(base, btc, cln, lnd)
        cln_penalises(btc, cln, ['DELAYED_CHEAT_OUTPUT_TO_THEM'])
        assert "doesn't fit a shachain" not in cln.logs()
        cln_forgets(btc, cln)
        assert cln_stored(cln) == []


SCENARIOS = {
    'lnd-cheats': scenario_lnd_cheats,
    'lnd-cheats-htlc': scenario_lnd_cheats_htlc,
    'lnd-long': scenario_lnd_long,
    'lnd-coop': scenario_lnd_coop,
    'cln-cheats': scenario_cln_cheats,
    'cln-cheats-htlc': scenario_cln_cheats_htlc,
    'cln-long': scenario_cln_long,
    'cln-coop': scenario_cln_coop,
    'shachain-peer': scenario_shachain_peer,
}

if __name__ == '__main__':
    which = sys.argv[1:] or list(SCENARIOS)
    failed = []
    for name in which:
        base = f'{BASE}/{name}'
        shutil.rmtree(base, ignore_errors=True)
        os.makedirs(base)
        log(f'=== {name}')
        start = time.time()
        try:
            SCENARIOS[name](base)
            log(f'PASS {name} ({time.time() - start:.0f}s)')
        except Exception as e:
            log(f'FAIL {name}: {type(e).__name__}: {e}')
            failed.append(name)
    log('failed:', failed or 'none')
    sys.exit(1 if failed else 0)
