#!/usr/bin/env python3
"""Two Lightning Fork (lnd) nodes on a BLAKE2b regtest, with simple taproot
channels under option_unified_sigs.

Bitcoin Knots with the BLAKE2b rules runs with BLAKE2b active from block 1,
so every transaction below is checked against the unified signature hash by
the node software itself before it confirms.

Scenarios, each on its own channel:
  coop        open, keysend both ways, cooperative close
  success     an HTLC held by bob, bob force closes, then settles: bob's
              HTLC-success transaction (alice's 0xa3, bob's 0x21)
  timeout     an HTLC held by bob, alice force closes and waits out the
              expiry: alice's HTLC-timeout transaction (bob's 0xa3, alice's
              0x21)
  breach      bob broadcasts a revoked commitment (his channel.db restored
              from an earlier copy); alice's breach arbiter takes it all

For each, the script checks the hash type byte of every MuSig2 key-path
signature (0x21, 65 bytes) and HTLC signature on chain.

BITCOIND_EXTRA adds options to bitcoind, for instance -rdtsexpiry=4000000000
to apply the BIP-110 rules from block 1, or -acceptnonstddatacarrier=1, without
which Knots refuses alice's justice transaction in the breach scenario (see
README.md).

Usage: taproot_regtest.py [scenario...]   (all by default)
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import base64

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get('REGTEST_BIN', HERE + '/bin')
RUN = os.environ.get('REGTEST_RUN', HERE + '/run')
RPCPORT, P2PPORT = 28443, 28444
NODES = {'alice': (29735, 20009), 'bob': (29736, 20010)}


class Fail(Exception):
    pass


def wait_for(pred, what, timeout=120, interval=0.5):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            r = pred()
            if r:
                return r
        except Fail:
            raise
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(interval)
    raise Fail(f'timed out waiting for {what}' + (f' ({last})' if last else ''))


class Bitcoind:
    def __init__(self, d):
        self.dir = d
        os.makedirs(d, exist_ok=True)
        self.proc = None

    def start(self):
        self.out = open(f'{self.dir}/stdout', 'a')
        self.proc = subprocess.Popen([
            f'{BIN}/bitcoind', '-regtest', f'-datadir={self.dir}', '-server',
            '-testactivationheight=blake2b@1', '-rejectparasites=0',
            '-rpcuser=u', '-rpcpassword=p', f'-rpcport={RPCPORT}',
            f'-port={P2PPORT}', '-txindex=1', '-fallbackfee=0.0002',
            '-listen=0', '-printtoconsole=0',
        ] + os.environ.get('BITCOIND_EXTRA', '').split(),
            stdout=self.out, stderr=subprocess.STDOUT)
        wait_for(lambda: self.rpc('getblockchaininfo'), 'bitcoind')

    def rpc(self, method, *params):
        req = urllib.request.Request(
            f'http://127.0.0.1:{RPCPORT}/',
            data=json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method,
                             'params': list(params)}).encode(),
            headers={'Authorization': 'Basic ' +
                     base64.b64encode(b'u:p').decode(),
                     'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                res = json.load(r)
        except urllib.error.HTTPError as e:
            res = json.load(e)
        if res.get('error'):
            raise RuntimeError(f'{method}: {res["error"]}')
        return res['result']

    def mine(self, n, addr):
        return self.rpc('generatetoaddress', n, addr)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.rpc('stop')
            except Exception:  # noqa: BLE001
                self.proc.terminate()
            self.proc.wait(60)


class Lnd:
    def __init__(self, name, d):
        self.name, self.dir = name, d
        self.port, self.rpcport = NODES[name]
        os.makedirs(d, exist_ok=True)
        self.proc = None

    def start(self):
        cmd = [f'{BIN}/lnd', f'--lnddir={self.dir}', '--bitcoin.regtest',
               '--bitcoin.node=bitcoind',
               f'--bitcoind.rpchost=127.0.0.1:{RPCPORT}',
               '--bitcoind.rpcuser=u', '--bitcoind.rpcpass=p',
               '--bitcoind.rpcpolling',
               '--bitcoind.blockpollinginterval=1s',
               '--bitcoind.txpollinginterval=1s',
               '--bitcoin.blake2b-activation-height=1',
               '--bitcoin.defaultchanconfs=1', '--noseedbackup',
               '--accept-keysend', '--debuglevel=debug',
               '--protocol.simple-taproot-chans',
               f'--listen=127.0.0.1:{self.port}',
               f'--rpclisten=127.0.0.1:{self.rpcport}',
               '--norest', '--nobootstrap', '--trickledelay=50']
        self.out = open(f'{self.dir}/stdout', 'a')
        self.proc = subprocess.Popen(cmd, stdout=self.out,
                                     stderr=subprocess.STDOUT)
        wait_for(lambda: self.alive() and self.cli('getinfo')['synced_to_chain'],
                 f'{self.name} synced', timeout=180)
        self.id = self.cli('getinfo')['identity_pubkey']

    def alive(self):
        if self.proc.poll() is not None:
            raise Fail(f'{self.name} exited: see {self.dir}/stdout')
        return True

    def cli_cmd(self, *args):
        return [f'{BIN}/lncli', f'--lnddir={self.dir}', '--network=regtest',
                f'--rpcserver=127.0.0.1:{self.rpcport}'] + [str(a) for a in args]

    def cli(self, *args):
        p = subprocess.run(self.cli_cmd(*args), capture_output=True, text=True,
                           timeout=120)
        if p.returncode != 0:
            raise RuntimeError(f'{self.name} {args[0]}: {p.stderr.strip() or p.stdout.strip()}')
        out = p.stdout.strip()
        dec, pos, last = json.JSONDecoder(), 0, {}
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
            except Exception:  # noqa: BLE001
                self.proc.terminate()
            self.proc.wait(120)
        self.proc = None

    def chandb(self):
        return f'{self.dir}/data/graph/regtest/channel.db'

    def address(self):
        return self.cli('newaddress', 'p2tr')['address']

    def balance(self):
        return int(self.cli('walletbalance')['confirmed_balance'])


def keysend(src, dst, amt):
    """Keysend, retried while a just-opened channel's link comes up."""
    def attempt():
        try:
            src.cli('sendpayment', f'--dest={dst.id}', f'--amt={amt}', '--keysend')
            return True
        except RuntimeError as e:
            if 'FAILED' in str(e) or 'insufficient' in str(e):
                return False
            raise
    wait_for(attempt, f'keysend of {amt} from {src.name}', timeout=60, interval=2)


def check(cond, msg):
    if not cond:
        raise Fail(msg)
    print(f'    ok: {msg}')


class Net:
    def __init__(self):
        shutil.rmtree(RUN, ignore_errors=True)
        self.btc = Bitcoind(f'{RUN}/bitcoind')
        self.alice = Lnd('alice', f'{RUN}/alice')
        self.bob = Lnd('bob', f'{RUN}/bob')

    def start(self):
        self.btc.start()
        # lnd waits for the activation height before it starts: mine one
        # block to an anyone-can-spend script first.
        desc = self.btc.rpc('getdescriptorinfo', 'raw(51)')['descriptor']
        self.btc.rpc('generatetodescriptor', 1, desc)
        self.alice.start()
        self.bob.start()
        self.mine_addr = self.alice.address()
        self.btc.mine(5, self.bob.address())
        self.btc.mine(110, self.mine_addr)
        self.sync()
        self.connect()

    def connect(self):
        try:
            self.alice.cli('connect', f'{self.bob.id}@127.0.0.1:{self.bob.port}')
        except RuntimeError as e:
            if 'already connected' not in str(e):
                raise
        wait_for(lambda: any(p['pub_key'] == self.bob.id
                             for p in self.alice.cli('listpeers')['peers']),
                 'peers connected')

    def mine(self, n=1):
        self.btc.mine(n, self.mine_addr)
        self.sync()

    def sync(self):
        h = self.btc.rpc('getblockcount')
        for n in (self.alice, self.bob):
            if n.proc is not None:
                wait_for(lambda n=n: n.cli('getinfo')['block_height'] >= h and
                         n.cli('getinfo')['synced_to_chain'],
                         f'{n.name} at {h}')

    def stop(self):
        for n in (self.bob, self.alice):
            n.stop()
        self.btc.stop()

    # --- helpers ---------------------------------------------------------
    def open_channel(self, amt=1_000_000, push=0):
        res = self.alice.cli('openchannel', f'--node_key={self.bob.id}',
                             f'--local_amt={amt}', f'--push_amt={push}',
                             '--channel_type=taproot', '--private',
                             '--remote_csv_delay=20')
        txid = res['funding_txid']
        wait_for(lambda: self.btc.rpc('getrawmempool').count(txid) or
                 txid in self.btc.rpc('getrawmempool'), 'funding tx in mempool')
        self.mine(3)
        chan = wait_for(lambda: next((c for c in self.alice.cli('listchannels')['channels']
                                      if c['channel_point'].startswith(txid) and c['active']), None),
                        'channel active')
        wait_for(lambda: any(c['channel_point'] == chan['channel_point'] and c['active']
                             for c in self.bob.cli('listchannels')['channels']),
                 'channel active at bob')
        # A first, small payment, retried until the link carries it, so
        # the scenario's own payments go through first time.
        keysend(self.alice, self.bob, 1000)
        return chan

    def tx(self, txid):
        return self.btc.rpc('getrawtransaction', txid, True)

    def spenders(self, txid, from_height):
        """Confirmed transactions from from_height on that spend txid."""
        found = []
        for h in range(from_height, self.btc.rpc('getblockcount') + 1):
            block = self.btc.rpc('getblock', self.btc.rpc('getblockhash', h), 2)
            for tx in block['tx']:
                if any(i.get('txid') == txid for i in tx['vin']):
                    found.append(tx)
        return found


def keypath_sig_ok(tx, idx=0):
    w = tx['vin'][idx]['txinwitness']
    return len(w) == 1 and len(w[0]) == 130 and w[0].endswith('21')


def show_channel_type(net, chan):
    check(chan.get('commitment_type') in ('SIMPLE_TAPROOT', 'TAPROOT'),
          f'commitment type {chan.get("commitment_type")}')
    check(chan.get('unified_sigs') is True,
          'channel carries option_unified_sigs')


def scenario_coop(net):
    chan = net.open_channel(push=100_000)
    show_channel_type(net, chan)
    for amt in (10_000, 20_000, 30_000):
        keysend(net.alice, net.bob, amt)
    keysend(net.bob, net.alice, 5000)
    txid, out = chan['channel_point'].split(':')
    res = net.alice.cli('closechannel', f'--funding_txid={txid}',
                        f'--output_index={out}')
    close_txid = res.get('closing_txid') or res.get('close_pending', {}).get('txid')
    wait_for(lambda: len(net.btc.rpc('getrawmempool')) > 0, 'close tx in mempool')
    height = net.btc.rpc('getblockcount') + 1
    net.mine(1)
    spent = net.spenders(txid, height)
    check(len(spent) == 1, 'cooperative close confirmed')
    check(keypath_sig_ok(spent[0]),
          'cooperative close witness is one 65-byte signature ending 0x21')


def hold_invoice(net, amt):
    preimage = os.urandom(32)
    phash = hashlib.sha256(preimage).hexdigest()
    inv = net.bob.cli('addholdinvoice', phash, f'--amt={amt}', '--expiry=3600',
                      '--cltv_expiry_delta=40')
    pay = subprocess.Popen(net.alice.cli_cmd('payinvoice', '--force',
                                             inv['payment_request']),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_for(lambda: any(c['pending_htlcs'] for c in net.bob.cli('listchannels')['channels']),
             'HTLC pending at bob')
    return preimage.hex(), phash, pay


def htlc_sigs(tx):
    w = tx['vin'][0]['txinwitness']
    return w[0], w[1]


def find_second_level(net, commit_txid, height, n_items):
    for tx in net.spenders(commit_txid, height):
        for i, vin in enumerate(tx['vin']):
            if vin.get('txid') == commit_txid and len(vin.get('txinwitness', [])) == n_items:
                return tx, i
    return None


def scenario_success(net):
    chan = net.open_channel()
    show_channel_type(net, chan)
    preimage, phash, pay = hold_invoice(net, 50_000)
    txid, out = chan['channel_point'].split(':')
    height = net.btc.rpc('getblockcount') + 1
    net.bob.cli('closechannel', '--force', f'--funding_txid={txid}',
                f'--output_index={out}')
    wait_for(lambda: len(net.btc.rpc('getrawmempool')) > 0, 'commitment in mempool')
    net.mine(1)
    commit = net.spenders(txid, height)
    check(len(commit) == 1, 'bob\'s commitment confirmed')
    check(keypath_sig_ok(commit[0]),
          'commitment witness is one 65-byte signature ending 0x21')
    commit_txid = commit[0]['txid']
    net.bob.cli('settleinvoice', preimage)
    found = wait_for(lambda: (net.mine(1) or True) and
                     find_second_level(net, commit_txid, height, 5),
                     'HTLC-success transaction confirmed', timeout=240, interval=1)
    tx, i = found
    w = tx['vin'][i]['txinwitness']
    check(len(w[0]) == 130 and w[0].endswith('a3'),
          'HTLC-success: alice\'s signature is 65 bytes ending 0xa3')
    check(len(w[1]) == 130 and w[1].endswith('21'),
          'HTLC-success: bob\'s own signature is 65 bytes ending 0x21')
    pay.wait(120)
    net.mine(30)
    wait_for(lambda: (net.mine(1) or True) and
             not net.bob.cli('pendingchannels')['waiting_close_channels'] and
             not net.bob.cli('pendingchannels')['pending_force_closing_channels'],
             'bob swept everything', timeout=300, interval=1)
    check(True, 'bob resolved the channel')


def scenario_timeout(net):
    chan = net.open_channel()
    show_channel_type(net, chan)
    preimage, phash, pay = hold_invoice(net, 60_000)
    txid, out = chan['channel_point'].split(':')
    height = net.btc.rpc('getblockcount') + 1
    net.alice.cli('closechannel', '--force', f'--funding_txid={txid}',
                  f'--output_index={out}')
    wait_for(lambda: len(net.btc.rpc('getrawmempool')) > 0, 'commitment in mempool')
    net.mine(1)
    commit = net.spenders(txid, height)
    check(len(commit) == 1, 'alice\'s commitment confirmed')
    check(keypath_sig_ok(commit[0]),
          'commitment witness is one 65-byte signature ending 0x21')
    commit_txid = commit[0]['txid']
    found = wait_for(lambda: (net.mine(2) or True) and
                     find_second_level(net, commit_txid, height, 4),
                     'HTLC-timeout transaction confirmed', timeout=300, interval=1)
    tx, i = found
    w = tx['vin'][i]['txinwitness']
    check(len(w[0]) == 130 and w[0].endswith('a3'),
          'HTLC-timeout: bob\'s signature is 65 bytes ending 0xa3')
    check(len(w[1]) == 130 and w[1].endswith('21'),
          'HTLC-timeout: alice\'s own signature is 65 bytes ending 0x21')
    net.bob.cli('cancelinvoice', phash)
    pay.wait(120)
    wait_for(lambda: (net.mine(1) or True) and
             not net.alice.cli('pendingchannels')['waiting_close_channels'] and
             not net.alice.cli('pendingchannels')['pending_force_closing_channels'],
             'alice swept everything', timeout=300, interval=1)
    check(True, 'alice resolved the channel')


def scenario_breach(net):
    chan = net.open_channel(push=200_000)
    show_channel_type(net, chan)
    # Bob's copy of this state, with about 200,000 sat on his side.
    net.bob.stop()
    old = net.bob.chandb() + '.old'
    shutil.copyfile(net.bob.chandb(), old)
    net.bob.start()
    net.connect()
    wait_for(lambda: any(c['channel_point'] == chan['channel_point'] and c['active']
                         for c in net.bob.cli('listchannels')['channels']),
             'channel active again')
    keysend(net.bob, net.alice, 150_000)
    # Alice goes away; bob comes back with the old state and closes.
    net.alice.stop()
    net.bob.stop()
    shutil.copyfile(old, net.bob.chandb())
    net.bob.start()
    txid, out = chan['channel_point'].split(':')
    height = net.btc.rpc('getblockcount') + 1
    net.bob.cli('closechannel', '--force', f'--funding_txid={txid}',
                f'--output_index={out}')
    wait_for(lambda: len(net.btc.rpc('getrawmempool')) > 0, 'revoked commitment in mempool')
    net.btc.mine(1, net.mine_addr)
    commit = net.spenders(txid, height)
    check(len(commit) == 1, 'bob\'s revoked commitment confirmed')
    check(keypath_sig_ok(commit[0]),
          'revoked commitment witness is one 65-byte signature ending 0x21')
    commit_txid = commit[0]['txid']
    net.alice.start()
    # Bob's output on his own commitment is the one his old state gave
    # him, about 201,000 sat (his push and the first payment); alice's is
    # the rest, less fees and anchors.
    outs = commit[0]['vout']
    bob_vout = next(v for v in outs if 150_000 < v['value'] * 1e8 < 250_000)
    bob_sat = int(round(bob_vout['value'] * 1e8))
    check(190_000 < bob_sat < 210_000, f'bob\'s revoked output holds {bob_sat} sat')

    def justice():
        net.mine(1)
        for tx in net.spenders(commit_txid, height):
            for vin in tx['vin']:
                if vin.get('txid') == commit_txid and vin.get('vout') == bob_vout['n']:
                    return tx
        return None
    jtx = wait_for(justice, 'justice transaction confirmed', timeout=300, interval=1)
    alice_txids = {t['tx_hash'] for t in net.alice.cli('listchaintxns')['transactions']}
    check(jtx['txid'] in alice_txids,
          'the revoked output was swept by alice\'s breach arbiter')
    swept = sum(int(round(v['value'] * 1e8)) for v in jtx['vout'])
    check(swept > bob_sat - 2000, f'alice took {swept} of bob\'s {bob_sat} sat, less the fee')
    wait_for(lambda: (net.mine(1) or True) and
             not net.alice.cli('pendingchannels')['waiting_close_channels'] and
             not net.alice.cli('pendingchannels')['pending_force_closing_channels'],
             'alice resolved the breach', timeout=300, interval=1)
    check(True, 'alice resolved the channel')


SCENARIOS = {'coop': scenario_coop, 'success': scenario_success,
             'timeout': scenario_timeout, 'breach': scenario_breach}


def main():
    names = sys.argv[1:] or list(SCENARIOS)
    net = Net()
    results = {}
    try:
        net.start()
        info = net.alice.cli('getinfo')
        print(f'chain height {info["block_height"]}, lnd {info["version"]}')
        for name in names:
            print(f'== {name}')
            try:
                if net.alice.proc is None:
                    net.alice.start()
                if net.bob.proc is None:
                    net.bob.start()
                net.connect()
                SCENARIOS[name](net)
                results[name] = 'PASS'
            except Exception as e:  # noqa: BLE001
                results[name] = f'FAIL: {e}'
                print(f'    FAIL: {e}')
    finally:
        net.stop()
    print()
    for name in names:
        print(f'{name:10} {results.get(name, "not run")}')
    sys.exit(0 if all(v == 'PASS' for v in results.values()) else 1)


if __name__ == '__main__':
    main()
