#!/usr/bin/env python3
"""Replay Neon-audit finding 7 (OP_RESERVED is push-only) against a real
Bitcoin Core v31.1 regtest node and a beamchain regtest node.

101 blocks; block 1's coinbase pays P2WSH(OP_TRUE). Then, through
testmempoolaccept and sendrawtransaction, a spend of it whose second output
is OP_RETURN OP_RESERVED (6a 50): Core's Solver classifies that NULL_DATA
(IsPushOnly counts every opcode <= OP_16), so the tx is standard. Then
decodescript 6a50 (Core: type nulldata). Controls: the same spend with an
OP_RETURN OP_NOP output (6a 61, nonstandard on both) and with OP_RETURN
OP_1 (6a 51, standard on both).

Usage:
  python3 repro.py --bitcoind <bitcoind 31.1> --beamchain <beamchain escript> \
      --core-src <bitcoin source tree, for test/functional/test_framework> \
      --workdir <scratch dir> [--label <text>]
"""
import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Rpc:
    def __init__(self, port, user=None, pw=None, cookie=None):
        self.url = f"http://127.0.0.1:{port}/"
        self.user, self.pw, self.cookie = user, pw, cookie

    def auth(self):
        if self.cookie:
            with open(self.cookie) as f:
                cred = f.read().strip()
        else:
            cred = f"{self.user}:{self.pw}"
        return base64.b64encode(cred.encode()).decode()

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, body, {"Authorization": "Basic " + self.auth(),
                                                      "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            out = json.loads(e.read())
        if out.get("error"):
            return {"error": out["error"]}
        return out["result"]


def wait_rpc(rpc, proc, name, timeout=180):
    t = time.time()
    while time.time() - t < timeout:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited rc={proc.returncode}")
        try:
            if isinstance(rpc.call("getblockcount"), int):
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"{name} RPC not up after {timeout}s")


def start_core(bitcoind, datadir):
    os.makedirs(datadir)
    rpcport, p2p = free_port(), free_port()
    proc = subprocess.Popen([bitcoind, "-regtest", f"-datadir={datadir}", f"-rpcport={rpcport}", f"-port={p2p}",
                             "-rpcuser=t", "-rpcpassword=t", "-listen=0", "-connect=0", "-dnsseed=0",
                             "-fixedseeds=0", "-printtoconsole=0", "-server=1"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rpc = Rpc(rpcport, "t", "t")
    wait_rpc(rpc, proc, "bitcoind")
    return proc, rpc


def start_beamchain(binary, datadir):
    os.makedirs(datadir)
    rpcport, p2p, rest = free_port(), free_port(), free_port()
    env = dict(os.environ, BEAMCHAIN_REST_PORT=str(rest), ERL_FLAGS="-beamchain metrics_port 0")
    log = open(os.path.join(datadir, "stdout.log"), "w")
    proc = subprocess.Popen([binary, "start", "--network=regtest", f"--datadir={datadir}",
                             f"--rpc-port={rpcport}", f"--p2p-port={p2p}", "--nodnsseed", "--nofixedseeds",
                             "--nodiscover", "--connect=127.0.0.1:1", "--printtoconsole"],
                            stdout=log, stderr=subprocess.STDOUT, env=env)
    cookie = os.path.join(datadir, "regtest", ".cookie")
    t = time.time()
    while not os.path.exists(cookie):
        if proc.poll() is not None or time.time() - t > 180:
            raise RuntimeError("beamchain did not write its cookie")
        time.sleep(0.5)
    rpc = Rpc(rpcport, cookie=cookie)
    wait_rpc(rpc, proc, "beamchain")
    return proc, rpc


def stop(proc, rpc):
    try:
        rpc.call("stop")
    except Exception:
        pass
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=30)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--beamchain", required=True)
    ap.add_argument("--core-src", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--label", default="beamchain")
    a = ap.parse_args()
    sys.path.insert(0, os.path.join(a.core_src, "test", "functional"))
    from test_framework.blocktools import create_block, create_coinbase
    from test_framework.messages import COIN, CTransaction, CTxIn, CTxInWitness, CTxOut, COutPoint
    from test_framework.script import CScript, OP_0, OP_TRUE
    import hashlib

    print(f"bitcoind: {subprocess.run([a.bitcoind, '-version'], capture_output=True, text=True).stdout.splitlines()[0]}")
    print(f"beamchain: {a.label}")
    ws = bytes(CScript([OP_TRUE]))
    p2wsh = CScript([OP_0, hashlib.sha256(ws).digest()])

    wd = a.workdir
    shutil.rmtree(wd, ignore_errors=True)
    core_p, core = start_core(a.bitcoind, os.path.join(wd, "core"))
    bc_p, bc = start_beamchain(a.beamchain, os.path.join(wd, "beamchain"))
    split = False
    try:
        tip = int(core.call("getbestblockhash"), 16)
        assert bc.call("getbestblockhash") == core.call("getbestblockhash"), "genesis differs"
        t0 = int(time.time()) - 2000
        cbs = []
        for h in range(1, 104):
            cb = create_coinbase(h, script_pubkey=p2wsh if h <= 3 else CScript([OP_TRUE]))
            blk = create_block(tip, cb, t0 + h)
            blk.solve()
            hx = blk.serialize().hex()
            rc, rb = core.call("submitblock", hx), bc.call("submitblock", hx)
            if rc is not None or rb is not None:
                raise RuntimeError(f"setup block {h}: core={rc} beamchain={rb}")
            cbs.append(cb)
            tip = blk.hash_int
        fmt = lambda r: ("accept" if isinstance(r, str) else "reject: " + str(r["error"].get("message")))
        for i, (name, extra) in enumerate((("OP_RETURN OP_RESERVED (6a50)", "6a50"),
                                           ("control OP_RETURN OP_NOP (6a61)", "6a61"),
                                           ("control OP_RETURN OP_1 (6a51)", "6a51"))):
            tx = CTransaction()
            tx.version = 2
            tx.vin = [CTxIn(COutPoint(cbs[i].txid_int, 0), b"", 0xfffffffd)]
            tx.vout = [CTxOut(50 * COIN - 20000, p2wsh), CTxOut(0, CScript(bytes.fromhex(extra)))]
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [ws]
            hx = tx.serialize().hex()
            tc = core.call("testmempoolaccept", [hx])[0]
            tb = bc.call("testmempoolaccept", [hx])
            tb = tb[0] if isinstance(tb, list) else tb
            rc, rb = core.call("sendrawtransaction", hx), bc.call("sendrawtransaction", hx)
            same = isinstance(rc, str) == isinstance(rb, str)
            split |= not same
            print(f"{name}: testmempoolaccept core allowed={tc.get('allowed')} reason={tc.get('reject-reason')!r} | "
                  f"beamchain allowed={tb.get('allowed') if isinstance(tb, dict) else tb} "
                  f"reason={tb.get('reject-reason') if isinstance(tb, dict) else None!r}")
            print(f"{name}: sendrawtransaction core={fmt(rc)} | beamchain={fmt(rb)} | {'AGREE' if same else 'SPLIT'}")
        for hexs in ("6a50", "6a61"):
            dc, db = core.call("decodescript", hexs), bc.call("decodescript", hexs)
            tc_, tb_ = dc.get("type"), (db.get("type") if isinstance(db, dict) else db)
            split |= tc_ != tb_
            print(f"decodescript {hexs}: core type={tc_} | beamchain type={tb_} | {'AGREE' if tc_ == tb_ else 'SPLIT'}")
    finally:
        stop(bc_p, bc)
        stop(core_p, core)
    print("RESULT mempool/decodescript:", "SPLIT" if split else "AGREE")
    return 1 if split else 0


if __name__ == "__main__":
    sys.exit(main())
