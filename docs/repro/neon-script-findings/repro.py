#!/usr/bin/env python3
"""Replay Neon-audit finding 1 (cut-off PUSHDATA length in an unexecuted
branch) against a real Bitcoin Core v31.1 regtest node and a beamchain
regtest node, and print each node's verdict.

Each case runs on fresh datadirs for both nodes:
  1. 101 blocks; block 1's coinbase pays 50 BTC to the case's scriptPubKey
     (bare script, or P2WSH of the witness script).
  2. block 102 spends that coinbase (empty scriptSig; for P2WSH the witness
     is the witness script alone).
The scripts are OP_1 OP_0 OP_IF <cut-off PUSHDATA> OP_ENDIF: Core's GetOp
fails on the cut-off length field (BAD_OPCODE) even though the branch is
not executed, so block 102 is invalid. The control has a complete push in
the unexecuted branch and is valid on both nodes.

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

    def p2wsh(ws):
        return CScript([OP_0, hashlib.sha256(ws).digest()])

    # (name, funding scriptPubKey, witness stack or None)
    cases = []
    for label, ws in (("PUSHDATA2 + 1 length byte", bytes.fromhex("5100634d68")),
                      ("PUSHDATA4 + 1 length byte", bytes.fromhex("5100634e68")),
                      ("PUSHDATA1, no length byte", bytes.fromhex("5100634c"))):
        cases.append((f"bare {ws.hex()} ({label})", CScript(ws), None))
        cases.append((f"P2WSH {ws.hex()} ({label})", p2wsh(ws), [ws]))
    ctrl = bytes.fromhex("5100634d0100aa68")
    cases.append((f"control bare {ctrl.hex()} (complete PUSHDATA2)", CScript(ctrl), None))
    cases.append((f"control P2WSH {ctrl.hex()} (complete PUSHDATA2)", p2wsh(ctrl), [ctrl]))

    split = False
    for i, (name, spk, wit) in enumerate(cases):
        wd = os.path.join(a.workdir, f"case{i}")
        shutil.rmtree(wd, ignore_errors=True)
        core_p, core = start_core(a.bitcoind, os.path.join(wd, "core"))
        bc_p, bc = start_beamchain(a.beamchain, os.path.join(wd, "beamchain"))
        try:
            genesis = core.call("getbestblockhash")
            assert bc.call("getbestblockhash") == genesis, "genesis differs"
            tip = int(genesis, 16)
            t0 = int(time.time()) - 2000
            first_cb = None
            for h in range(1, 102):
                cb = create_coinbase(h, script_pubkey=spk if h == 1 else CScript([OP_TRUE]))
                blk = create_block(tip, cb, t0 + h)
                blk.solve()
                hx = blk.serialize().hex()
                rc, rb = core.call("submitblock", hx), bc.call("submitblock", hx)
                if rc is not None or rb is not None:
                    raise RuntimeError(f"setup block {h}: core={rc} beamchain={rb}")
                if h == 1:
                    first_cb = cb
                tip = blk.hash_int
            tx = CTransaction()
            tx.version = 2
            tx.vin = [CTxIn(COutPoint(first_cb.txid_int, 0), b"", 0xffffffff)]
            tx.vout = [CTxOut(49 * COIN, CScript([OP_TRUE]))]
            if wit is not None:
                tx.wit.vtxinwit = [CTxInWitness()]
                tx.wit.vtxinwit[0].scriptWitness.stack = wit
            blk = create_block(tip, create_coinbase(102, fees=1 * COIN), t0 + 102, txlist=[tx])
            if wit is not None:
                from test_framework.blocktools import add_witness_commitment
                add_witness_commitment(blk)
            blk.solve()
            hx = blk.serialize().hex()
            rc, rb = core.call("submitblock", hx), bc.call("submitblock", hx)
            tc, tb = core.call("getblockcount"), bc.call("getblockcount")
            agree = (rc is None) == (rb is None) and tc == tb
            split |= not agree
            print(f"{name}: core submitblock={rc!r} height={tc} | beamchain submitblock={rb!r} height={tb} | "
                  f"{'AGREE' if agree else 'SPLIT'}")
        finally:
            stop(bc_p, bc)
            stop(core_p, core)
    print("RESULT blocks:", "SPLIT" if split else "AGREE")
    return 1 if split else 0


if __name__ == "__main__":
    sys.exit(main())
