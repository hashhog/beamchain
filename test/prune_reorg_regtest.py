#!/usr/bin/env python3
"""A pruned node must still reorg across the 288-block keep window (regtest).

Runs one scenario against a real beamchain escript, or against bitcoind for
the reference behaviour (Core v31.1, -prune=1 -fastprune):

  1. start in manual prune mode (-prune=1), mine 1500 blocks
  2. localservices: NODE_NETWORK clear, NODE_NETWORK_LIMITED set
  3. pruneblockchain(1500) -> last pruned height P <= 1500 - 288
  4. getblock(P) fails "Block not available (pruned data)"; block P+1 and
     every block of the keep window are served; pruneheight == P + 1
  5. invalidateblock(block 1213): 288 blocks are disconnected, each needing
     its undo data; mine 5 blocks on the fork
  6. reconsiderblock(block 1213): the node reorgs back, disconnecting the 5
     fork blocks and reconnecting the 288 kept ones; tip == the original tip

Core prunes whole blk/rev files, so its P is the end of the last whole file
below 1212; beamchain prunes per block, so its P is exactly 1212. Both must
satisfy every check above. Stdlib only. The node is stopped with the `stop`
RPC; nothing is killed.

usage: prune_reorg_regtest.py --beam <escript> --workdir <dir>
       prune_reorg_regtest.py --core <bitcoind> --workdir <dir>
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
import urllib.error
import urllib.request

CHAIN = 1500
KEEP = 288
NODE_NETWORK = 0x1
NODE_NETWORK_LIMITED = 0x400
ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
# The fork pays elsewhere: re-mining to ADDR at the same mock height and
# time rebuilds the block just invalidated ("duplicate-invalid").
FORK_ADDR = "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t"


def free_port():
    while True:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        if port != 22000:
            return port


class Node:
    def __init__(self, port, cookie_path):
        self.port = port
        self.cookie_path = cookie_path

    def call(self, method, *params, timeout=300):
        with open(self.cookie_path) as f:
            auth = base64.b64encode(f.read().strip().encode()).decode()
        body = json.dumps({"jsonrpc": "1.0", "id": method,
                           "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:%d/" % self.port, data=body,
            headers={"Authorization": "Basic " + auth,
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            resp = json.loads(e.read())
        return resp.get("result"), resp.get("error")

    def ok(self, method, *params):
        res, err = self.call(method, *params)
        if err:
            raise AssertionError("%s%r -> error %r" % (method, params, err))
        return res


def start(args, work):
    rpc, p2p = free_port(), free_port()
    datadir = os.path.join(work, "node")
    os.makedirs(datadir)
    log = open(os.path.join(work, "node.log"), "w")
    if args.beam:
        env = dict(os.environ, BEAMCHAIN_PRUNE="1",
                   ERL_FLAGS="-beamchain metrics_port 0")
        cmd = [args.beam, "start", "--network=regtest",
               "--datadir=" + datadir, "--rpc-port=%d" % rpc,
               "--p2p-port=%d" % p2p, "--nodnsseed", "--nofixedseeds",
               "--nodiscover", "--connect=127.0.0.1:1", "--printtoconsole"]
    else:
        env = dict(os.environ)
        cmd = [args.core, "-regtest", "-datadir=" + datadir,
               "-rpcport=%d" % rpc, "-port=%d" % p2p, "-listen=0",
               "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-prune=1",
               "-fastprune", "-printtoconsole=0"]
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env)
    node = Node(rpc, os.path.join(datadir, "regtest", ".cookie"))
    deadline = time.time() + 180
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit("node exited during startup, see node.log")
        try:
            if os.path.exists(node.cookie_path):
                res, err = node.call("getblockcount", timeout=5)
                if err is None:
                    return proc, node
        except (OSError, ValueError):
            pass
        time.sleep(0.5)
    raise SystemExit("node did not answer RPC within 180 s")


def stop(proc, node):
    try:
        node.call("stop", timeout=30)
    except (OSError, ValueError):
        pass
    try:
        proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        print("WARN: node pid %d did not exit after stop" % proc.pid)


def check(cond, what):
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        raise AssertionError(what)


def scenario(node):
    for _ in range(CHAIN // 100):
        node.ok("generatetoaddress", 100, ADDR)
    check(node.ok("getblockcount") == CHAIN, "mined %d blocks" % CHAIN)
    tip = node.ok("getbestblockhash")
    hashes = {h: node.ok("getblockhash", h) for h in range(1, CHAIN + 1)}

    services = int(node.ok("getnetworkinfo")["localservices"], 16)
    check(services & NODE_NETWORK == 0,
          "localservices %#x has no NODE_NETWORK" % services)
    check(services & NODE_NETWORK_LIMITED != 0,
          "localservices %#x has NODE_NETWORK_LIMITED" % services)
    check(node.ok("getblockchaininfo")["pruned"] is True, "pruned is true")

    last = node.ok("pruneblockchain", CHAIN)
    print("pruneblockchain(%d) -> %r" % (CHAIN, last))
    check(isinstance(last, int) and 1 <= last <= CHAIN - KEEP,
          "last pruned height %r within 1..%d" % (last, CHAIN - KEEP))
    res, err = node.call("getblock", hashes[last])
    check(res is None and err is not None and err.get("code") == -1
          and "pruned data" in err.get("message", ""),
          "getblock(%d) is pruned: %r" % (last, err))
    check(node.ok("getblockchaininfo")["pruneheight"] == last + 1,
          "pruneheight == %d" % (last + 1))
    window = range(CHAIN - KEEP + 1, CHAIN + 1)
    served = [h for h in range(last + 1, CHAIN + 1)
              if node.call("getblock", hashes[h])[1] is None]
    check(len(served) == CHAIN - last,
          "all %d blocks above the prune height served" % (CHAIN - last))
    check(all(h in served for h in window), "keep window fully served")

    fork = CHAIN - KEEP + 1
    node.ok("invalidateblock", hashes[fork])
    check(node.ok("getblockcount") == fork - 1,
          "invalidateblock disconnected %d blocks (tip %d)" % (KEEP, fork - 1))
    node.ok("generatetoaddress", 5, FORK_ADDR)
    check(node.ok("getblockcount") == fork + 4, "mined 5 fork blocks")
    check(node.ok("getbestblockhash") != tip, "fork tip differs")
    node.ok("reconsiderblock", hashes[fork])
    deadline = time.time() + 120
    while node.ok("getbestblockhash") != tip and time.time() < deadline:
        time.sleep(0.5)
    check(node.ok("getbestblockhash") == tip and
          node.ok("getblockcount") == CHAIN,
          "reconsiderblock reorged back across %d blocks to the original tip"
          % KEEP)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--beam")
    g.add_argument("--core")
    ap.add_argument("--workdir", required=True)
    args = ap.parse_args()
    if os.path.exists(args.workdir):
        shutil.rmtree(args.workdir)
    os.makedirs(args.workdir)
    proc, node = start(args, args.workdir)
    try:
        scenario(node)
        print("RESULT: PASS")
        rc = 0
    except AssertionError as e:
        print("RESULT: FAIL (%s)" % e)
        rc = 1
    finally:
        stop(proc, node)
    sys.exit(rc)


if __name__ == "__main__":
    main()
