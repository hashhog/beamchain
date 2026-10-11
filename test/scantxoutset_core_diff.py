#!/usr/bin/env python3
"""scantxoutset: Bitcoin Core v31.1 vs beamchain on offline regtest.

Mines outputs of every script type on bitcoind (wallet sends and
generatetodescriptor coinbases), submits the same blocks to beamchain,
then runs scantxoutset with each descriptor kind on both nodes and
compares every field, JSON key order and number text included. Error
cases compare code and message. Exits 1 on any mismatch.

Env: BITCOIN_DIR (bin/bitcoind, bin/bitcoin-cli), BEAM (escript),
SCAN_WORK, SCAN_CORE_RPC, SCAN_BEAM_RPC, SCAN_BEAM_P2P.
"""
import base64, json, os, shutil, signal, subprocess, sys, time
import urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BITCOIN_DIR = os.environ.get("BITCOIN_DIR", "/tmp/bitcoin-core/bitcoin-31.1")
BITCOIND = os.path.join(BITCOIN_DIR, "bin", "bitcoind")
BEAM = os.environ.get("BEAM", os.path.join(ROOT, "_build/default/bin/beamchain"))
WORK = os.environ.get("SCAN_WORK", "/tmp/scantxoutset-diff")
CORE_RPC = os.environ.get("SCAN_CORE_RPC", "18543")
BEAM_RPC = os.environ.get("SCAN_BEAM_RPC", "18545")
BEAM_P2P = os.environ.get("SCAN_BEAM_P2P", "18546")
CORE_DIR = os.path.join(WORK, "core")
BEAM_DIR = os.path.join(WORK, "beam")

G = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
G_C = "02" + G
G_U = ("04" + G + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

rows = []        # (tag, field, core, beam, ok)
procs = {}


class Num(str):
    pass


def loads(raw):
    return json.loads(raw, object_pairs_hook=lambda kv: ("OBJ", kv),
                      parse_float=Num, parse_int=lambda s: int(s))


def to_py(v):
    if isinstance(v, tuple) and v and v[0] == "OBJ":
        return {k: to_py(x) for k, x in v[1]}
    if isinstance(v, list):
        return [to_py(x) for x in v]
    return v


def rpc(port, auth, method, params=None, timeout=300, path="/"):
    body = json.dumps({"jsonrpc": "1.0", "id": "d", "method": method,
                       "params": params or []}).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:%s%s" % (port, path), data=body,
        headers={"Authorization": "Basic " + auth,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
    try:
        top = to_py(loads(raw))
    except json.JSONDecodeError:
        return {"_error": {"code": "nonjson", "message": raw[:300]}}, None
    if top.get("error"):
        return {"_error": {"code": top["error"].get("code"),
                           "message": top["error"].get("message")}}, None
    # keep the ordered form of "result" for key-order checks
    ordered = None
    t = loads(raw)
    for k, v in t[1]:
        if k == "result":
            ordered = v
    return top.get("result"), ordered


def cookie(path):
    end = time.time() + 120
    while time.time() < end:
        if os.path.isfile(path):
            raw = open(path, "rb").read().strip()
            if raw:
                return base64.b64encode(raw).decode()
        time.sleep(0.2)
    raise SystemExit("cookie missing: %s" % path)


def key_order(o):
    if isinstance(o, tuple) and o and o[0] == "OBJ":
        return [(k, key_order(v)) for k, v in o[1]]
    if isinstance(o, list):
        return [key_order(x) for x in o]
    return None


def rec(tag, field, c, b):
    ok = c == b
    rows.append((tag, field, c, b, ok))
    if not ok:
        print("  MISMATCH %s.%s\n    core=%s\n    beam=%s" % (tag, field, c, b))
    return ok


def is_err(v):
    return isinstance(v, dict) and "_error" in v


def stop_all():
    for name, p in procs.items():
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(30)
            except subprocess.TimeoutExpired:
                p.kill()


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(CORE_DIR)
    os.makedirs(BEAM_DIR)
    print(subprocess.run([BITCOIND, "-version"], capture_output=True,
                         text=True).stdout.splitlines()[0])
    procs["core"] = subprocess.Popen(
        [BITCOIND, "-regtest", "-datadir=" + CORE_DIR, "-listen=0",
         "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-server=1",
         "-fallbackfee=0.0002", "-rpcbind=127.0.0.1",
         "-rpcallowip=127.0.0.1", "-rpcport=" + CORE_RPC],
        stdout=open(os.path.join(WORK, "core.out"), "w"),
        stderr=subprocess.STDOUT)
    procs["beam"] = subprocess.Popen(
        [BEAM, "start", "--network=regtest", "--datadir=" + BEAM_DIR,
         "--rpc-port=" + BEAM_RPC, "--p2p-port=" + BEAM_P2P,
         "--nodnsseed", "--nofixedseeds", "--connect=127.0.0.1:1",
         "--printtoconsole"],
        stdout=open(os.path.join(WORK, "beam.out"), "w"),
        stderr=subprocess.STDOUT)
    ca = cookie(os.path.join(CORE_DIR, "regtest", ".cookie"))
    ba = cookie(os.path.join(BEAM_DIR, "regtest", ".cookie"))

    def core(m, p=None, w=None, t=300):
        for _ in range(100):
            r, _o = rpc(CORE_RPC, ca, m, p, t,
                        "/wallet/%s" % w if w else "/")
            if is_err(r) and r["_error"]["code"] == -28:
                time.sleep(0.2)
                continue
            if is_err(r):
                raise SystemExit("core %s %s: %s" % (m, p, r))
            return r
        raise SystemExit("core warmup")

    def beam_ok(m, p=None):
        for _ in range(300):
            r, _o = rpc(BEAM_RPC, ba, m, p)
            if is_err(r) and r["_error"]["code"] in (-28, "nonjson"):
                time.sleep(0.2)
                continue
            return r
        raise SystemExit("beam warmup")

    core("createwallet", ["fund"])
    core("createwallet", ["keys"])
    fund = core("getnewaddress", ["", "bech32"], "fund")
    core("generatetoaddress", [110, fund], "fund")

    # wallet keys for hex-key and xpub descriptors
    descs = core("listdescriptors", [False], "keys")["descriptors"]

    def wallet_desc(prefix, internal=False):
        for d in descs:
            s = d["desc"]
            if s.startswith(prefix) and d.get("internal", False) == internal:
                return s.split("#")[0]
        raise SystemExit("no wallet descriptor %s" % prefix)

    xp_wpkh = wallet_desc("wpkh(")        # wpkh([fp/84h/1h/0h]tpub/0/*)
    xp_tr = wallet_desc("tr(")
    xp_pkh = wallet_desc("pkh(")
    xp_shwpkh = wallet_desc("sh(wpkh(")
    inner = xp_wpkh[len("wpkh("):-1]       # [fp/84h/1h/0h]tpub.../0/*
    tpub_bare = inner.split("]", 1)[1]    # tpub.../0/*
    tpub_root = tpub_bare.rsplit("/", 2)[0]

    def pub_of(kind):
        a = core("getnewaddress", ["", kind], "keys")
        return a, core("getaddressinfo", [a], "keys")

    a_w, i_w = pub_of("bech32")
    a_l, i_l = pub_of("legacy")
    a_s, i_s = pub_of("p2sh-segwit")
    a_t, i_t = pub_of("bech32m")
    a_c, i_c = pub_of("bech32")
    k_w, k_l, k_s, k_c = (i_w["pubkey"], i_l["pubkey"], i_s["pubkey"],
                          i_c["pubkey"])
    a_m1, i_m1 = pub_of("bech32")
    a_m2, i_m2 = pub_of("bech32")
    k_m1, k_m2 = i_m1["pubkey"], i_m2["pubkey"]
    tr_out = i_t["scriptPubKey"][4:]

    def addr_of(desc):
        d = core("getdescriptorinfo", [desc])["descriptor"]
        return core("deriveaddresses", [d])[0]

    def chk(desc):
        return core("getdescriptorinfo", [desc])["descriptor"]

    # wallet sends (coinbase=false)
    sends = {
        a_w: "1.1", a_l: "1.2", a_s: "1.3", a_t: "1.4",
        addr_of("pkh(%s)" % k_c): "0.5",
        addr_of("wpkh(%s)" % k_c): "0.6",
        addr_of("sh(wpkh(%s))" % k_c): "0.7",
        addr_of("sh(multi(1,%s,%s))" % (k_m1, k_m2)): "0.8",
        addr_of("wsh(multi(1,%s,%s))" % (k_m1, k_m2)): "0.9",
        addr_of("sh(sortedmulti(1,%s,%s))" % (k_m2, k_m1)): "0.11",
        addr_of("wsh(sortedmulti(1,%s,%s))" % (k_m2, k_m1)): "0.12",
        addr_of("tr(%s)" % G): "0.13",
        addr_of("tr(%s,{pk(%s),pk(%s)})" % (G, k_m1[2:], k_m2[2:])): "0.14",
        addr_of("tr(%s,pk(%s))" % (k_m1[2:], k_m2[2:])): "0.15",
        addr_of("rawtr(%s)" % k_m2[2:]): "0.16",
        addr_of("pkh(%s)" % G_U): "0.17",
        addr_of("sh(pkh(%s))" % G_U): "0.18",
        addr_of("wsh(pkh(%s))" % k_m1): "0.19",
        addr_of("pkh([deadbeef/1h/2]%s)" % k_m1): "0.21",
        addr_of("tr(%s,{pk(%s),pk(%s)})" % (G, k_m2[2:], k_m1[2:])): "0.22",
        addr_of("tr(%s,{{pk(%s),pk(%s)},pk(%s)})" % (G, k_m2[2:], k_m1[2:], k_c[2:])): "0.23",
        addr_of("tr(%s,{pk(%s),{pk(%s),pk(%s)}})" % (G, k_c[2:], k_m2[2:], k_m1[2:])): "0.24",
        addr_of("tr(%s,multi_a(1,%s,%s))" % (G, k_m1[2:], k_m2[2:])): "0.25",
        addr_of("tr(%s,sortedmulti_a(1,%s,%s))" % (G, k_m2[2:], k_m1[2:])): "0.26",
        addr_of("wsh(and_v(v:pk(%s),after(2)))" % k_m1): "0.27",
        addr_of("tr(%s,and_v(v:pk(%s),older(5)))" % (G, k_m1[2:])): "0.28",
        addr_of("wsh(pk(%s))" % k_m2): "0.29",
        addr_of("sh(wsh(multi(1,%s,%s)))" % (k_m1, k_m2)): "0.31",
    }
    for i in (0, 1, 7, 999, 1000, 1001):
        d = "wpkh(%s)" % inner.replace("*", str(i))
        sends[addr_of(d)] = "0.0%d" % (i % 9 + 1)
    for i in (0, 5):
        sends[addr_of("tr(%s)" % xp_tr[3:-1].replace("*", str(i)))] = "0.031"
        sends[addr_of("pkh(%s)" % xp_pkh[4:-1].replace("*", str(i)))] = "0.032"
        sends[addr_of("sh(wpkh(%s))" % xp_shwpkh[8:-2].replace("*", str(i)))] = "0.033"
    sends[addr_of("wpkh(%s/0/3)" % tpub_root)] = "0.034"
    core("sendmany", ["", sends], "fund")
    core("sendtoaddress", [a_w, "0.4"], "fund")   # second coin same script
    core("generatetoaddress", [1, fund], "fund")

    # coinbases (coinbase=true) to scripts a wallet send cannot reach
    for d in ("pk(%s)" % k_c, "pk(%s)" % G_U, "raw(51)", "raw(6a0102)",
              "pkh(%s)" % k_c, "combo(%s)" % G_C, "raw(%s)" % ("21" + G_C + "ac"),
              "sh(multi(1,%s))" % G_U, "multi(1,%s,%s)" % (k_m1, k_m2)):
        core("generatetodescriptor", [1, chk(d)])
    core("generatetoaddress", [3, fund], "fund")

    tip = core("getblockcount")
    for h in range(1, tip + 1):
        hx = core("getblock", [core("getblockhash", [h]), 0])
        r = beam_ok("submitblock", [hx])
        if r is not None:
            raise SystemExit("submitblock %d -> %s" % (h, r))
    rec("tip", "height", tip, beam_ok("getblockcount"))
    rec("tip", "bestblock", core("getbestblockhash"),
        beam_ok("getbestblockhash"))

    def nochk(d):
        return d.split("#")[0]

    cases = [
        ("addr-wpkh", ["start", [chk("addr(%s)" % a_w)]]),
        ("addr-wpkh-nochk", ["start", ["addr(%s)" % a_w]]),
        ("addr-pkh", ["start", [chk("addr(%s)" % a_l)]]),
        ("addr-p2sh", ["start", [chk("addr(%s)" % a_s)]]),
        ("addr-tr", ["start", [chk("addr(%s)" % a_t)]]),
        ("raw-pkh", ["start", [chk("raw(%s)" % i_l["scriptPubKey"])]]),
        ("raw-51", ["start", ["raw(51)"]]),
        ("raw-opreturn", ["start", ["raw(6a0102)"]]),
        ("raw-p2pk", ["start", ["raw(21%sac)" % G_C]]),
        ("pk", ["start", [chk("pk(%s)" % k_c)]]),
        ("pk-uncomp", ["start", ["pk(%s)" % G_U]]),
        ("pkh", ["start", [chk("pkh(%s)" % k_c)]]),
        ("pkh-legacykey", ["start", ["pkh(%s)" % k_l]]),
        ("pkh-uncomp", ["start", ["pkh(%s)" % G_U]]),
        ("pkh-origin", ["start", ["pkh([deadbeef/1h/2]%s)" % k_m1]]),
        ("wpkh", ["start", [chk("wpkh(%s)" % k_w)]]),
        ("wpkh-nochk", ["start", ["wpkh(%s)" % k_c]]),
        ("sh-wpkh", ["start", [chk("sh(wpkh(%s))" % k_s)]]),
        ("sh-wpkh-c", ["start", ["sh(wpkh(%s))" % k_c]]),
        ("combo", ["start", [chk("combo(%s)" % k_c)]]),
        ("combo-G", ["start", ["combo(%s)" % G_C]]),
        ("combo-uncomp", ["start", ["combo(%s)" % G_U]]),
        ("sh-multi", ["start", ["sh(multi(1,%s,%s))" % (k_m1, k_m2)]]),
        ("wsh-multi", ["start", ["wsh(multi(1,%s,%s))" % (k_m1, k_m2)]]),
        ("sh-sortedmulti", ["start", ["sh(sortedmulti(1,%s,%s))" % (k_m2, k_m1)]]),
        ("wsh-sortedmulti", ["start", ["wsh(sortedmulti(1,%s,%s))" % (k_m2, k_m1)]]),
        ("bare-multi", ["start", ["multi(1,%s,%s)" % (k_m1, k_m2)]]),
        ("sh-multi-uncomp", ["start", ["sh(multi(1,%s))" % G_U]]),
        ("sh-pkh-uncomp", ["start", ["sh(pkh(%s))" % G_U]]),
        ("wsh-pkh", ["start", ["wsh(pkh(%s))" % k_m1]]),
        ("tr-G", ["start", [chk("tr(%s)" % G)]]),
        ("tr-ckey-nomatch", ["start", ["tr(%s)" % k_c[2:]]]),
        ("tr-tree", ["start", ["tr(%s,{pk(%s),pk(%s)})" % (G, k_m1[2:], k_m2[2:])]]),
        ("tr-leaf", ["start", ["tr(%s,pk(%s))" % (k_m1[2:], k_m2[2:])]]),
        ("tr-tree-rev", ["start", ["tr(%s,{pk(%s),pk(%s)})" % (G, k_m2[2:], k_m1[2:])]]),
        ("tr-tree-left", ["start", ["tr(%s,{{pk(%s),pk(%s)},pk(%s)})" % (G, k_m2[2:], k_m1[2:], k_c[2:])]]),
        ("tr-tree-right", ["start", ["tr(%s,{pk(%s),{pk(%s),pk(%s)}})" % (G, k_c[2:], k_m2[2:], k_m1[2:])]]),
        ("tr-multi_a", ["start", ["tr(%s,multi_a(1,%s,%s))" % (G, k_m1[2:], k_m2[2:])]]),
        ("tr-sortedmulti_a", ["start", ["tr(%s,sortedmulti_a(1,%s,%s))" % (G, k_m2[2:], k_m1[2:])]]),
        ("wsh-miniscript", ["start", ["wsh(and_v(v:pk(%s),after(2)))" % k_m1]]),
        ("tr-miniscript", ["start", ["tr(%s,and_v(v:pk(%s),older(5)))" % (G, k_m1[2:])]]),
        ("wsh-pk", ["start", ["wsh(pk(%s))" % k_m2]]),
        ("sh-wsh-multi", ["start", ["sh(wsh(multi(1,%s,%s)))" % (k_m1, k_m2)]]),
        ("addr-of-wsh-miniscript", ["start", ["addr(%s)" % addr_of("wsh(and_v(v:pk(%s),after(2)))" % k_m1)]]),
        ("rawtr", ["start", [chk("rawtr(%s)" % tr_out)]]),
        ("rawtr-key", ["start", ["rawtr(%s)" % k_m2[2:]]]),
        ("xpub-wpkh-default", ["start", [xp_wpkh]]),
        ("xpub-wpkh-chk", ["start", [chk(xp_wpkh)]]),
        ("xpub-wpkh-r1001", ["start", [{"desc": xp_wpkh, "range": 1001}]]),
        ("xpub-wpkh-r5", ["start", [{"desc": xp_wpkh, "range": 5}]]),
        ("xpub-wpkh-r[1,7]", ["start", [{"desc": xp_wpkh, "range": [1, 7]}]]),
        ("xpub-wpkh-noorigin", ["start", [{"desc": "wpkh(%s)" % tpub_bare, "range": 10}]]),
        ("xpub-fixed", ["start", ["wpkh(%s/0/3)" % tpub_root]]),
        ("xpub-tr", ["start", [{"desc": xp_tr, "range": 6}]]),
        ("xpub-pkh", ["start", [{"desc": xp_pkh, "range": 6}]]),
        ("xpub-sh-wpkh", ["start", [{"desc": xp_shwpkh, "range": 6}]]),
        ("xpub-combo", ["start", [{"desc": "combo(%s)" % tpub_bare, "range": 2}]]),
        ("multi-obj", ["start", ["addr(%s)" % a_w, "wpkh(%s)" % k_w,
                                 "pkh(%s)" % k_c, {"desc": "raw(51)"}]]),
        ("dup-first-wins", ["start", ["wpkh(%s)" % k_c, "combo(%s)" % k_c]]),
        ("dup-first-wins2", ["start", ["combo(%s)" % k_c, "wpkh(%s)" % k_c]]),
        ("empty", ["start", []]),
        ("nomatch", ["start", ["raw(52)"]]),
        ("range-ignored", ["start", [{"desc": "wpkh(%s)" % k_w, "range": 50}]]),
        # errors
        ("err-badchk", ["start", [nochk(chk("wpkh(%s)" % k_w)) + "#qqqqqqqq"]]),
        ("err-chk7", ["start", ["wpkh(%s)#abcdefg" % k_w]]),
        ("err-multihash", ["start", ["wpkh(%s)#a#b" % k_w]]),
        ("err-badchar", ["start", ["wpkh(\u00e9)"]]),
        ("err-unknownfn", ["start", ["foo(%s)" % k_w]]),
        ("err-badpub", ["start", ["wpkh(02deadbeef)"]]),
        ("err-uncomp-wpkh", ["start", ["wpkh(%s)" % G_U]]),
        ("err-badaddr", ["start", ["addr(notanaddress)"]]),
        ("err-mainnet-addr", ["start", ["addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)"]]),
        ("err-bare-addr", ["start", [a_w]]),
        ("err-bare-hex", ["start", [i_l["scriptPubKey"]]]),
        ("err-raw-badhex", ["start", ["raw(zz)"]]),
        ("err-raw-empty", ["start", ["raw()"]]),
        ("err-tr-xonly-bad", ["start", ["rawtr(%s)" % ("00" * 32)]]),
        ("err-hardened-xpub", ["start", ["wpkh(%s/0h/*)" % tpub_root]]),
        ("err-obj-nodesc", ["start", [{"range": 3}]]),
        ("err-obj-number", ["start", [5]]),
        ("err-range-neg", ["start", [{"desc": xp_wpkh, "range": [-1, 3]}]]),
        ("err-range-rev", ["start", [{"desc": xp_wpkh, "range": [5, 3]}]]),
        ("err-range-big", ["start", [{"desc": xp_wpkh, "range": 1000000}]]),
        ("err-range-high", ["start", [{"desc": xp_wpkh, "range": 2147483648}]]),
        ("err-range-str", ["start", [{"desc": xp_wpkh, "range": "x"}]]),
        ("err-nostart-objs", ["start"]),
        ("err-action", ["bogus"]),
        ("err-start-null", ["start", None]),
        ("err-start-str", ["start", "raw(51)"]),
        ("err-start-obj", ["start", {"desc": "raw(51)"}]),
        ("err-action-num", [5]),
        ("err-noparams", []),
        ("err-range-float", ["start", [{"desc": xp_wpkh, "range": 5.0}]]),
        ("err-desc-num", ["start", [{"desc": 5}]]),
        ("err-desc-null", ["start", [{"desc": None}]]),
        ("status-idle", ["status"]),
        ("abort-idle", ["abort"]),
        ("status-idle-extra", ["status", ["raw(51)"]]),
    ]
    for tag, params in cases:
        c, co = rpc(CORE_RPC, ca, "scantxoutset", params)
        b, bo = rpc(BEAM_RPC, ba, "scantxoutset", params)
        print("=== %s ===" % tag)
        if is_err(c) or is_err(b):
            rec(tag, "error", c if is_err(c) else "OK", b if is_err(b) else "OK")
            continue
        if not isinstance(c, dict) or "unspents" not in c:
            rec(tag, "result", c, b)
            continue
        if not isinstance(b, dict):
            rec(tag, "result", "object", b)
            continue
        for f in ("success", "txouts", "height", "bestblock", "total_amount"):
            rec(tag, f, c.get(f), b.get(f))
        rec(tag, "key_order", [k for k, _ in key_order(co)],
            [k for k, _ in key_order(bo)])
        cu, bu = c["unspents"], b.get("unspents") or []
        rec(tag, "n_unspents", len(cu), len(bu))
        rec(tag, "unspent_order", [(u["txid"], u["vout"]) for u in cu],
            [(u.get("txid"), u.get("vout")) for u in bu])
        bi = {(u.get("txid"), u.get("vout")): u for u in bu}
        cko = key_order(co)
        bko = key_order(bo)
        c_uko = [x for k, x in cko if k == "unspents"][0]
        b_uko = [x for k, x in bko if k == "unspents"][0]
        if c_uko and b_uko:
            rec(tag, "unspent_key_order", [k for k, _ in c_uko[0]],
                [k for k, _ in b_uko[0]])
        if len(cu) == 0:
            print("  (core matched nothing)")
        for u in cu:
            k = (u["txid"], u["vout"])
            v = bi.get(k)
            if v is None:
                rec(tag, "unspent[%s:%s]" % k, "present", None)
                continue
            for f in ("txid", "vout", "scriptPubKey", "desc", "amount",
                      "coinbase", "height", "blockhash", "confirmations"):
                rec(tag, "u[%s:%d].%s" % (k[0][:8], k[1], f), u.get(f), v.get(f))
        print("  n=%d txouts=%s total=%s descs=%s" % (
            len(cu), c.get("txouts"), c.get("total_amount"),
            sorted({u["desc"] for u in cu})[:6]))

    bad = [r for r in rows if not r[4]]
    print("\n=== SUMMARY ===")
    print("cases=%d checks=%d matched=%d mismatched=%d" % (
        len(cases), len(rows), len(rows) - len(bad), len(bad)))
    by_case = {}
    for r in rows:
        by_case.setdefault(r[0], [0, 0])[0 if r[4] else 1] += 1
    for t, (m, x) in by_case.items():
        print("  %-22s matched=%-4d mismatched=%d" % (t, m, x))
    return 1 if bad else 0


if __name__ == "__main__":
    rc = 2
    try:
        rc = main()
    finally:
        stop_all()
    sys.exit(rc)
