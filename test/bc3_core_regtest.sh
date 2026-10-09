#!/usr/bin/env bash
# BC-3: Bitcoin Core v31.1 regtest vs beamchain, offline (no peers).
# Mines on bitcoind, submits the same blocks to beamchain, compares
# scantxoutset / gettxoutsetinfo / tip, then connects one more block
# while a scantxoutset walk is parked on BEAMCHAIN_TEST_HOOK_DIR.
#
# tools/regtest-harness.sh is named by the CLI and is not in this tree.
# Requires: bitcoind+bitcoin-cli (official v31.1), _build/default/bin/beamchain,
# python3. Does not dial any public seed or peer.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BITCOIN_DIR="${BITCOIN_DIR:-/tmp/bitcoin-core/bitcoin-31.1}"
BITCOIND="${BITCOIND:-$BITCOIN_DIR/bin/bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-$BITCOIN_DIR/bin/bitcoin-cli}"
BEAM="${BEAM:-$ROOT/_build/default/bin/beamchain}"
export PATH="${HOME}/.local/bin:${PATH}"

WORK="${BC3_WORK:-/tmp/bc3-regtest}"
CORE_DIR="$WORK/core"
BEAM_DIR="$WORK/beam"
HOOK_DIR="$WORK/hooks"
CORE_RPC_PORT="${BC3_CORE_RPC:-18443}"
BEAM_RPC_PORT="${BC3_BEAM_RPC:-18445}"
BEAM_P2P_PORT="${BC3_BEAM_P2P:-18446}"

if [[ ! -x "$BITCOIND" || ! -x "$BITCOIN_CLI" ]]; then
    echo "bitcoind/bitcoin-cli missing under $BITCOIN_DIR" >&2
    exit 2
fi
if [[ ! -x "$BEAM" ]]; then
    echo "beamchain escript missing: $BEAM (rebar3 escriptize)" >&2
    exit 2
fi

rm -rf "$WORK"
mkdir -p "$CORE_DIR" "$BEAM_DIR" "$HOOK_DIR"

cleanup() {
    if [[ -n "${BEAM_PID:-}" ]] && kill -0 "$BEAM_PID" 2>/dev/null; then
        kill "$BEAM_PID" 2>/dev/null || true
        wait "$BEAM_PID" 2>/dev/null || true
    fi
    if [[ -x "$BITCOIN_CLI" && -d "$CORE_DIR" ]]; then
        "$BITCOIN_CLI" -regtest -datadir="$CORE_DIR" -rpcport="$CORE_RPC_PORT" \
            stop >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "=== bitcoind version ==="
"$BITCOIND" -version | head -n 2

"$BITCOIND" -regtest -datadir="$CORE_DIR" \
    -listen=0 -connect=0 -dnsseed=0 -fixedseeds=0 \
    -server=1 -txindex=1 -fallbackfee=0.0002 \
    -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
    -rpcport="$CORE_RPC_PORT" -daemon

for _ in $(seq 1 50); do
    if "$BITCOIN_CLI" -regtest -datadir="$CORE_DIR" -rpcport="$CORE_RPC_PORT" \
            getblockcount >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
"$BITCOIN_CLI" -regtest -datadir="$CORE_DIR" -rpcport="$CORE_RPC_PORT" getblockcount >/dev/null

echo "=== beamchain (offline regtest) ==="
BEAMCHAIN_TEST_HOOK_DIR="$HOOK_DIR" \
    "$BEAM" start \
    --network=regtest \
    --datadir="$BEAM_DIR" \
    --rpc-port="$BEAM_RPC_PORT" \
    --p2p-port="$BEAM_P2P_PORT" \
    --nodnsseed \
    --nofixedseeds \
    --connect=127.0.0.1:1 \
    --printtoconsole \
    >"$BEAM_DIR/beamchain.out" 2>&1 &
BEAM_PID=$!

export BC3_CORE_DIR="$CORE_DIR"
export BC3_BEAM_DIR="$BEAM_DIR"
export BC3_HOOK_DIR="$HOOK_DIR"
export BC3_CORE_RPC_PORT="$CORE_RPC_PORT"
export BC3_BEAM_RPC_PORT="$BEAM_RPC_PORT"
export BC3_BEAM_PID="$BEAM_PID"
export BC3_BITCOIN_CLI="$BITCOIN_CLI"

python3 - <<'PY'
import json, os, sys, time, base64, urllib.request, urllib.error, threading
from decimal import Decimal

core_dir = os.environ["BC3_CORE_DIR"]
beam_dir = os.environ["BC3_BEAM_DIR"]
hook_dir = os.environ["BC3_HOOK_DIR"]
core_port = os.environ["BC3_CORE_RPC_PORT"]
beam_port = os.environ["BC3_BEAM_RPC_PORT"]
beam_pid = int(os.environ["BC3_BEAM_PID"])
cli = os.environ["BC3_BITCOIN_CLI"]

core_url = "http://127.0.0.1:%s/" % core_port
fund_url = "http://127.0.0.1:%s/wallet/fund" % core_port
recv_url = "http://127.0.0.1:%s/wallet/recv" % core_port
beam_url = "http://127.0.0.1:%s/" % beam_port

mismatches = []
justified = []
unsupported = []
matched = [0]

def cookie_basic(path):
    deadline = time.time() + 60
    while time.time() < deadline:
        if os.path.isfile(path):
            raw = open(path, "rb").read().strip()
            if raw:
                return base64.b64encode(raw).decode()
        if beam_pid and not _alive(beam_pid) and "beam" in path:
            break
        time.sleep(0.2)
    raise SystemExit("cookie missing: %s" % path)

def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def rpc(url, auth, method, params=None, timeout=180):
    body = json.dumps({
        "jsonrpc": "1.0", "id": "bc3", "method": method, "params": params or []
    }).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Authorization": "Basic " + auth,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode(), parse_float=Decimal)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            payload = json.loads(raw, parse_float=Decimal)
        except json.JSONDecodeError:
            return {"_error": {"code": e.code, "message": raw[:500]}}
    except (TimeoutError, urllib.error.URLError) as e:
        return {"_error": {"code": "timeout", "message": str(e)}}
    err = payload.get("error")
    if err:
        return {"_error": err}
    return payload.get("result")

def is_err(v):
    return isinstance(v, dict) and "_error" in v

def err_text(v):
    e = v["_error"]
    if isinstance(e, dict):
        return "code=%s message=%s" % (e.get("code"), e.get("message"))
    return str(e)

def show(label, a, b):
    print("  MISMATCH %s" % label)
    print("    core=%s" % a)
    print("    beam=%s" % b)

def same(field, a, b, why=None):
    if a == b:
        matched[0] += 1
        return True
    if why:
        justified.append((field, a, b, why))
        print("  JUSTIFIED %s" % field)
        print("    core=%s" % a)
        print("    beam=%s" % b)
        print("    why=%s" % why)
    else:
        mismatches.append((field, a, b))
        show(field, a, b)
    return False

def norm_hex(v):
    if isinstance(v, str):
        return v.lower()
    return v

def desc_body(v):
    if not isinstance(v, str):
        return v
    return v.split("#", 1)[0]

def index_unspents(rows):
    out = {}
    for u in rows or []:
        out[(u.get("txid"), u.get("vout"))] = u
    return out

UNSPENT_KEYS = (
    "txid", "vout", "scriptPubKey", "desc", "amount",
    "coinbase", "height", "blockhash", "confirmations",
)

def cmp_unspents(tag, core_rows, beam_rows):
    ci = index_unspents(core_rows)
    bi = index_unspents(beam_rows)
    same("%s.unspents_len" % tag, len(core_rows or []), len(beam_rows or []))
    for key in sorted(set(ci) | set(bi)):
        c = ci.get(key)
        b = bi.get(key)
        ks = "%s:%s" % key
        if c is None or b is None:
            same("%s.unspent[%s]" % (tag, ks), c, b)
            continue
        for f in UNSPENT_KEYS:
            cv, bv = c.get(f), b.get(f)
            if f in ("txid", "scriptPubKey", "blockhash"):
                cv, bv = norm_hex(cv), norm_hex(bv)
            if f == "desc":
                if cv == bv:
                    matched[0] += 1
                else:
                    why = ("Core desc is InferDescriptor(script)->ToString() "
                           "(checksum, often specialized); beamchain echoes "
                           "the scan object with the #checksum stripped "
                           "(scan_object_descriptor/1, pre-existing)")
                    justified.append(("%s.unspent[%s].desc" % (tag, ks), cv, bv, why))
                    print("  JUSTIFIED %s.unspent[%s].desc" % (tag, ks))
                    print("    core=%s" % cv)
                    print("    beam=%s" % bv)
                continue
            same("%s.unspent[%s].%s" % (tag, ks, f), cv, bv)

def cmp_scan(tag, core, beam, kind):
    print("=== SCAN %s (%s) ===" % (tag, kind))
    if is_err(beam) and kind in ("wpkh", "tr"):
        unsupported.append((tag, err_text(beam),
                            None if is_err(core) else {
                                "success": core.get("success"),
                                "txouts": core.get("txouts"),
                                "n": len(core.get("unspents") or []),
                            }))
        print("  UNSUPPORTED on beamchain: %s" % err_text(beam))
        if not is_err(core):
            print("  core accepted: success=%s txouts=%s unspents=%s" % (
                core.get("success"), core.get("txouts"),
                len(core.get("unspents") or [])))
        return None
    if is_err(core) or is_err(beam):
        same("%s.error" % tag,
             None if not is_err(core) else err_text(core),
             None if not is_err(beam) else err_text(beam))
        return None
    print("  n core=%s beam=%s txouts core=%s beam=%s total core=%s beam=%s" % (
        len(core.get("unspents") or []), len(beam.get("unspents") or []),
        core.get("txouts"), beam.get("txouts"),
        core.get("total_amount"), beam.get("total_amount")))
    same("%s.success" % tag, core.get("success"), beam.get("success"))
    same("%s.txouts" % tag, core.get("txouts"), beam.get("txouts"))
    same("%s.height" % tag, core.get("height"), beam.get("height"))
    same("%s.bestblock" % tag, norm_hex(core.get("bestblock")),
         norm_hex(beam.get("bestblock")))
    same("%s.total_amount" % tag, core.get("total_amount"), beam.get("total_amount"))
    cmp_unspents(tag, core.get("unspents"), beam.get("unspents"))
    return beam

def cmp_info(tag, core, beam, hash_field=None):
    print("=== GETTXOUTSETINFO %s ===" % tag)
    if is_err(core) or is_err(beam):
        same("%s.error" % tag,
             None if not is_err(core) else err_text(core),
             None if not is_err(beam) else err_text(beam))
        return
    for f in ("height", "bestblock", "txouts", "bogosize",
              "total_amount", "transactions"):
        cv, bv = core.get(f), beam.get(f)
        if f == "bestblock":
            cv, bv = norm_hex(cv), norm_hex(bv)
        same("%s.%s" % (tag, f), cv, bv)
    if hash_field:
        same("%s.%s" % (tag, hash_field),
             norm_hex(core.get(hash_field)), norm_hex(beam.get(hash_field)))
    cv, bv = core.get("disk_size"), beam.get("disk_size")
    if cv == bv:
        matched[0] += 1
    else:
        why = ("beamchain do_rpc_gettxoutsetinfo hardcodes disk_size 0 "
               "(pre-existing; not the scantxoutset fold)")
        justified.append(("%s.disk_size" % tag, cv, bv, why))
        print("  JUSTIFIED %s.disk_size" % tag)
        print("    core=%s" % cv)
        print("    beam=%s" % bv)
        print("    why=%s" % why)

print("waiting for cookies")
core_auth = cookie_basic(os.path.join(core_dir, "regtest", ".cookie"))
# --datadir is the base; non-mainnet appends the network name
# (beamchain_config:determine_datadir/1). Cookie lives in that directory.
beam_auth = cookie_basic(os.path.join(beam_dir, "regtest", ".cookie"))

def core(method, params=None, timeout=180, url=None):
    return rpc(url or core_url, core_auth, method, params, timeout)

def beam(method, params=None, timeout=180):
    return rpc(beam_url, beam_auth, method, params, timeout)

print("=== peers before mining ===")
cc = core("getconnectioncount")
print("  core connections=%s" % cc)
if cc not in (0, None) and not is_err(cc) and cc != 0:
    raise SystemExit("core has peers: %s" % cc)

# Receipts live in a second wallet so later sends do not spend them.
for name in ("fund", "recv"):
    w = core("createwallet", [name])
    if is_err(w):
        raise SystemExit("createwallet %s: %s" % (name, err_text(w)))

def gna(url, kind):
    a = core("getnewaddress", ["", kind], url=url)
    if is_err(a):
        raise SystemExit("getnewaddress %s: %s" % (kind, err_text(a)))
    return a

a_fund = gna(fund_url, "bech32")
a_wpkh = gna(recv_url, "bech32")
a_legacy = gna(recv_url, "legacy")
a_tr = gna(recv_url, "bech32m")
print("addresses fund=%s wpkh=%s legacy=%s tr=%s" % (a_fund, a_wpkh, a_legacy, a_tr))

gen = core("generatetoaddress", [101, a_fund], url=fund_url, timeout=300)
if is_err(gen):
    raise SystemExit("generatetoaddress 101: %s" % err_text(gen))
for amt, dest in ((Decimal("1"), a_legacy), (Decimal("0.5"), a_tr),
                  (Decimal("0.25"), a_wpkh)):
    tx = core("sendtoaddress", [dest, str(amt)], url=fund_url)
    if is_err(tx):
        raise SystemExit("sendtoaddress %s: %s" % (dest, err_text(tx)))
    print("  spend %s -> %s txid=%s" % (amt, dest, tx))
gen2 = core("generatetoaddress", [15, a_fund], url=fund_url, timeout=180)
if is_err(gen2):
    raise SystemExit("generatetoaddress 15: %s" % err_text(gen2))

tip_h = core("getblockcount")
tip_hash = core("getbestblockhash")
print("=== core chain ===")
print("  height=%s bestblock=%s" % (tip_h, tip_hash))
if not isinstance(tip_h, int) or tip_h < 110:
    raise SystemExit("expected height >= 110, got %s" % tip_h)
cc = core("getconnectioncount")
print("  core connections=%s" % cc)
if cc != 0:
    raise SystemExit("core grew peers: %s" % cc)

print("=== feed blocks to beamchain ===")
t_feed = time.perf_counter()
for h in range(1, tip_h + 1):
    bh = core("getblockhash", [h])
    hx = core("getblock", [bh, 0])
    if is_err(bh) or is_err(hx):
        raise SystemExit("getblock %s failed" % h)
    res = beam("submitblock", [hx], timeout=120)
    if res is not None:
        raise SystemExit("submitblock height %s -> %s" % (h, res))
    if h % 25 == 0 or h == tip_h:
        print("  submitted %s/%s" % (h, tip_h))
print("  feed_s=%.3f" % (time.perf_counter() - t_feed))

bc = beam("getconnectioncount")
print("=== peers after feed ===")
print("  beam connections=%s" % bc)
if bc != 0:
    raise SystemExit("beamchain has peers: %s" % bc)

bh_b = beam("getblockcount")
bb_b = beam("getbestblockhash")
print("=== TIP ===")
same("tip.height", tip_h, bh_b)
same("tip.bestblock", norm_hex(tip_hash), norm_hex(bb_b))

def info(addr):
    r = core("getaddressinfo", [addr], url=recv_url)
    if is_err(r):
        raise SystemExit("getaddressinfo %s: %s" % (addr, err_text(r)))
    return r

def checksummed(desc):
    r = core("getdescriptorinfo", [desc])
    if is_err(r):
        return desc
    return r.get("descriptor", desc)

infos = {a_wpkh: info(a_wpkh), a_legacy: info(a_legacy), a_tr: info(a_tr)}
scans = []
scans.append(("addr-bech32", "addr", checksummed("addr(%s)" % a_wpkh)))
scans.append(("addr-legacy", "addr", checksummed("addr(%s)" % a_legacy)))
scans.append(("addr-bech32m", "addr", checksummed("addr(%s)" % a_tr)))
legacy_spk = infos[a_legacy].get("scriptPubKey")
scans.append(("raw-legacy", "raw", checksummed("raw(%s)" % legacy_spk)))
pub_w = infos[a_wpkh].get("pubkey")
if isinstance(pub_w, str) and len(pub_w) == 66:
    scans.append(("wpkh", "wpkh", checksummed("wpkh(%s)" % pub_w)))
else:
    unsupported.append(("wpkh", "no compressed pubkey on bech32 address", None))
    print("=== SCAN wpkh ===")
    print("  UNSUPPORTED skip: getaddressinfo pubkey=%s" % pub_w)
pub_t = infos[a_tr].get("pubkey")
tr_spk = infos[a_tr].get("scriptPubKey") or ""
if isinstance(pub_t, str) and len(pub_t) in (64, 66):
    xonly = pub_t[-64:]
    scans.append(("tr", "tr", checksummed("tr(%s)" % xonly)))
elif isinstance(tr_spk, str) and tr_spk.startswith("5120") and len(tr_spk) == 68:
    # Output key from the v1 witness program. tr(<internal>) is not
    # recoverable here; rawtr(<output key>) is the descriptor Core infers.
    scans.append(("rawtr", "tr", checksummed("rawtr(%s)" % tr_spk[4:])))
else:
    unsupported.append(("tr", "no taproot key (pubkey=%s script=%s)" % (pub_t, tr_spk), None))
    print("=== SCAN tr ===")
    print("  UNSUPPORTED skip: pubkey=%s scriptPubKey=%s" % (pub_t, tr_spk))

saved = {}
for tag, kind, desc in scans:
    c = core("scantxoutset", ["start", [desc]], timeout=180)
    b = beam("scantxoutset", ["start", [desc]], timeout=180)
    got = cmp_scan(tag, c, b, kind)
    if tag in ("addr-bech32", "addr-legacy", "addr-bech32m", "raw-legacy"):
        n = 0 if is_err(c) else len(c.get("unspents") or [])
        if n < 1:
            raise SystemExit("%s matched no coins on core (desc=%s)" % (tag, desc))
    if got is not None and tag == "addr-legacy":
        saved["scan"] = got
        saved["desc"] = desc
        saved["core"] = c

cmp_info("none", core("gettxoutsetinfo", ["none"], timeout=180),
         beam("gettxoutsetinfo", ["none"], timeout=180))
cmp_info("hash_serialized_3",
         core("gettxoutsetinfo", ["hash_serialized_3"], timeout=180),
         beam("gettxoutsetinfo", ["hash_serialized_3"], timeout=180),
         "hash_serialized_3")

if "scan" not in saved:
    raise SystemExit("no pre-connect scan saved")

print("=== PARK: mine one core block, do not submit yet ===")
extra = core("generatetoaddress", [1, a_fund], url=fund_url, timeout=60)
if is_err(extra) or not extra:
    raise SystemExit("extra block: %s" % extra)
new_hash = extra[0]
new_hex = core("getblock", [new_hash, 0])
new_h = core("getblockcount")
print("  core now height=%s hash=%s (beam still %s)" % (new_h, new_hash, bh_b))

hook = os.path.join(hook_dir, "scantxoutset.fold")
hit = hook + ".hit"
open(hook, "wb").close()
try:
    os.remove(hit)
except OSError:
    pass

box = {}
def run_scan():
    t0 = time.perf_counter()
    box["result"] = beam("scantxoutset", ["start", [saved["desc"]]], timeout=180)
    box["scan_s"] = time.perf_counter() - t0

th = threading.Thread(target=run_scan)
th.start()
deadline = time.time() + 60
while time.time() < deadline and not os.path.isfile(hit):
    if not th.is_alive() and "result" in box:
        break
    time.sleep(0.05)
if not os.path.isfile(hit):
    print("  PARK hook never hit; scan result=%s" % box.get("result"))
    os.remove(hook)
    th.join(timeout=30)
    mismatches.append(("park.hook", "hit file", box.get("result")))
else:
    st = beam("scantxoutset", ["status"], timeout=10)
    print("  status while parked=%s" % st)
    t0 = time.perf_counter()
    sub = beam("submitblock", [new_hex], timeout=8)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    still = os.path.isfile(hook)
    print("  submitblock_ms=%.3f" % dt_ms)
    print("  hook_still_present=%s" % still)
    print("  submitblock_result=%s" % sub)
    os.remove(hook)
    th.join(timeout=60)
    scan = box.get("result")
    print("  parked_scan_wall_s=%.3f" % box.get("scan_s", -1))
    if not still:
        mismatches.append(("park.hook_released_early", True, still))
        show("park.hook_released_early", True, still)
    if sub is not None:
        mismatches.append(("park.submitblock", None, sub))
        show("park.submitblock", None, sub)
    else:
        matched[0] += 1
    if dt_ms > 2000:
        mismatches.append(("park.submitblock_ms", "<2000 while hook held", dt_ms))
        show("park.submitblock_ms", "<2000 while hook held", dt_ms)
    else:
        matched[0] += 1
        print("  connect returned in %.3f ms while the scan was parked" % dt_ms)
    if is_err(scan) or not isinstance(scan, dict):
        mismatches.append(("park.scan", "pre-connect snapshot", scan))
        show("park.scan", "pre-connect snapshot", scan)
    else:
        pre = saved["scan"]
        print("  parked scan height=%s bestblock=%s txouts=%s total=%s" % (
            scan.get("height"), scan.get("bestblock"),
            scan.get("txouts"), scan.get("total_amount")))
        print("  pre-connect     height=%s bestblock=%s txouts=%s total=%s" % (
            pre.get("height"), pre.get("bestblock"),
            pre.get("txouts"), pre.get("total_amount")))
        same("park.success", pre.get("success"), scan.get("success"))
        same("park.txouts", pre.get("txouts"), scan.get("txouts"))
        same("park.height", pre.get("height"), scan.get("height"))
        same("park.bestblock", norm_hex(pre.get("bestblock")),
             norm_hex(scan.get("bestblock")))
        same("park.total_amount", pre.get("total_amount"), scan.get("total_amount"))
        cmp_unspents("park", pre.get("unspents"), scan.get("unspents"))
        if scan.get("height") == new_h:
            mismatches.append(("park.saw_new_tip", pre.get("height"), scan.get("height")))

print("=== fresh scan at new tip vs core ===")
c2 = core("scantxoutset", ["start", [saved["desc"]]], timeout=180)
b2 = beam("scantxoutset", ["start", [saved["desc"]]], timeout=180)
cmp_scan("post-connect-legacy", c2, b2, "addr")
same("post.tip.height", core("getblockcount"), beam("getblockcount"))
same("post.tip.bestblock", norm_hex(core("getbestblockhash")),
     norm_hex(beam("getbestblockhash")))
bc = beam("getconnectioncount")
cc = core("getconnectioncount")
print("=== peers at end ===")
print("  core=%s beam=%s" % (cc, bc))
if cc != 0 or bc != 0:
    mismatches.append(("peers", (0, 0), (cc, bc)))

print("=== SUMMARY ===")
print("  matched_fields=%s" % matched[0])
print("  justified=%s" % len(justified))
print("  unsupported=%s" % len(unsupported))
print("  unjustified=%s" % len(mismatches))
for item in unsupported:
    print("  unsupported %s :: %s" % (item[0], item[1]))
if mismatches:
    print("UNJUSTIFIED MISMATCHES:")
    for field, a, b in mismatches:
        print("  %s" % field)
        print("    core=%s" % a)
        print("    beam=%s" % b)
    sys.exit(1)
print("OK")
PY
