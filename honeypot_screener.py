#!/usr/bin/env python3
"""BSC honeypot screener (read-only, stdlib-only).

Rebuilt from Zainur's stated methodology signals: blacklist, maxTx, maxWallet,
cooldown, sellability. No wallet, no private key, no API key, no payment, no
transaction is ever created. Data comes from public sources only.

Usage:
    python3 honeypot_screener.py <contract-address> [<address> ...]

Chain: BNB Smart Chain (56).

PRIMARY data source: GoPlus token_security public API (no key required).
  https://api.gopluslabs.io/api/v1/token_security/56?contract_addresses=<addr>
  NOTE (found empirically 2026-11-03): the free endpoint effectively returns data
  for one address per request; batch requests silently drop the rest. This script
  therefore queries ONE address per request, with a small delay between calls.

FALLBACK data source (only when GoPlus has no record for an address): direct
read-only eth_call checks against public BSC RPCs (metadata, code, Pancake pair +
reserves, owner). The fallback can never prove sellability on its own, so a
fallback-only result is verdict UNKNOWN (fail closed), never SAFE.

SCORING (transparent points; every point is printed with its evidence):
  FAIL (10 pts each):
    - GoPlus is_honeypot = 1 (their buy/sell simulation says sells fail)
    - sell_tax >= 0.50 (50%+ of the sale is taken)
  STRONG WARN (3 pts each):
    - cannot_buy = 1 (cannot enter at all)
    - cannot_sell_all = 1 (simulation shows not all holdings can be sold)
    - is_in_dex = 0 (no DEX pair: no public exit route)
    - hidden_owner = 1, selfdestruct = 1, owner_change_balance = 1
    - sell_tax >= 0.10 (10%+ exit cost)
    - buy_tax >= 0.50 (50%+ entry cost)
  WEAK WARN (1 pt each):
    - is_blacklisted = 1 (blacklist FUNCTION EXISTS -- capability, not proof it is
      used; many compliant tokens have one, so this alone never fails a token)
    - trading_cooldown = 1, is_anti_whale = 1, anti_whale_modifiable = 1
    - transfer_pausable = 1, is_mintable = 1, can_take_back_ownership = 1
    - slippage_modifiable = 1, is_open_source = 0, is_proxy = 1
    - owner or creator holds >= 50% of supply (dump concentration)
  VERDICT (v2, 2026-11-03): FAIL or >= 10 pts -> HONEYPOT | any STRONG signal
  or >= 5 weak pts -> SUSPICIOUS | 3-4 weak pts only -> NOTED (capabilities
  noted, no abuse detected) | 0-2 weak pts only -> SAFE
  No GoPlus record + incomplete fallback -> UNKNOWN (fail closed).
  GoPlus record with NO core sellability data (is_honeypot, sell_tax, buy_tax
  all null) -> UNKNOWN (fail closed, never silent SAFE).

METHODOLOGY NOTES (honest limits):
  - GoPlus exposes maxTx/maxWallet only as a single capability flag
    (is_anti_whale). It does NOT report the actual limits, and it does not split
    maxTx from maxWallet. They are scored once, together, as "maxTx/maxWallet
    (anti-whale)". Exact limits need the contract source/ABI.
  - GoPlus tax fields are decimal fractions (0.05 = 5%). Thresholds above use
    that reading.
  - A verdict is a SNAPSHOT. An owner who can change taxes, blacklist wallets,
    or pause trading can turn a SAFE-looking token into a honeypot later.
    Re-run immediately before any execution; never treat an old verdict as proof.
  - GoPlus is_honeypot is a simulation verdict, not a legal finding. When it
    disagrees with another label, investigate the case individually.

Runs on stock Python 3 (incl. phone proot Python 3.14). No third-party deps.
Public RPCs reject default python User-Agents, so every request carries a browser
User-Agent header.
"""

import json
import sys
import time
import urllib.error
import urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
GOPLUS_URL = "https://api.gopluslabs.io/api/v1/token_security/56?contract_addresses="
RPCS = ["https://bsc-dataseed.bnbchain.org", "https://bsc-dataseed1.bnbchain.org"]
FACTORY = "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73"
WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"

SEL_NAME = "06fdde03"
SEL_SYMBOL = "95d89b41"
SEL_DECIMALS = "313ce567"
SEL_TOTALSUPPLY = "18160ddd"
SEL_OWNER = "8da5cb5b"
SEL_GETPAIR = "e6a43905"
SEL_GETRESERVES = "0902f1ac"
SEL_CODE = "eth_getCode"


def http_get_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def http_post_json(url, payload, timeout=30):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": UA, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


# ---------------------------------------------------------------- eth_call utils

def _pad_addr(addr):
    return "0" * 24 + addr.lower().replace("0x", "")


def eth_call(rpc, to, data):
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
    }
    out = http_post_json(rpc, payload)
    if "error" in out:
        raise RuntimeError(out["error"].get("message", "eth_call error"))
    return out["result"]


def rpc_call_first(method_payload_fn):
    """Try each RPC in order; return (rpc_url, result) or raise last error."""
    last_err = None
    for rpc in RPCS:
        try:
            return rpc, method_payload_fn(rpc)
        except Exception as e:  # noqa: BLE001 - try next endpoint
            last_err = e
    raise RuntimeError(f"all RPCs failed: {last_err}")


def decode_string(hexdata):
    """Decode an ABI-encoded string return value; '' on failure."""
    try:
        b = bytes.fromhex(hexdata.replace("0x", ""))
        if len(b) < 64:
            return ""
        off = int.from_bytes(b[0:32], "big")
        ln = int.from_bytes(b[off:off + 32], "big")
        return b[off + 32:off + 32 + ln].decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def decode_uint(hexdata):
    try:
        return int(hexdata, 16)
    except Exception:  # noqa: BLE001
        return None


def decode_addr(hexdata):
    try:
        b = bytes.fromhex(hexdata.replace("0x", ""))
        if len(b) < 32:
            return None
        return "0x" + b[-20:].hex()
    except Exception:  # noqa: BLE001
        return None


def get_code(rpc, addr):
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
        "params": [addr, "latest"],
    }
    out = http_post_json(rpc, payload)
    if "error" in out:
        raise RuntimeError(out["error"].get("message", "eth_getCode error"))
    return out["result"]


# ---------------------------------------------------------------- GoPlus

def fetch_goplus(addr, retries=3):
    """One address per request (batching silently drops addresses)."""
    last_err = None
    for attempt in range(retries):
        try:
            d = http_get_json(GOPLUS_URL + addr, timeout=30)
            if d.get("code") != 1:
                raise RuntimeError(f"GoPlus code={d.get('code')} msg={d.get('message')}")
            return (d.get("result") or {}).get(addr.lower())
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"GoPlus fetch failed after {retries} tries: {last_err}")


# ---------------------------------------------------------------- fallback

def fallback_checks(addr):
    """Direct on-chain reads. Never proves sellability alone."""
    fb = {}
    try:
        _, code = rpc_call_first(lambda rpc: get_code(rpc, addr))
        fb["has_code"] = bool(code and code not in ("0x", "0x0"))
        fb["code_bytes"] = (len(code) - 2) // 2 if code else 0
    except Exception as e:  # noqa: BLE001
        fb["code_error"] = str(e)
        return fb
    if not fb["has_code"]:
        return fb
    try:
        _, r = rpc_call_first(lambda rpc: eth_call(rpc, addr, "0x" + SEL_NAME))
        fb["name"] = decode_string(r)
        _, r = rpc_call_first(lambda rpc: eth_call(rpc, addr, "0x" + SEL_SYMBOL))
        fb["symbol"] = decode_string(r)
        _, r = rpc_call_first(lambda rpc: eth_call(rpc, addr, "0x" + SEL_DECIMALS))
        fb["decimals"] = decode_uint(r)
    except Exception:  # noqa: BLE001
        pass
    try:
        _, r = rpc_call_first(
            lambda rpc: eth_call(rpc, FACTORY, "0x" + SEL_GETPAIR + _pad_addr(addr) + _pad_addr(WBNB))
        )
        fb["wbnb_pair"] = decode_addr(r)
    except Exception:  # noqa: BLE001
        pass
    pair = fb.get("wbnb_pair")
    if pair and pair != "0x0000000000000000000000000000000000000000":
        try:
            _, r = rpc_call_first(lambda rpc: eth_call(rpc, pair, "0x" + SEL_GETRESERVES))
            b = bytes.fromhex(r.replace("0x", ""))
            fb["reserves"] = (
                int.from_bytes(b[0:32], "big"),
                int.from_bytes(b[32:64], "big"),
            )
        except Exception:  # noqa: BLE001
            pass
    try:
        _, r = rpc_call_first(lambda rpc: eth_call(rpc, addr, "0x" + SEL_OWNER))
        fb["owner"] = decode_addr(r)
    except Exception:  # noqa: BLE001
        pass
    return fb


# ---------------------------------------------------------------- scoring

def fnum(info, key):
    """GoPlus numeric-as-string field -> float or None."""
    try:
        v = info.get(key)
        if v is None or v == "":
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def flag(info, key):
    return str(info.get(key, "0")) == "1"


def score_token(addr, info, fb):
    """Return (verdict, points, signal_lines, notes)."""
    lines = []  # (status, text, points)
    pts = 0
    sig = {"fail": False, "strong": 0, "weak": 0}

    def add(status, text, p):
        nonlocal pts
        pts += p
        if p >= 10:
            sig["fail"] = True
        elif p == 3:
            sig["strong"] += 3
        elif p == 1:
            sig["weak"] += 1
        lines.append((status, text, p))

    if info is None:
        lines.append(("UNKNOWN", "GoPlus has no record for this address", 0))
        if fb.get("has_code"):
            lines.append(("INFO", f"on-chain code exists ({fb.get('code_bytes', '?')} bytes)", 0))
            if fb.get("symbol"):
                lines.append(("INFO", f"token metadata: {fb.get('name', '?')} / {fb.get('symbol')} / decimals {fb.get('decimals')}", 0))
            pair = fb.get("wbnb_pair")
            if pair and pair != "0x0000000000000000000000000000000000000000":
                lines.append(("INFO", f"Pancake WBNB pair exists: {pair}", 0))
                if fb.get("reserves"):
                    lines.append(("INFO", f"pair reserves (raw): {fb['reserves']}", 0))
            else:
                lines.append(("WARN", "no Pancake WBNB pair found", 0))
            if fb.get("owner"):
                lines.append(("INFO", f"owner() returns: {fb['owner']}", 0))
        else:
            lines.append(("FAIL", "no contract code at this address (or RPC unreachable)", 0))
        return "UNKNOWN", 0, lines, (
            "Fail closed: without GoPlus simulation data, sellability cannot be "
            "verified, so this token is NOT cleared. Re-check when GoPlus covers it, "
            "or verify a sell by simulation before any execution."
        )

    # ---- null hardening (v2): a record with NO core sellability evidence
    # must never read as SAFE (ROD case: mostly-null record scored SAFE 1pt).
    if info.get("is_honeypot") is None and fnum(info, "sell_tax") is None \
            and fnum(info, "buy_tax") is None:
        lines.append(("UNKNOWN", "GoPlus record exists but carries NO core sellability "
                               "data (is_honeypot, sell_tax, buy_tax all null)", 0))
        lines.append(("INFO", f"GoPlus: {info.get('token_name', '?')} ({info.get('token_symbol', '?')}), "
                              f"open_source={info.get('is_open_source', '?')}, "
                              f"proxy={info.get('is_proxy', '?')}", 0))
        return "UNKNOWN", 0, lines, (
            "Fail closed: the record contains no sellability evidence, so this token "
            "is NOT cleared. Do not treat it as SAFE; re-check when GoPlus covers it, "
            "or verify a sell by simulation before any execution."
        )

    # ---- identity (info only)
    lines.append(("INFO", f"GoPlus: {info.get('token_name', '?')} ({info.get('token_symbol', '?')}), "
                         f"holders={info.get('holder_count', '?')}, trust_list={info.get('trust_list', '?')}, "
                         f"open_source={info.get('is_open_source', '?')}, proxy={info.get('is_proxy', '?')}", 0))

    # ---- 1. SELLABILITY
    if flag(info, "is_honeypot"):
        add("FAIL", "sellability: GoPlus is_honeypot=1 (buy/sell simulation says sells fail)", 10)
    else:
        add("OK", "sellability: GoPlus is_honeypot=0 (simulation did not flag a sell block)", 0)
    if flag(info, "cannot_buy"):
        add("FAIL", "sellability: cannot_buy=1 (cannot enter at all)", 3)
    if flag(info, "cannot_sell_all"):
        add("WARN", "sellability: cannot_sell_all=1 (simulation shows not all holdings "
                     "can be sold — direct sell restriction)", 3)
    if not flag(info, "is_in_dex"):
        add("FAIL", "sellability: is_in_dex=0 (no DEX pair: no public exit route)", 3)
    else:
        add("OK", "sellability: is_in_dex=1 (listed on a DEX)", 0)
    st = fnum(info, "sell_tax")
    if st is not None:
        if st >= 0.50:
            add("FAIL", f"sellability: sell_tax={st} ({st * 100:.2f}% of every sale is taken)", 10)
        elif st >= 0.10:
            add("WARN", f"sellability: sell_tax={st} ({st * 100:.2f}% exit cost)", 3)
        else:
            add("OK", f"sellability: sell_tax={st} ({st * 100:.2f}%)", 0)
    else:
        add("UNKNOWN", "sellability: sell_tax not reported", 0)
    bt = fnum(info, "buy_tax")
    if bt is not None:
        if bt >= 0.50:
            add("WARN", f"entry cost: buy_tax={bt} ({bt * 100:.2f}%)", 3)
        else:
            add("OK", f"entry cost: buy_tax={bt} ({bt * 100:.2f}%)", 0)

    # ---- 2. BLACKLIST (capability, not proof of use)
    if flag(info, "is_blacklisted"):
        add("WARN", "blacklist: blacklist function EXISTS (capability only; does not prove "
                     "any wallet is currently blacklisted)", 1)
    else:
        add("OK", "blacklist: no blacklist function reported", 0)

    # ---- 3. maxTx / maxWallet (one GoPlus flag covers both; exact limits not exposed)
    if flag(info, "is_anti_whale"):
        add("WARN", "maxTx/maxWallet: is_anti_whale=1 (a max-tx and/or max-wallet limit "
                     "exists; GoPlus does not report the values or split them)", 1)
    else:
        add("OK", "maxTx/maxWallet: is_anti_whale=0 (no anti-whale limit reported)", 0)
    if flag(info, "anti_whale_modifiable"):
        add("WARN", "maxTx/maxWallet: anti_whale_modifiable=1 (owner can change the limits)", 1)

    # ---- 4. COOLDOWN
    if flag(info, "trading_cooldown"):
        add("WARN", "cooldown: trading_cooldown=1 (trades are rate-limited by the contract)", 1)
    else:
        add("OK", "cooldown: trading_cooldown=0", 0)

    # ---- 5. SUPPORTING: owner powers, code visibility, concentration
    if flag(info, "hidden_owner"):
        add("WARN", "owner: hidden_owner=1 (ownership is obscured)", 3)
    if flag(info, "selfdestruct"):
        add("WARN", "owner: selfdestruct=1 (contract can be destroyed by owner)", 3)
    if flag(info, "owner_change_balance"):
        add("WARN", "owner: owner_change_balance=1 (owner can rewrite balances)", 3)
    if flag(info, "transfer_pausable"):
        add("WARN", "owner: transfer_pausable=1 (owner can pause all transfers)", 1)
    if flag(info, "is_mintable"):
        add("WARN", "owner: is_mintable=1 (owner can mint new supply)", 1)
    if flag(info, "can_take_back_ownership"):
        add("WARN", "owner: can_take_back_ownership=1 (renouncement can be undone)", 1)
    if flag(info, "slippage_modifiable"):
        add("WARN", "owner: slippage_modifiable=1 (owner can change slippage rules)", 1)
    if not flag(info, "is_open_source"):
        add("WARN", "code: is_open_source=0 (source not verified; rules cannot be read)", 1)
    if flag(info, "is_proxy"):
        add("WARN", "code: is_proxy=1 (logic lives in an implementation contract; check it too)", 1)
    for key in ("owner_percent", "creator_percent"):
        v = fnum(info, key)
        if v is not None and v >= 0.50:
            add("WARN", f"concentration: {key}={v} (>=50% held by one controller)", 1)

    if pts >= 10 or sig["fail"]:
        verdict = "HONEYPOT"
        note = ("Treat as a honeypot: at least one hard sell-block or confiscatory-tax "
                "signal fired. Do not buy; if held, do not assume an exit exists.")
    elif sig["strong"] >= 3 or sig["weak"] >= 5:
        verdict = "SUSPICIOUS"
        note = ("Proceed only with caution: a strong risk signal fired, or at least five "
                "weak capability flags stacked up, even though no hard sell-block fired. "
                "Re-check immediately before any execution, and prefer a small test buy "
                "+ sell over a full position.")
    elif sig["weak"] >= 3:
        verdict = "NOTED"
        note = ("Capabilities noted, no abuse detected: only weak capability flags fired "
                "(no sell-block, no confiscatory tax, no strong owner-power abuse). This "
                "is not an alarm, but the capabilities exist — re-check before executing, "
                "same as any token.")
    else:
        verdict = "SAFE"
        note = ("No honeypot signal fired in this snapshot. This is not a guarantee: an "
                "owner with live powers can change taxes, blacklist wallets, or pause "
                "trading later. Re-run before executing.")
    return verdict, pts, lines, note


def report_one(addr):
    print(f"\n{'=' * 72}\n{addr}\n{'=' * 72}")
    try:
        info = fetch_goplus(addr)
    except Exception as e:  # noqa: BLE001
        print(f"[!] GoPlus fetch failed: {e}")
        info = None
    fb = {}
    if info is None:
        print("[*] GoPlus has no record -> running on-chain fallback checks ...")
        try:
            fb = fallback_checks(addr)
        except Exception as e:  # noqa: BLE001
            print(f"[!] fallback failed: {e}")
    verdict, pts, lines, note = score_token(addr, info, fb)
    for status, text, p in lines:
        mark = {"OK": "[ok] ", "WARN": "[warn]", "FAIL": "[FAIL]", "INFO": "[info]", "UNKNOWN": "[ ? ]"}[status]
        suffix = f" (+{p} pts)" if p else ""
        print(f"{mark} {text}{suffix}")
    print(f"\nVERDICT {addr} {verdict} {pts}pts")
    print(f"NOTE: {note}")
    return verdict, pts


def valid_address(a):
    a = a.strip()
    return len(a) == 42 and a.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in a[2:])


def main(argv):
    addrs = argv[1:]
    if not addrs:
        print(__doc__)
        print("Usage: python3 honeypot_screener.py <contract-address> [<address> ...]")
        return 2
    results = []
    for i, addr in enumerate(addrs):
        if not valid_address(addr):
            print(f"\n[!] skipping invalid address: {addr}")
            continue
        if i > 0:
            time.sleep(0.6)  # be polite to the free GoPlus endpoint
        try:
            results.append((addr, *report_one(addr)))
        except Exception as e:  # noqa: BLE001
            print(f"\n[!] {addr} crashed: {e}")
            results.append((addr, "ERROR", 0))
    print(f"\n{'=' * 72}\nSUMMARY")
    for addr, verdict, pts in results:
        print(f"  {verdict:10s} {pts:>2}pts  {addr}")
    print("\nRead-only. No wallet, no key, no transaction was created.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
