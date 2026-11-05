# Honeypot Screener API — check a BSC token before you buy it

Free, no-key HTTP API that checks whether a BNB Smart Chain token looks
like a honeypot. Built for AI agents and developers who screen memecoins
before trading. Read-only: it never holds a wallet, never signs anything,
never moves funds.

**Live demo (free tier):** `https://appearance-opt-clara-anaheim.trycloudflare.com`
> ⚠️ The demo runs on a temporary tunnel URL that changes on restart. If the
> URL above is dead, run the server yourself — it takes one command (below).

## Quick start

```bash
# Check a token (no key, no signup)
curl -s -X POST https://appearance-opt-clara-anaheim.trycloudflare.com/check \
  -H 'Content-Type: application/json' \
  -d '{"address":"0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"}'
```

```json
{
  "address": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
  "verdict": "SAFE",
  "points": 0,
  "signals": [{"status": "INFO", "text": "GoPlus: Wrapped BNB (WBNB), ...", "points": 0}],
  "note": "...",
  "source": "goplus",
  "rate_limit": {"limit": 10, "remaining": 9}
}
```

Verdicts: `SAFE` · `NOTED` · `SUSPICIOUS` · `HONEYPOT` · `UNKNOWN`.

## Endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/health` | `{"status":"ok","service":"honeypot-screener-api","daily_limit_per_ip":10}` |
| POST | `/check` | `{"address":"0x..."}` → verdict JSON (see above) |

Anything else → 404. Bad address → 400. Body > 4 KB → 413.
Free limit reached → 429 (`daily free limit reached`, resets next UTC day).

**Free tier: 10 queries/day/IP (UTC), no key, no signup.**

## Run it yourself

Requires Python 3.11+ and nothing else — standard library only, no
dependencies to install.

```bash
git clone <this-repo>
cd honeypot-screener
python3 api_server.py            # localhost:8080, limit 10/day/IP
# or: HONEYPOT_API_PORT=8000 HONEYPOT_API_DAILY_LIMIT=50 python3 api_server.py
```

CLI usage (same scorer, no server):

```bash
python3 honeypot_screener.py 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
```

## How scoring works

Data source: [GoPlus token_security](https://gopluslabs.io/) (free, no key),
plus a read-only on-chain fallback when GoPlus has no record.

Scoring (v2, validated on 16 cases with zero regressions):

- `HONEYPOT` — a FAIL signal, or ≥ 10 points. FAIL signals:
  simulation-confirmed `cannot_sell_all`, 100% sell tax, or a
  tiny max-sell restriction.
- `SUSPICIOUS` — any STRONG warning, or ≥ 5 weak warnings.
- `NOTED` — 3–4 weak warnings only.
- `SAFE` — 0–2 weak warnings only.
- `UNKNOWN` — fail-closed when there is no sellability evidence at all
  (e.g. GoPlus `is_honeypot` + `buy_tax` + `sell_tax` all null).

## Honest limits

This is a snapshot from GoPlus plus read-only checks. It catches
simulation-confirmed sell restrictions, 100% sell tax, and tiny-max-sell
traps, and it clears canonical tokens (e.g. WBNB) without false alarms.
It is **not** general honeypot detection: there is no own sell simulation
yet, no EIP-1967 proxy resolution, and no second-opinion oracle.
A `SAFE` verdict is not a buy recommendation, and a token can turn bad
later (owner can pause trading, change taxes, or blacklist sellers).
Always verify before risking funds.

## Files

- `honeypot_screener.py` — the CLI scorer (stdlib-only).
- `api_server.py` — the HTTP wrapper (stdlib-only, binds `127.0.0.1` only;
  expose it publicly through a tunnel or reverse proxy, never directly).

## License

MIT — see `LICENSE`.
