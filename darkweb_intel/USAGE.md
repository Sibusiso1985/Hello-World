# Dark Web Threat Intelligence Toolkit

A targeted threat-intelligence tool for **authorised pentesting engagements
and defensive security** workflows.  It routes all traffic through the local
[Tor](https://www.torproject.org/) daemon and limits crawling to explicitly
supplied seed domains.

> **Legal notice** — Only use this tool against services you are explicitly
> authorised to access.  Unauthorised access to computer systems is illegal
> in most jurisdictions regardless of the network used to reach them.

---

## Prerequisites

| Requirement | Install |
|---|---|
| Python 3.10+ | system package manager |
| Tor daemon | `sudo apt install tor` (Debian/Ubuntu) |
| Python deps | `pip install -r requirements.txt` |

### Optional: circuit rotation

Add to `/etc/tor/torrc` and restart Tor:

```
ControlPort 9051
HashedControlPassword <output of: tor --hash-password YOUR_PASSWORD>
```

Then set `TOR_CONTROL_PASSWORD=YOUR_PASSWORD` in `.env`.

---

## Quick start

```bash
# Copy and edit the environment file
cp darkweb_intel/.env.example .env

# Verify Tor is running
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# Crawl a seed, watch for mentions of your client's domain
python -m darkweb_intel crawl \
    http://some-forum-xxxxxxxxxxx.onion \
    --keyword "target-company.com" \
    --keyword "Target Company" \
    --depth 2 \
    --db engagement.db

# Generate a report
python -m darkweb_intel report --db engagement.db
```

---

## Architecture

```
darkweb_intel/
├── tor_connector.py    # SOCKS5 session + circuit rotation via stem
├── crawler.py          # Depth-limited, rate-throttled, domain-allowlisted crawler
├── intel_extractor.py  # Regex-based artefact extraction (emails, creds, wallets, PGP, keywords)
├── storage.py          # SQLite persistence (SQLAlchemy Core)
├── cli.py              # click + rich CLI (crawl / report sub-commands)
└── tests/              # pytest unit tests (no Tor required)
```

## Extracted artefacts

| Artefact | Description |
|---|---|
| Emails | All `user@domain` patterns |
| Credentials | `email:password` pairs common in leaked dumps |
| BTC wallets | Legacy (`1…`/`3…`) and bech32 (`bc1…`) |
| ETH wallets | `0x…` 40-hex addresses |
| XMR wallets | Monero standard address pattern |
| PGP keys | Full `BEGIN/END PGP PUBLIC KEY BLOCK` blocks |
| Keywords | Configurable strings with surrounding context |

## Running tests

```bash
pip install pytest
pytest darkweb_intel/tests/ -v
```
