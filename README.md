# Scambait Research Toolkit

A local, VM-contained FastAPI panel for studying scammer tactics, capturing
behavioral signals, and analyzing fraud patterns. It runs entirely on
`127.0.0.1` and makes **zero outbound network calls** by design.

This is a **defensive / academic security research** tool. It is not a bot, it
does not message anyone on your behalf, and it stores everything locally.

---

## What it does

- **Session tracking** - log inbound/outbound messages of a baiting session and
  measure how much of a scammer's time was wasted.
- **Persona & delay scripts** - pre-written "confused elderly", "overly eager",
  "tech illiterate", and "suspicious but curious" personas plus realistic
  time-wasting delay patterns (phone calls, looking for glasses, asking a
  spouse, etc.). These are suggestions for a human operator to send manually.
- **Static attachment analysis** - hash uploaded files (MD5/SHA-1/SHA-256),
  detect file type, and flag suspicious traits **without executing anything**.
- **URL defanging & link analysis** - inspect suspicious links safely
  (defanged, never fetched).
- **Scam-pattern detection** - keyword heuristics across urgency / authority /
  fear / greed / social-proof / reciprocity categories.
- **Wallet honeypot** - a purely cosmetic fake crypto wallet page (no real
  funds, no real address you control) used to study how scammers react to a
  "loaded" wallet.
- **Metadata collection** - request headers, user-agent parsing, and
  behavioral signals, stored locally.
- **Audit logging & VM-reset helpers** - every action is logged; built-in
  wipe/snapshot-prep endpoints support clean VM snapshots.

## Architecture

```
scambait-research-toolkit/
├── config.py               # All settings (env-overridable, safe defaults)
├── run.py                  # Entry point -> starts uvicorn on 127.0.0.1
├── core/                   # FastAPI app, SQLite layer, models, safety controls
├── modules/
│   ├── analyzer/           # File hashing, static analysis, URL defanging
│   ├── metadata/           # Request metadata + enrichment (local only)
│   ├── scripts/            # Personas, delay patterns, response engine
│   └── wallet/             # Fake wallet honeypot
├── dashboard/              # Jinja2 templates + static JS/CSS dashboard
└── tests/                  # Test scaffold (see "Tests" below - WIP)
```

## Requirements

- Python 3.10+
- An isolated VM is **strongly recommended** (this tool is meant to be run in a
  disposable sandbox you can snapshot and wipe).
- No internet access required - operation is fully local.

## Setup

```bash
# 1. Clone
git clone https://github.com/DoradoDevs/scambait-research-toolkit.git
cd scambait-research-toolkit

# 2. Create a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) create a local config from the template
cp .env.example .env        # then edit values if you want to
```

There are no secrets to fill in - every value in `.env.example` is optional and
has a safe default. The SQLite database is created automatically on first run.

## Running

```bash
python run.py
```

Then open:

- Dashboard: <http://localhost:8000>
- API docs (Swagger): <http://localhost:8000/api/docs>

To change the port, set `SCAMBAIT_PORT` in your `.env` (or the environment).
The host is intentionally locked to `127.0.0.1` in `config.py`.

## Configuration

| Variable               | Default                          | Purpose                                     |
| ---------------------- | -------------------------------- | ------------------------------------------- |
| `SCAMBAIT_PORT`        | `8000`                           | Local dashboard port                        |
| `HONEYPOT_ADDRESS`     | Solana incinerator burn address  | Public display address for the fake wallet  |
| `HONEYPOT_BALANCE_SOL` | `47832.91`                       | Fake SOL balance shown on the honeypot page |
| `HONEYPOT_BALANCE_USD` | `4783291.00`                     | Fake USD balance shown on the honeypot page |

> The default honeypot address is Solana's well-known "incinerator" burn
> address, which nobody controls. **Never** set `HONEYPOT_ADDRESS` to a wallet
> you actually own - this page is deliberately shown to scammers.

## Safety model

1. **Localhost only** - binds to `127.0.0.1`; a host-header allowlist rejects
   any other `Host`.
2. **Zero outbound** - no external API calls, CDNs, or remote assets. The
   honeypot page intentionally references no remote images.
3. **No execution** - uploaded files are hashed and statically inspected only;
   nothing is run.
4. **Local storage** - all data lives under `data/` (gitignored) in a local
   SQLite database.
5. **Wipe / snapshot** - `POST /api/safety/full-wipe` and
   `/api/safety/prepare-snapshot` support clean VM resets.

## Tests

`tests/` currently contains only scaffolding - there is no meaningful test suite
yet. Contributions welcome. `pytest` and `pytest-asyncio` are already listed in
`requirements.txt`.

## Responsible use

This tool is intended for legitimate defensive research, fraud-awareness
training, and education. Do not use it to harass individuals, collect data
without authorization, or break the law. See [LEGAL_NOTICE.md](LEGAL_NOTICE.md)
for the full usage guidelines and ethics notes.

## License

Released under the [MIT License](LICENSE).
