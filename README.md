# Triage

A threat-intelligence tool that takes indicators of compromise (IP addresses and domains) and returns a verdict for each, backed by VirusTotal. Paste a raw log, plain list, or upload a file, and Triage extracts every indicator, checks it, and hands back a rated summary.

It exists to solve a small but real annoyance: VirusTotal's interface checks one indicator at a time. An analyst triaging a log of suspicious IPs would have to paste them in one by one. Triage does the whole batch at once, remembers what it has already seen, and applies a consistent verdict policy on the raw results.

<img width="1168" height="600" alt="image" src="https://github.com/user-attachments/assets/5e893c83-727a-452b-9c15-21b278e6fe7a" />

## What it does

- **Extracts indicators from anything** — paste a clean list, a raw log file, or upload a file. IPs and domains are pulled out by pattern, regardless of the surrounding log format.
- **Enriches via VirusTotal** — each indicator is looked up and scored by how many of VirusTotal's engines flag it.
- **Applies its own verdict** — raw engine counts are turned into a `clean` / `suspicious` / `malicious` / `undetected` verdict using a fixed threshold.
- **Caches results** — a verdict is stored the first time an indicator is seen, so repeat lookups don't cost another API call.
- **Deduplicates** — the same indicator appearing many times in a log is checked once.

## Tech stack

- **Backend:** Python, FastAPI, SQLite
- **Threat intel:** VirusTotal API v3
- **Frontend:** vanilla HTML / CSS / JavaScript, served by FastAPI

## Setup

Triage needs your own VirusTotal API key (the free tier works). It is a local tool. Clone it and run it in your own environment.

1. **Clone and enter the project**
   ```bash
   git clone https://github.com/kiandadban/triage.git
   cd triage
   ```

2. **Create a virtual environment and install dependencies**
   ```bash
   python -m venv .venv
   source .venv/bin/activate        # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
   > Use `python3` on macOS/Linux if `python` doesn't work.

3. **Add your VirusTotal API key**

   Get a free key from your VirusTotal account under ***API Key***.
   
   Create a `.env` file in the project root with your key:
```bash
   echo "VT_API_KEY=your_key_here" > .env
```
   

4. **Run it**
   ```bash
   uvicorn main:app --reload
   ```
   Open `http://127.0.0.1:8000` in your browser.

## Usage

**Web interface** — the fastest way. Open the root URL, paste indicators (or a raw log) into the *Paste* tab, or drop a file into the *Upload* tab, and click Enrich. Results appear color-coded by verdict.

**API** — the tool is a REST API; the UI just calls it. You can drive it directly:

```bash
# check a single indicator
curl -X POST http://127.0.0.1:8000/check \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8", "type": "ip"}'

# check a batch
curl -X POST http://127.0.0.1:8000/check-batch \
  -H "Content-Type: application/json" \
  -d '[{"indicator": "8.8.8.8", "type": "ip"}, {"indicator": "google.com", "type": "domain"}]'

# extract-and-check from pasted text or a raw log
curl -X POST http://127.0.0.1:8000/check-text \
  -H "Content-Type: application/json" \
  -d '{"text": "failed login from 45.33.32.156 to evil.com"}'

# extract-and-check from an uploaded file
curl -X POST http://127.0.0.1:8000/check-file -F "file=@log.txt"
```

Interactive API docs are available at `http://127.0.0.1:8000/docs`.

## Verdicts

Each indicator gets a verdict derived from how many VirusTotal engines flagged it:

| Verdict      | Condition                                    |
|--------------|----------------------------------------------|
| `malicious`  | 3 or more engines flagged it                 |
| `suspicious` | 1–2 engines flagged it                       |
| `clean`      | no engines flagged it                        |
| `undetected` | no engine has any verdict on it              |

## Limitations

- Uses the VirusTotal free tier (rate-limited, daily quota).
- Runs locally with SQLite; not built for concurrent multi-user deployment.
- Extraction is pattern-based, so it captures every IP/domain in the input, including internal addresses.
