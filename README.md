# 🔍 GitHub Secrets Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![TruffleHog](https://img.shields.io/badge/TruffleHog-Powered-orange?style=for-the-badge&logo=security&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Bug%20Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-red?style=for-the-badge&logo=hackerone&logoColor=white)

**A high-performance, async GitHub secret scanning pipeline for bug bounty hunters and security researchers.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Dashboard](#-live-dashboard) • [Architecture](#-architecture)

</div>

---

## ✨ Features

- 🚀 **Async producer-consumer pipeline** — concurrent clone + scan workers for maximum throughput
- 🎯 **Two-command workflow** — `fetch` repos from any org/user, then `scan` them all
- 🔁 **Resume support** — crashes? interrupted? just re-run with `--resume`
- 💾 **Crash-safe streaming** — every finding written to disk immediately (NDJSON stream)
- 🧠 **Backpressure control** — bounded scan queue prevents RAM/disk exhaustion
- 🛡️ **Severity ranking** — findings auto-scored: CRITICAL → HIGH → MEDIUM → LOW
- 🗑️ **Automatic cleanup** — repos deleted after scan (keeps repos with findings as evidence)
- 💽 **Disk guard** — pauses cloning when disk space drops below threshold
- 📊 **Live web dashboard** — real-time findings viewer with filters, search, and severity badges
- 🔑 **GitHub API support** — authenticated (5000 req/hr) or unauthenticated (60 req/hr)

---

## 📦 Installation

### Prerequisites

```bash
# 1. Python 3.10+
python3 --version

# 2. git
git --version

# 3. TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

### Clone & Setup

```bash
git clone https://github.com/YOUR_USERNAME/github-secret-finder.git
cd github-secret-finder

# No pip dependencies — pure stdlib!
```

### Configure GitHub Token *(recommended)*

Create a `.env` file (automatically loaded at runtime):

```bash
GITHUB_TOKEN=ghp_your_personal_access_token_here
```

> **Generate a token:** https://github.com/settings/tokens  
> Required scopes: `public_repo` (read-only is fine)

---

## 🚀 Usage

### Step 1 — Fetch repos from a GitHub org

```bash
# Single org
python github_secret_finder.py fetch schubergphilis

# Multiple orgs at once
python github_secret_finder.py fetch stripe twilio sendgrid --token ghp_xxx

# Full GitHub URL formats also supported
python github_secret_finder.py fetch https://github.com/orgs/myorg/repositories

# Append to existing repos.txt instead of overwriting
python github_secret_finder.py fetch neworg --append
```

### Step 2 — Scan repos

```bash
# Basic scan
python github_secret_finder.py scan --input repos.txt

# Optimized scan (tune workers to your machine)
python github_secret_finder.py scan --input repos.txt --clone-workers 5 --scan-workers 8

# Resume an interrupted scan
python github_secret_finder.py scan --input repos.txt --resume

# Only report live/verified credentials
python github_secret_finder.py scan --input repos.txt --verified-only

# Full history scan (slower but more thorough)
python github_secret_finder.py scan --input repos.txt --no-shallow-clone
```

### One-liner: Fetch + Scan

```bash
python github_secret_finder.py fetch schubergphilis --scan --verified-only --token ghp_xxx
```

---

## ⚙️ CLI Reference

### `fetch` subcommand

| Argument | Default | Description |
|---|---|---|
| `orgs` | *(required)* | One or more org slugs or GitHub URLs |
| `--output` | `repos.txt` | Output file path |
| `--token` | `$GITHUB_TOKEN` | GitHub PAT for API auth |
| `--append` | off | Append to existing file |
| `--scan` | off | Auto-start scan after fetch |

### `scan` subcommand

| Argument | Default | Description |
|---|---|---|
| `--input` | `repos.txt` | Path to repos list file |
| `--clone-workers` | `5` | Concurrent git clone threads |
| `--scan-workers` | `6` | Concurrent trufflehog threads |
| `--resume` | off | Skip already-cloned repos |
| `--keep-repos` | off | Don't delete repos after scan |
| `--shallow-clone` | off | Clone last 50 commits only |
| `--verified-only` | off | Only report live credentials |
| `--scan-timeout` | `300` | Max seconds per repo scan |
| `--repos-dir` | `repos/` | Directory for cloned repos |
| `--results-dir` | `results/` | Directory for scan output |

---

## 📊 Live Dashboard

The scanner ships with a glassmorphism-styled web dashboard for real-time monitoring and review.

```bash
# Start the dashboard manually
python server.py

# Or it auto-starts when you run a scan (opens at http://localhost:8000)
```

**Dashboard features:**
- 📡 **Live monitoring** — auto-refresh during active scans
- 🔎 **Search** across repos, detectors, file paths
- 🏷️ **Severity filters** — CRITICAL / HIGH / MEDIUM / LOW
- ✅ **Verification status** — mark findings as Valid / Invalid
- 📁 **Upload JSON** — review offline scan results
- 🗂️ **Multi-scan selector** — browse all historical scan results

---

## 🗂️ Output Files

| File | Description |
|---|---|
| `results/scan_TIMESTAMP.json` | Full JSON results with all findings |
| `results/scan_TIMESTAMP_summary.txt` | Human-readable summary report |
| `results/stream_TIMESTAMP.ndjson` | Crash-safe streaming log (one finding per line) |
| `state.json` | Resume state (tracks cloned/failed repos) |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    github_secret_finder.py                  │
│                                                             │
│  Phase 1: Parse & validate repos.txt                        │
│      ↓                                                      │
│  Phase 2: Clone Workers (async, bounded queue)              │
│      ↓  [backpressure — scan_q.maxsize=15]                  │
│  Phase 3: Scan Workers (trufflehog filesystem)              │
│      ↓  [stream to NDJSON on every finding]                 │
│  Phase 4: Dedup + Severity Ranking                          │
│      ↓                                                      │
│  Phase 5: JSON + Summary Output                             │
└─────────────────────────────────────────────────────────────┘
         ↕ live_scan.json (every 3s)
┌─────────────────────────────────────────────────────────────┐
│          server.py  +  index.html  +  dashboard.js          │
│                  Live Web Dashboard :8000                   │
└─────────────────────────────────────────────────────────────┘
```

### Severity Scoring

| Detector | Score | Severity |
|---|---|---|
| AWS / GCP / Azure credentials | 100 | 🔴 CRITICAL |
| Private Keys | 95 | 🔴 CRITICAL |
| Stripe / DigitalOcean | 90 | 🔴 CRITICAL |
| GitHub / GitLab tokens | 85 | 🟠 HIGH |
| PostgreSQL / MySQL / MongoDB | 80 | 🟠 HIGH |
| Twilio / SendGrid | 70–75 | 🟠 HIGH |
| Generic API Keys | 50 | 🟡 MEDIUM |
| High-entropy strings | 30 | 🟢 LOW |

---

## 📄 repos.txt Format

One GitHub repo URL per line. Comments with `#` are ignored.

```
# Schuberg Philis repositories
https://github.com/schubergphilis/mcvs-golang-action
https://github.com/schubergphilis/terraform-aws-mcvs-cognito
https://github.com/schubergphilis/chef-workstation
```

---

## ⚠️ Legal & Ethics

> **Only use this tool against targets explicitly in scope for an authorized bug bounty program or with explicit written permission from the repository owner.**
>
> Unauthorized scanning of GitHub repositories may violate GitHub's Terms of Service and applicable computer crime laws. The author assumes no liability for misuse.

---

## 🛠️ Troubleshooting

**`trufflehog not found`**
```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
which trufflehog  # verify
```

**API rate limit hit (60 req/hr)**  
→ Add a `GITHUB_TOKEN` to `.env` to get 5000 req/hr

**Disk space issues**  
→ Tool auto-pauses when < 2 GB free. Use `--shallow-clone` to reduce disk usage.

**Want faster scans?**  
→ Increase `--scan-workers` (default: 6). trufflehog is CPU-bound, so don't exceed your CPU core count.

---

<div align="center">
Made with ❤️ for the bug bounty community
</div>
