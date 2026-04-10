#!/usr/bin/env python3
"""
GitHub Secrets Scanner — Bug Bounty Workflow
=============================================
Producer-consumer pipeline:
  Phase 1 : Parse & validate repos.txt
  Phase 2 : Clone workers  (I/O bound, default 5)
  Phase 3 : Scan workers   (CPU bound, default 6)
  Phase 4 : Dedup + severity ranking
  Phase 5 : JSON + summary output

USAGE:
  python scanner.py --input repos.txt
  python scanner.py --input repos.txt --clone-workers 3 --scan-workers 8
  python scanner.py --input repos.txt --resume
  python scanner.py --input repos.txt --keep-repos

REQUIREMENTS:
  - git        (in PATH)
  - trufflehog (in PATH)  ->  https://github.com/trufflesecurity/trufflehog

Only use against targets explicitly in scope for an authorized bug bounty program.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

# ── ANSI colors (disabled when not a tty) ───────────────────────────────────
_USE_COLOR = sys.platform != "win32" and sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

RED    = lambda t: _c("31", t)
GREEN  = lambda t: _c("32", t)
YELLOW = lambda t: _c("33", t)
CYAN   = lambda t: _c("36", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("2",  t)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scanner")

# ── Constants ────────────────────────────────────────────────────────────────
GITHUB_URL_RE  = re.compile(r"^https://github\.com/[\w.\-]+/[\w.\-]+(\.git)?$")
CLONE_RETRIES  = 3
RETRY_BASE_SEC = 2        # exponential backoff: 2s, 4s, 8s
DISK_MIN_GB    = 2.0      # pause cloning below this free-space threshold
DISK_CHECK_SEC = 10       # how often to re-check disk when paused
SCAN_TIMEOUT   = 300      # seconds before trufflehog is killed for a single repo
SHALLOW_DEPTH  = 50       # commits to fetch with --shallow-clone
SCAN_Q_MAX     = 15       # bounded scan queue — prevents cloning faster than scanning (backpressure)
STATE_FLUSH_INTERVAL = 10 # write state file every N clones instead of every single one
LIVE_WRITE_INTERVAL  = 3  # live_scan.json refresh interval in seconds (was 2)

# ── Severity map ─────────────────────────────────────────────────────────────
SEVERITY = {
    "AWS": 100, "GCP": 100, "Azure": 100, "DigitalOcean": 90,
    "Github": 85, "Gitlab": 85, "Bitbucket": 80,
    "Stripe": 90, "Braintree": 85, "Square": 85,
    "Twilio": 75, "SendGrid": 70, "Mailgun": 70,
    "PostgreSQL": 80, "MySQL": 80, "MongoDB": 80, "Redis": 70,
    "PrivateKey": 95, "JWT": 65,
    "GenericApiKey": 50, "HexHighEntropy": 30, "Base64HighEntropy": 30,
}

def severity_score(detector: str) -> int:
    for key, score in SEVERITY.items():
        if key.lower() in detector.lower():
            return score
    return 20


# ════════════════════════════════════════════════════════════════════════════
# Progress tracker
# ════════════════════════════════════════════════════════════════════════════

class Progress:
    def __init__(self, total: int):
        self.total        = total
        self.cloned       = 0
        self.clone_failed = 0
        self.scanned      = 0
        self.findings     = 0
        self._lock        = asyncio.Lock()
        self._start       = time.monotonic()

    async def inc_cloned(self):
        async with self._lock:
            self.cloned += 1
            self._render()

    async def inc_clone_failed(self):
        async with self._lock:
            self.clone_failed += 1
            self._render()

    async def inc_scanned(self, new_findings: int = 0):
        async with self._lock:
            self.scanned  += 1
            self.findings += new_findings
            self._render()

    def _render(self):
        elapsed = time.monotonic() - self._start
        bar_w   = 22
        done    = self.scanned + self.clone_failed
        filled  = int(bar_w * done / max(self.total, 1))
        bar     = "█" * filled + "░" * (bar_w - filled)
        line = (
            f"\r  {CYAN('cloned')} {self.cloned}/{self.total}"
            f"  {CYAN('scanned')} {self.scanned}/{self.total}"
            f"  [{bar}]"
            f"  {GREEN(str(self.findings) + ' findings')}"
            f"  {DIM(f'{elapsed:.0f}s')}"
            + "  "
        )
        print(line, end="", flush=True)

    def finish(self):
        print()


# ════════════════════════════════════════════════════════════════════════════
# Phase 1 — Parse & validate
# ════════════════════════════════════════════════════════════════════════════

def parse_repos(input_file: Path) -> list:
    if not input_file.exists():
        log.error("Input file not found: %s", input_file)
        sys.exit(1)

    raw = input_file.read_text(encoding="utf-8").splitlines()
    urls, bad = [], []

    for i, line in enumerate(raw, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.rstrip("/")
        if url.endswith(".git"):
            url = url[:-4]
        if GITHUB_URL_RE.match(url) or GITHUB_URL_RE.match(url + ".git"):
            urls.append(url)
        else:
            bad.append((i, line))

    if bad:
        log.warning("Skipping %d malformed URL(s):", len(bad))
        for lineno, url in bad:
            log.warning("  line %d: %s", lineno, url)

    # Deduplicate, preserve order
    seen, dedup = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            dedup.append(u)

    dupes = len(urls) - len(dedup)
    if dupes:
        log.info("Removed %d duplicate(s)", dupes)

    log.info("Loaded %d valid repos", len(dedup))
    return dedup


# ════════════════════════════════════════════════════════════════════════════
# State file — resume support
# ════════════════════════════════════════════════════════════════════════════

class StateFile:
    def __init__(self, path: Path):
        self.path     = path
        self._cloned  = set()
        self._failed  = set()
        self._dirty   = 0     # count of un-flushed writes
        if path.exists():
            data = json.loads(path.read_text())
            self._cloned = set(data.get("cloned", []))
            self._failed = set(data.get("failed", []))

    def is_cloned(self, url: str) -> bool:
        return url in self._cloned

    def mark_cloned(self, url: str):
        self._cloned.add(url)
        self._dirty += 1
        if self._dirty >= STATE_FLUSH_INTERVAL:
            self._flush()

    def mark_failed(self, url: str):
        self._failed.add(url)
        self._dirty += 1
        if self._dirty >= STATE_FLUSH_INTERVAL:
            self._flush()

    def _flush(self):
        self._dirty = 0
        self.path.write_text(json.dumps({
            "cloned": sorted(self._cloned),
            "failed": sorted(self._failed),
        }, indent=2))

    def flush_final(self):
        """Force a final flush at the end of the scan."""
        self._flush()

    def summary(self):
        return len(self._cloned), len(self._failed)


# ════════════════════════════════════════════════════════════════════════════
# Disk guard
# ════════════════════════════════════════════════════════════════════════════

async def wait_for_disk(repos_dir: Path):
    while True:
        stat    = shutil.disk_usage(repos_dir)
        free_gb = stat.free / (1024 ** 3)
        if free_gb >= DISK_MIN_GB:
            return
        log.warning(
            "Low disk space (%.1f GB free) — pausing clones for %ds …",
            free_gb, DISK_CHECK_SEC,
        )
        await asyncio.sleep(DISK_CHECK_SEC)


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════

def repo_dir_name(url: str) -> str:
    parts = url.rstrip("/").split("/")
    return f"{parts[-2]}__{parts[-1]}"


# ════════════════════════════════════════════════════════════════════════════
# Phase 2 — Clone worker
# ════════════════════════════════════════════════════════════════════════════

async def clone_worker(clone_q, scan_q, repos_dir, state, progress, resume, shallow_clone=False):
    while True:
        url = await clone_q.get()
        try:
            await wait_for_disk(repos_dir)
            name = repo_dir_name(url)
            dest = repos_dir / name

            # Resume: skip if already done
            if resume and state.is_cloned(url) and dest.exists():
                log.info("SKIP (already cloned): %s", name)
                await scan_q.put(dest)   # .put() blocks when scan_q is full — natural backpressure
                await progress.inc_cloned()
                continue

            if dest.exists():
                shutil.rmtree(dest)

            success = False
            for attempt in range(1, CLONE_RETRIES + 1):
                try:
                    log.info("Cloning [attempt %d/%d]: %s", attempt, CLONE_RETRIES, name)
                    clone_cmd = ["git", "clone", "--quiet"]
                    if shallow_clone:
                        clone_cmd += ["--depth", str(SHALLOW_DEPTH)]
                    clone_cmd += [url, str(dest)]
                    proc = await asyncio.create_subprocess_exec(
                        *clone_cmd,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _, stderr = await proc.communicate()
                    if proc.returncode == 0:
                        success = True
                        break
                    err = stderr.decode().strip()
                    log.warning("Clone attempt %d failed: %s — %s", attempt, name, err)
                    if attempt < CLONE_RETRIES:
                        wait = RETRY_BASE_SEC ** attempt
                        log.info("Retrying in %ds …", wait)
                        await asyncio.sleep(wait)
                except Exception as exc:
                    log.warning("Clone attempt %d exception: %s — %s", attempt, name, exc)

            if success:
                state.mark_cloned(url)
                await scan_q.put(dest)   # blocks when full — that's intentional
                await progress.inc_cloned()
            else:
                state.mark_failed(url)
                await progress.inc_clone_failed()
                log.error("FAILED after %d attempts: %s", CLONE_RETRIES, name)
        finally:
            clone_q.task_done()


# ════════════════════════════════════════════════════════════════════════════
# Phase 3 — Scan worker
# ════════════════════════════════════════════════════════════════════════════

def parse_trufflehog_output(raw: str) -> list:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return findings


async def scan_worker(scan_q, results, results_lock, keep_repos, progress, verified_only=False, result_stream_path=None):
    while True:
        repo_dir = await scan_q.get()
        try:
            name = repo_dir.name
            log.info("Scanning: %s", name)
            try:
                th_cmd = ["trufflehog", "filesystem", str(repo_dir), "--json", "--no-update"]
                if verified_only:
                    th_cmd.append("--only-verified")
                proc = await asyncio.create_subprocess_exec(
                    *th_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(), timeout=SCAN_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.communicate()  # ensure process is reaped
                    log.warning("trufflehog timed out on %s (>%ds) — skipping", name, SCAN_TIMEOUT)
                    await progress.inc_scanned(0)
                    continue
                if stderr_bytes:
                    log.debug("trufflehog stderr [%s]: %s",
                              name, stderr_bytes.decode(errors="replace").strip())
                raw_output = stdout.decode(errors="replace")
            except FileNotFoundError:
                log.error(
                    "trufflehog not found. Install: "
                    "https://github.com/trufflesecurity/trufflehog"
                )
                await progress.inc_scanned(0)
                continue
            except Exception as exc:
                log.error("trufflehog error on %s: %s", name, exc)
                await progress.inc_scanned(0)
                continue

            findings = parse_trufflehog_output(raw_output)
            for f in findings:
                f["_repo"] = name

            if findings:
                async with results_lock:
                    results.extend(findings)
                    # ── Stream findings immediately to disk so they are never lost ──
                    if result_stream_path:
                        try:
                            with open(result_stream_path, "a", encoding="utf-8") as fh:
                                for f in findings:
                                    fh.write(json.dumps(f) + "\n")
                        except Exception as exc:
                            log.debug("stream write error: %s", exc)

            count = len(findings)
            await progress.inc_scanned(count)

            if count:
                log.info(GREEN(f"  ★  {count} secret(s) in {name}"))

            # Cleanup — always delete repo unless keeping or has findings
            if not keep_repos:
                if count == 0:
                    shutil.rmtree(repo_dir, ignore_errors=True)
                else:
                    log.info("Keeping repo folder as evidence: %s", name)

        finally:
            scan_q.task_done()


# ════════════════════════════════════════════════════════════════════════════
# Phase 4 — Dedup + severity ranking
# ════════════════════════════════════════════════════════════════════════════

def dedup_and_rank(findings: list) -> list:
    seen = {}
    for f in findings:
        key = str(
            f.get("Raw") or f.get("raw") or
            f.get("RawV2") or f.get("raw_v2") or
            json.dumps(f, sort_keys=True)
        ).strip()
        if key not in seen:
            seen[key] = f

    unique = list(seen.values())
    unique.sort(
        key=lambda f: severity_score(
            f.get("DetectorName") or f.get("detector_name") or ""
        ),
        reverse=True,
    )
    return unique


# ════════════════════════════════════════════════════════════════════════════
# Phase 5 — Output
# ════════════════════════════════════════════════════════════════════════════

def sev_label(score: int) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 50: return "MEDIUM"
    return "LOW"


def write_outputs(findings, total_repos, elapsed, results_dir, ts):
    results_dir.mkdir(parents=True, exist_ok=True)

    # Full JSON
    json_path = results_dir / f"scan_{ts}.json"
    json_path.write_text(json.dumps({
        "meta": {
            "timestamp":      ts,
            "total_repos":    total_repos,
            "total_secrets":  len(findings),
            "elapsed_sec":    round(elapsed, 1),
        },
        "findings": findings,
    }, indent=2))
    log.info("Full results  -> %s", json_path)

    # Human-readable summary
    summary_path = results_dir / f"scan_{ts}_summary.txt"
    lines = [
        "=" * 62,
        "  GitHub Secrets Scanner — Summary",
        "=" * 62,
        f"  Timestamp     : {ts}",
        f"  Repos scanned : {total_repos}",
        f"  Secrets found : {len(findings)}",
        f"  Elapsed       : {elapsed:.1f}s",
        "=" * 62,
        "",
    ]

    if not findings:
        lines.append("  No secrets found.")
    else:
        by_repo = {}
        for f in findings:
            repo = f.get("_repo", "unknown")
            by_repo.setdefault(repo, []).append(f)

        for repo, rf in sorted(by_repo.items()):
            lines.append(f"  [{repo}]  {len(rf)} finding(s)")
            for f in rf:
                detector = f.get("DetectorName") or f.get("detector_name") or "Unknown"
                score    = severity_score(detector)
                label    = sev_label(score)
                # Try to extract a commit hash from SourceMetadata
                commit_h = ""
                meta = f.get("SourceMetadata") or {}
                data = meta.get("Data") or {}
                for v in (data.values() if isinstance(data, dict) else []):
                    if isinstance(v, dict) and "commit" in v:
                        commit_h = v["commit"][:8]
                        break
                lines.append(
                    f"    [{label:8s}] {detector}"
                    + (f"  commit:{commit_h}" if commit_h else "")
                )
            lines.append("")

    summary_path.write_text("\n".join(lines))
    log.info("Summary       -> %s", summary_path)

    # Print to terminal
    print()
    print("\n".join(lines))


# ════════════════════════════════════════════════════════════════════════════
# Prerequisite check
# ════════════════════════════════════════════════════════════════════════════

def check_prerequisites():
    missing = [t for t in ("git", "trufflehog") if shutil.which(t) is None]
    if missing:
        for t in missing:
            log.error("Required tool not in PATH: %s", t)
        if "trufflehog" in missing:
            log.error(
                "Install trufflehog from: "
                "https://github.com/trufflesecurity/trufflehog#installation"
            )
        sys.exit(1)


# ════════════════════════════════════════════════════════════════════════════
# Live Dashboard Writer
# ════════════════════════════════════════════════════════════════════════════

async def live_writer(results, results_lock, results_dir, total_repos, start_time, progress, clone_workers, scan_workers):
    live_path = results_dir / "live_scan.json"
    while True:
        await asyncio.sleep(LIVE_WRITE_INTERVAL)
        async with results_lock:
            # Only snapshot counts — do NOT serialize all findings every tick
            total_secrets = len(results)
            # Grab last 50 findings for the dashboard preview (not full list)
            preview = list(results[-50:])
        
        elapsed = time.monotonic() - start_time
        try:
            live_path.write_text(json.dumps({
                "meta": {
                    "timestamp": "LIVE",
                    "total_repos": total_repos,
                    "cloned": getattr(progress, 'cloned', 0),
                    "scanned": getattr(progress, 'scanned', 0),
                    "clone_workers": clone_workers,
                    "scan_workers": scan_workers,
                    "total_secrets": total_secrets,
                    "elapsed_sec": round(elapsed, 1),
                    "status": "running"
                },
                "findings": preview,
            }, indent=2))
        except Exception:
            pass


import subprocess
import atexit

# ════════════════════════════════════════════════════════════════════════════
# Main orchestrator
# ════════════════════════════════════════════════════════════════════════════

async def run(args):
    check_prerequisites()

    server_path = Path("server.py")
    dashboard_proc = None
    if server_path.exists():
        log.info("Starting dashboard server on http://localhost:8000 📡")
        dashboard_proc = subprocess.Popen(
            [sys.executable, str(server_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        def cleanup_server():
            if dashboard_proc and dashboard_proc.poll() is None:
                dashboard_proc.terminate()
        atexit.register(cleanup_server)

    input_file  = Path(args.input)
    repos_dir   = Path(args.repos_dir)
    results_dir = Path(args.results_dir)
    state_file  = Path(args.state_file)
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")

    repos_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Phase 1
    urls = parse_repos(input_file)
    if not urls:
        log.error("No valid URLs found. Exiting.")
        sys.exit(1)

    state    = StateFile(state_file)
    progress = Progress(len(urls))

    # Phase 2 — queues
    # clone_q: unbounded — all URLs are pre-loaded (just strings, tiny)
    # scan_q:  BOUNDED to SCAN_Q_MAX — provides backpressure so we never clone
    #          faster than we can scan (prevents disk/memory explosion)
    clone_q = asyncio.Queue()
    scan_q  = asyncio.Queue(maxsize=SCAN_Q_MAX)

    for url in urls:
        await clone_q.put(url)

    results      = []
    results_lock = asyncio.Lock()
    # Stream all findings to a NDJSON file as they arrive (crash-safe)
    stream_path  = results_dir / f"stream_{ts}.ndjson"

    print(BOLD(f"\n  Scanning {len(urls)} repos"))
    print(f"  Clone workers  : {args.clone_workers}")
    print(f"  Scan workers   : {args.scan_workers}")
    print(f"  Repos dir      : {repos_dir}")
    print(f"  Results dir    : {results_dir}")
    print(f"  Resume mode    : {args.resume}")
    print(f"  Keep repos     : {args.keep_repos}")
    print(f"  Verified only  : {args.verified_only}")
    print()

    start = time.monotonic()

    # Start live writer
    writer_task = asyncio.create_task(live_writer(
        results, results_lock, results_dir, len(urls), start, progress,
        getattr(args, 'clone_workers', 5), getattr(args, 'scan_workers', 6)
    ))

    # Start clone workers
    clone_tasks = [
        asyncio.create_task(clone_worker(
            clone_q, scan_q, repos_dir, state, progress, args.resume,
            shallow_clone=args.shallow_clone,
        ))
        for _ in range(args.clone_workers)
    ]

    # Start scan workers
    scan_tasks = [
        asyncio.create_task(scan_worker(
            scan_q, results, results_lock, args.keep_repos, progress,
            verified_only=args.verified_only,
            result_stream_path=stream_path,
        ))
        for _ in range(args.scan_workers)
    ]

    # Wait: all clones finish → all scans finish
    await clone_q.join()
    for t in clone_tasks:
        t.cancel()

    await scan_q.join()
    for t in scan_tasks:
        t.cancel()

    writer_task.cancel()
    
    # Remove live scan file at the end
    live_path = results_dir / "live_scan.json"
    if live_path.exists():
        try:
            live_path.unlink()
        except:
            pass

    progress.finish()
    elapsed = time.monotonic() - start

    # Phase 4
    log.info("Deduplicating %d raw findings …", len(results))
    unique = dedup_and_rank(results)
    log.info("Unique secrets after dedup: %d", len(unique))

    # Flush state one final time
    state.flush_final()

    # Phase 5
    write_outputs(unique, len(urls), elapsed, results_dir, ts)

    cloned_ok, cloned_fail = state.summary()
    print(BOLD(f"\n  Finished in {elapsed:.1f}s"))
    print(f"  Cloned OK  : {cloned_ok}")
    print(f"  Failed     : {cloned_fail}")
    print(f"  Secrets    : {GREEN(str(len(unique)))}\n")

    if dashboard_proc:
        print(GREEN(BOLD("  ✅ Dashboard is running at http://localhost:8000")))
        print("  Press Ctrl+C to stop the dashboard and exit.")
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        except KeyboardInterrupt:
            pass
        finally:
            if dashboard_proc.poll() is None:
                dashboard_proc.terminate()


# ════════════════════════════════════════════════════════════════════════════
# Fetch repos from a GitHub org page (no API key needed)
# ════════════════════════════════════════════════════════════════════════════

import html as _html
import urllib.request as _urllib_req
import urllib.error  as _urllib_err
import urllib.parse  as _urllib_parse

# Regex to extract repo hrefs from the rendered HTML
_REPO_HREF_RE = re.compile(
    r'href="/([\w.\-]+/[\w.\-]+)"[^>]*>\s*\n?\s*\1',
    re.MULTILINE,
)
# Simpler fallback: any /org/repo link inside an <a> that looks like a repo
_REPO_LINK_RE = re.compile(
    r'href="/([\w.\-]+/[\w.\-]+)"'
)

_GITHUB_BASE = "https://github.com"
_ORG_REPOS_RE = re.compile(
    r"github\.com/(?:orgs/)?([\w.\-]+)(?:/repositories)?/?$"
)


_GH_API_BASE = "https://api.github.com"


def _api_get(path: str, token: str | None, allow_404: bool = False) -> list | dict | None:
    """Call the GitHub REST API, return parsed JSON. Returns None on 404 if allow_404=True."""
    url = f"{_GH_API_BASE}{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = _urllib_req.Request(url, headers=headers)
    try:
        with _urllib_req.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except _urllib_err.HTTPError as e:
        if e.code == 404 and allow_404:
            return None   # caller will try a different endpoint
        log.error("GitHub API HTTP %d for %s", e.code, url)
        if e.code == 401:
            log.error("Bad or missing --token. Generate one at https://github.com/settings/tokens")
        sys.exit(1)
    except Exception as exc:
        log.error("Failed to call GitHub API %s: %s", url, exc)
        sys.exit(1)


def _fetch_html(url: str) -> str:
    """Fetch raw HTML from a URL with a browser-like User-Agent (fallback)."""
    req = _urllib_req.Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
    )
    try:
        with _urllib_req.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except _urllib_err.HTTPError as e:
        log.error("HTTP %d fetching %s", e.code, url)
        sys.exit(1)
    except Exception as exc:
        log.error("Failed to fetch %s: %s", url, exc)
        sys.exit(1)


def _extract_repos_from_html(html: str, org: str) -> list:
    """
    Parse GitHub org/repositories HTML and return full repo URLs.
    GitHub renders repo links as:  href="/org/repo-name"
    We collect all such hrefs where the first path segment matches the org
    and there is exactly one slash (i.e. org/repo, not org/repo/blob/...).
    """
    # Unescape HTML entities first
    html = _html.unescape(html)

    repos = set()
    for m in _REPO_LINK_RE.finditer(html):
        path = m.group(1)           # e.g.  "perfectscale-io/goose"
        parts = path.split("/")
        if len(parts) != 2:         # skip anything deeper than org/repo
            continue
        repo_org, repo_name = parts
        if repo_org.lower() != org.lower():
            continue
        # Skip special GitHub paths like ".github"
        if repo_name.startswith("."):
            continue
        repos.add(f"{_GITHUB_BASE}/{repo_org}/{repo_name}")

    return sorted(repos)


def _paginate_repos_from_api(endpoint_prefix: str, name: str, token: str | None) -> list:
    """
    Generic paginator: tries endpoint_prefix (e.g. /orgs or /users) and
    returns all public repos. Returns empty list if 404 (wrong type).
    """
    all_repos: set = set()
    page = 1
    while True:
        path = f"/{endpoint_prefix}/{name}/repos?per_page=100&page={page}&type=public"
        log.info("API [%s] page %d …", endpoint_prefix, page)
        data = _api_get(path, token, allow_404=True)
        if data is None:
            # 404 — this name is not an org (or not a user), signal caller
            return []  # type: ignore[return-value]
        if not isinstance(data, list) or not data:
            break
        for repo in data:
            full_name = repo.get("full_name", "")
            if full_name:
                all_repos.add(f"{_GITHUB_BASE}/{full_name}")
        log.info("  %d repo(s) on page %d (total: %d)", len(data), page, len(all_repos))
        if len(data) < 100:
            break
        page += 1
        time.sleep(0.3)
    return sorted(all_repos)


def _paginate_org_repos(org: str, token: str | None = None) -> list:
    """
    Fetch all public repos for a GitHub org OR user account.
    Tries the /orgs/ endpoint first; if that 404s, falls back to /users/.
    This handles companies that use a personal account instead of an org.
    """
    # Try org endpoint first
    repos = _paginate_repos_from_api("orgs", org, token)
    if repos:
        log.info("'%s' resolved as a GitHub Organization.", org)
        return repos

    # 404 on org — try user endpoint
    log.info("'%s' is not an org — trying as a user/personal account …", org)
    repos = _paginate_repos_from_api("users", org, token)
    if repos:
        log.info("'%s' resolved as a GitHub User account.", org)
        return repos

    log.warning("No public repos found for '%s' (tried org + user endpoints).", org)
    return []


def _resolve_org(source: str) -> str | None:
    """
    Parse an org/user slug from a URL or plain slug.
    Handles:
      - https://github.com/Payop?tab=repositories
      - https://github.com/Payop
      - https://github.com/orgs/Payop/repositories
      - Payop
    Returns None on failure.
    """
    # Strip query string (e.g. ?tab=repositories)
    source = source.strip().split("?")[0].rstrip("/")
    m = _ORG_REPOS_RE.search(source)
    if m:
        return m.group(1)
    if re.match(r"^[\w.\-]+$", source):
        return source
    return None


def cmd_fetch(args):
    """Subcommand: fetch repo URLs from one or more GitHub orgs into repos.txt."""
    token = getattr(args, "token", None) or os.environ.get("GITHUB_TOKEN")

    if not token:
        log.warning(
            "No --token provided. Using unauthenticated API (60 req/hr limit). "
            "Set --token or GITHUB_TOKEN env var for 5000 req/hr."
        )

    out_file = Path(args.output)

    # Merge with existing file if --append
    existing = set()
    if args.append and out_file.exists():
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                existing.add(line)
        log.info("Existing repos in output file: %d", len(existing))

    all_new_repos: set = set()
    orgs_fetched  = []

    for source in args.orgs:
        org = _resolve_org(source)
        if not org:
            log.error("Cannot parse org from: %s — skipping", source)
            continue

        log.info("Fetching repos for org: %s", org)
        repos = _paginate_org_repos(org, token=token)

        if not repos:
            log.warning("No public repos found for org '%s' — skipping.", org)
            continue

        print(BOLD(f"\n  [{org}]  {len(repos)} repo(s) found"))
        for r in repos:
            print(f"    {CYAN(r)}")

        all_new_repos.update(repos)
        orgs_fetched.append(org)

    if not all_new_repos and not existing:
        log.error("No repos collected from any org. Exiting.")
        sys.exit(1)

    combined = sorted(existing | all_new_repos)
    orgs_str  = ", ".join(orgs_fetched) if orgs_fetched else "(none)"

    header = (
        f"# GitHub Secrets Scanner — repos.txt\n"
        f"# Orgs fetched : {orgs_str}\n"
        f"# Date         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"# Total repos  : {len(combined)}\n\n"
    )

    out_file.write_text(header + "\n".join(combined) + "\n")

    print()
    print(BOLD(f"  Total repos collected : {len(all_new_repos)}"))
    if existing:
        new_count = len(all_new_repos - existing)
        print(f"  New repos added       : {new_count}")
        print(f"  Already in file       : {len(existing)}")
    print(f"  Written to            : {out_file}")
    print()

    if args.scan:
        log.info("--scan flag set — starting scan now …")
        args.input = args.output
        asyncio.run(run(args))


# ════════════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════════════

def main():  # noqa: C901
    # Auto-load .env file if it exists (no external libraries needed)
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ[key.strip()] = val.strip()

    p = argparse.ArgumentParser(
        description="GitHub Secrets Scanner — Bug Bounty Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    sub = p.add_subparsers(dest="command")

    # ── subcommand: fetch ────────────────────────────────────────────────────
    pf = sub.add_parser(
        "fetch",
        help="Fetch all repo URLs from a GitHub org page → repos.txt",
    )
    pf.add_argument(
        "orgs",
        nargs="+",
        help=(
            "One or more GitHub org slugs or URLs. Examples:\n"
            "  schubergphilis\n"
            "  schubergphilis stripe twilio\n"
            "  https://github.com/orgs/myorg/repositories"
        ),
    )
    pf.add_argument("--output",  default="repos.txt", help="Output file (default: repos.txt)")
    pf.add_argument("--append",  action="store_true", help="Append to existing file instead of overwriting")
    pf.add_argument("--scan",    action="store_true", help="Start scanning immediately after fetching")
    pf.add_argument("--token",   default=None, help="GitHub PAT for API access (or set GITHUB_TOKEN env var)")
    # Scan options (used when --scan is passed)
    pf.add_argument("--repos-dir",      default="repos",      help="Clone directory (default: repos/)")
    pf.add_argument("--results-dir",    default="results",    help="Results directory (default: results/)")
    pf.add_argument("--state-file",     default="state.json", help="Resume state file")
    pf.add_argument("--clone-workers",  type=int, default=3,  help="Clone workers (default: 3 — increase with caution on busy machines)")
    pf.add_argument("--scan-workers",   type=int, default=4,  help="Scan workers (default: 4 — trufflehog is CPU-heavy)")
    pf.add_argument("--resume",         action="store_true",  help="Skip already-cloned repos")
    pf.add_argument("--keep-repos",     action="store_true",  help="Never delete cloned repos")
    pf.add_argument("--shallow-clone",  action="store_true", default=True, help=f"Clone with --depth {SHALLOW_DEPTH} to save disk/time (default: ON)")
    pf.add_argument("--no-shallow-clone", dest="shallow_clone", action="store_false", help="Disable shallow clone (full history)")
    pf.add_argument("--scan-timeout",   type=int, default=SCAN_TIMEOUT, help=f"Seconds before trufflehog is killed (default: {SCAN_TIMEOUT})")
    pf.add_argument("--verified-only",  action="store_true",  help="Only report secrets trufflehog can actively verify (live credentials)")

    # ── subcommand: scan ─────────────────────────────────────────────────────
    ps = sub.add_parser(
        "scan",
        help="Scan repos listed in repos.txt",
    )
    ps.add_argument("--input",          default="repos.txt",  help="Path to repos.txt (default: repos.txt)")
    ps.add_argument("--repos-dir",      default="repos",      help="Clone directory (default: repos/)")
    ps.add_argument("--results-dir",    default="results",    help="Results directory (default: results/)")
    ps.add_argument("--state-file",     default="state.json", help="Resume state file")
    ps.add_argument("--clone-workers",  type=int, default=5,  help="Clone workers (default: 5)")
    ps.add_argument("--scan-workers",   type=int, default=6,  help="Scan workers (default: 6)")
    ps.add_argument("--resume",         action="store_true",  help="Skip already-cloned repos")
    ps.add_argument("--keep-repos",     action="store_true",  help="Never delete cloned repos")
    ps.add_argument("--shallow-clone",  action="store_true",  help=f"Clone with --depth {SHALLOW_DEPTH} to save disk/time")
    ps.add_argument("--scan-timeout",   type=int, default=SCAN_TIMEOUT, help=f"Seconds before trufflehog is killed (default: {SCAN_TIMEOUT})")
    ps.add_argument("--verified-only",  action="store_true",  help="Only report secrets trufflehog can actively verify (live credentials)")

    args = p.parse_args()

    # Apply --debug flag
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        log.debug("Debug logging enabled.")

    # Default: if no subcommand, show help
    if not args.command:
        server_path = Path("server.py")
        if server_path.exists():
            print(BOLD("\n  No subcommand provided, starting Dashboard Server ..."))
            print(GREEN(BOLD("  ✅ Dashboard is running at http://localhost:8000")))
            print("  Press Ctrl+C to stop the dashboard and exit.\n")
            try:
                import subprocess
                subprocess.run([sys.executable, str(server_path)])
            except KeyboardInterrupt:
                pass
            sys.exit(0)
        else:
            p.print_help()
            print("\nExamples:")
            print("  python scanner.py fetch schubergphilis stripe twilio --token ghp_xxx")
            print("  python scanner.py fetch schubergphilis --scan --verified-only")
            print("  python scanner.py scan --input repos.txt --verified-only")
            sys.exit(0)

    try:
        if args.command == "fetch":
            cmd_fetch(args)
        elif args.command == "scan":
            asyncio.run(run(args))
    except KeyboardInterrupt:
        print(f"\n{YELLOW('  Interrupted. Run scan with --resume to continue.')}\n")
        sys.exit(130)


if __name__ == "__main__":
    main()
