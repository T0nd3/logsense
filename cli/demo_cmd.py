"""Demo mode --shows how the tool looks with synthetic data.

No real log files, no Ollama, no database required.
Every section uses the same formatting as the real commands.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Annotated

import typer

app = typer.Typer(help="Guided demo of all major features using synthetic data.")

# ---------------------------------------------------------------------------
# Colours (mirrors main.py)
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    "low": typer.colors.CYAN,
    "medium": typer.colors.YELLOW,
    "high": typer.colors.RED,
    "critical": typer.colors.BRIGHT_RED,
    "debug": typer.colors.WHITE,
    "info": typer.colors.WHITE,
    "warning": typer.colors.YELLOW,
    "error": typer.colors.RED,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _h(title: str) -> None:
    """Print a section header."""
    width = 60
    typer.echo("\n" + typer.style("=" * width, fg=typer.colors.BRIGHT_BLUE))
    typer.echo(typer.style(f"  {title}", fg=typer.colors.BRIGHT_BLUE, bold=True))
    typer.echo(typer.style("=" * width, fg=typer.colors.BRIGHT_BLUE))


def _pause(no_pause: bool) -> None:
    if no_pause:
        typer.echo()
        return
    typer.echo(
        typer.style("\n  [Enter] to continue ...", fg=typer.colors.BRIGHT_BLACK),
        nl=False,
    )
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        typer.echo()


def _sev(s: str) -> str:
    return typer.style(s.upper().ljust(8), fg=_SEV_COLOR.get(s.lower(), typer.colors.WHITE))


def _ts(offset_minutes: int = 0) -> str:
    dt = datetime.now(tz=UTC) - timedelta(minutes=offset_minutes)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _stream_fake(text: str, delay: float = 0.012, no_pause: bool = False) -> None:
    """Simulate token-by-token LLM streaming."""
    if no_pause:
        typer.echo(text)
        return
    for word in text.split(" "):
        print(word + " ", end="", flush=True)
        time.sleep(delay)
    print()


# ---------------------------------------------------------------------------
# Synthetic data
# ---------------------------------------------------------------------------

_PARSE_LINES = [
    ("nginx",  "info",     180, '192.168.1.42 - alice [{}] "GET /api/health HTTP/1.1" 200 512'),
    ("nginx",  "error",    175, '10.0.0.5 - bob [{}] "POST /login HTTP/1.1" 401 193'),
    ("nginx",  "error",    170, '10.0.0.5 - bob [{}] "POST /login HTTP/1.1" 401 201'),
    ("nginx",  "error",    165, '10.0.0.5 - bob [{}] "POST /login HTTP/1.1" 401 198'),
    ("syslog", "warning",  160, '{} web01 sshd[3812]: Failed password for root from 203.0.113.9 port 44201 ssh2'),
    ("syslog", "warning",  155, '{} web01 sshd[3812]: Failed password for root from 203.0.113.9 port 44202 ssh2'),
    ("json",   "error",    150, '{{"ts":"{}","level":"ERROR","msg":"DB connection timeout","host":"db-prod-1","latency_ms":5200}}'),
    ("json",   "info",     145, '{{"ts":"{}","level":"INFO","msg":"Cache warmed up","keys":18342}}'),
    ("json",   "critical", 140, '{{"ts":"{}","level":"CRITICAL","msg":"Disk usage 97%","path":"/var/data","free_gb":1.2}}'),
]

_PII_EXAMPLES = [
    (
        'User john.doe@example.com logged in from 192.168.1.100',
        'User <EMAIL> logged in from <IP>',
    ),
    (
        'Payment processed: card 4111-1111-1111-1111 for $49.99, ref TXN-20240519-8821',
        'Payment processed: card <CREDIT_CARD> for $49.99, ref TXN-<NUM>-<NUM>',
    ),
    (
        'Password reset for user ID 83947, token=a3f9bc12d7e1',
        'Password reset for user ID <NUM>, token=<HASH>',
    ),
    (
        'API call from 10.0.0.44 failed --key sk-proj-aBcDeFgHiJkL was revoked',
        'API call from <IP> failed --key <API_KEY> was revoked',
    ),
]

_FINDINGS = [
    ("SSH_BRUTE_FORCE",        "critical", "web01",    150, "5 failed SSH login attempts for root from 203.0.113.9"),
    ("HTTP_AUTH_FAILURE_BURST","high",     "nginx",    170, "4 consecutive 401 responses from 10.0.0.5 to /login"),
    ("DISK_USAGE_CRITICAL",    "high",     "app-srv",  140, "Disk usage at 97% --free space 1.2 GB on /var/data"),
    ("DB_LATENCY_SPIKE",       "medium",   "db-prod-1",150, "Database query latency 5200 ms (threshold: 2000 ms)"),
]

_ERRORS = [
    ("a1b2c3d4", "ConnectionTimeout",   "error",    42,  "DB connection timeout",                      120, 5),
    ("e5f6a7b8", "DiskSpaceError",       "critical",  7,  "Disk usage 97% on /var/data",                140, 1),
    ("c9d0e1f2", "AuthenticationError", "error",    31,  "Failed password for invalid user root",       155, 3),
    ("f3a4b5c6", "HTTPError",           "warning",  18,  "HTTP 429 Too Many Requests from 10.0.0.5",    170, 2),
    ("d7e8f9a0", "SSLCertWarning",      "warning",   5,  "SSL certificate expires in 7 days",           180, 1),
]

_STORED_FINDINGS = [
    ("SSH_BRUTE_FORCE",         "critical", "auth.log",   "5 failed SSH logins for root"),
    ("HTTP_AUTH_FAILURE_BURST", "high",     "access.log", "4x 401 from same IP in 60s"),
    ("DISK_USAGE_CRITICAL",     "high",     "syslog",     "Disk at 97% on /var/data"),
]

_ANOMALY_FEATURES = [
    ("event_count",  4.8,  "events/min",  18.3),
    ("error_rate",   0.12, "errors/event", 0.61),
    ("http_5xx",     0.1,  "per min",      4.0),
]

_LLM_EXPLAIN = """\
The SSH brute-force finding indicates repeated failed authentication attempts \
targeting the root account from a single external IP address (203.0.113.9). \
This pattern is consistent with automated credential stuffing or dictionary \
attacks against the SSH service.

The most likely cause is an internet-facing SSH port being probed by an \
automated scanner. Root login over SSH should be disabled entirely \
(PermitRootLogin no in sshd_config) and access restricted to known IPs \
via firewall rules or fail2ban.

Immediate steps: block 203.0.113.9 at the firewall, verify no successful \
logins occurred, and rotate any credentials that may have been exposed.\
"""

_LLM_CLASSIFY = """\
LINE   1: [INFO]     Health check endpoint responding normally --no action needed.
LINE   2: [WARNING]  Repeated 401 responses may indicate brute-force attempt on /login.
LINE   3: [WARNING]  SSH login failures for root --potential scanning activity.
LINE   5: [ERROR]    Database connection timeout (5200 ms) --investigate DB load.
LINE   7: [CRITICAL] Disk at 97% --service disruption imminent without intervention.\
"""


# ---------------------------------------------------------------------------
# Demo command
# ---------------------------------------------------------------------------

@app.command("run")
def demo_run(
    no_pause: Annotated[bool, typer.Option("--no-pause", help="Print all sections without pausing.")] = False,
) -> None:
    """Run the full guided demo with synthetic data."""

    sep = "-" * 60

    # ── Intro ──────────────────────────────────────────────────────────────
    typer.echo(typer.style(r"""
  _                      _                _
 | |    ___   __ _      / \   _ __   __ _| |_   _ _______ _ __
 | |   / _ \ / _` |    / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 | |__| (_) | (_| |   / ___ \| | | | (_| | | |_| |/ /  __/ |
 |_____\___/ \__, |  /_/   \_\_| |_|\__,_|_|\__, /___\___|_|
             |___/                           |___/
""", fg=typer.colors.BRIGHT_BLUE))
    typer.echo("  Local log analysis with LLM support -- interactive demo\n")
    typer.echo("  All data is synthetic. No files, database, or LLM required.\n")
    _pause(no_pause)

    # ── 1. Log Parsing ─────────────────────────────────────────────────────
    _h("1 / 7  -- Log Parsing")
    typer.echo("\n  $ analyzer scan /var/log/app.log\n")
    typer.echo("  Formats auto-detected: nginx, syslog, json\n")

    typer.echo(f"  {'#':>6}  {'TIMESTAMP':<20} {'SEV':<8}  {'FORMAT':<8}  MESSAGE")
    typer.echo(f"  {'-'*6}  {'-'*20} {'-'*8}  {'-'*8}  {'-'*40}")

    for i, (fmt, sev, offset, tmpl) in enumerate(_PARSE_LINES, 1):
        ts = _ts(offset)
        msg = (tmpl.format(ts) if tmpl.count("{}") == 1 else tmpl)[:60]
        typer.echo(f"  [{i:>5}]  {ts}  {_sev(sev)}  {fmt:<8}  {msg}")

    typer.echo(f"\n  {sep}")
    typer.echo("  Source   : /var/log/app.log")
    typer.echo("  Format   : nginx / syslog / json (auto)")
    typer.echo(f"  Events   : {len(_PARSE_LINES):,}")
    typer.echo("  PII hits : 7 (mode: redact)")
    typer.echo("  Findings : 4")
    typer.echo(f"  {sep}")
    _pause(no_pause)

    # ── 2. PII Redaction ───────────────────────────────────────────────────
    _h("2 / 7  -- PII Redaction")
    typer.echo("\n  Sensitive data is detected and redacted before any processing.\n")

    for before, after in _PII_EXAMPLES:
        typer.echo(f"  {typer.style('BEFORE', fg=typer.colors.RED)}  {before}")
        typer.echo(f"  {typer.style('AFTER ', fg=typer.colors.GREEN)}  {after}")
        typer.echo()

    typer.echo("  Supported: emails, IPs, credit cards, API keys, JWTs, UUIDs,")
    typer.echo("             phone numbers, hashes, and custom regex rules.\n")
    typer.echo("  Modes: --redact (replace)  --mask (****)  --dry-run (report only)")
    _pause(no_pause)

    # ── 3. Rule Engine ─────────────────────────────────────────────────────
    _h("3 / 7  -- Rule Engine & Findings")
    typer.echo("\n  Detection rules match patterns in parsed events.")
    typer.echo("  Built-in rules cover: brute-force, injection, anomalies, policy.\n")

    typer.echo(f"  Findings ({len(_FINDINGS)}):\n")
    for rule_id, sev, source, offset, message in _FINDINGS:
        ts = _ts(offset)
        color = _SEV_COLOR.get(sev, typer.colors.WHITE)
        line = f"  [{sev.upper()}] {ts}  {rule_id}  {message}"
        typer.echo(typer.style(line, fg=color))

    typer.echo("\n  Rule formats supported: YAML (native) and Sigma.")
    typer.echo("  Custom rules: analyzer rules validate my_rule.yml")
    typer.echo("  List rules  : analyzer rules list")
    _pause(no_pause)

    # ── 4. Error Tracking ──────────────────────────────────────────────────
    _h("4 / 7  -- Error Tracking  (--track-errors)")
    typer.echo("\n  Errors are deduplicated by fingerprint and persisted to SQLite.\n")
    typer.echo("  $ analyzer errors list\n")

    typer.echo("  5 error types  (103 total occurrences)\n")
    typer.echo(f"  {'FINGERPRINT':<14} {'SEV':<10} {'COUNT':>6}  {'LAST SEEN':<20} TYPE")
    typer.echo(f"  {'-'*14} {'-'*10} {'-'*6}  {'-'*20} {'-'*30}")

    for fp, etype, sev, count, msg, offset, sources in _ERRORS:
        color = _SEV_COLOR.get(sev, typer.colors.WHITE)
        sev_label = typer.style(sev.upper().ljust(10), fg=color)
        typer.echo(
            f"  {fp:<14} {sev_label} {count:>6}  {_ts(offset):<20} {etype}"
        )

    typer.echo("\n  Extras: analyzer errors show <fp>  |  analyzer errors new --since 24h")
    typer.echo("          analyzer errors regression  (errors that reappeared after silence)")
    _pause(no_pause)

    # ── 5. Finding Persistence ─────────────────────────────────────────────
    _h("5 / 7  -- Finding Persistence  (HIGH / CRITICAL)")
    typer.echo("\n  HIGH and CRITICAL findings are stored to SQLite automatically.")
    typer.echo("  Re-scanning the same file never creates duplicates.\n")
    typer.echo("  $ analyzer findings list\n")

    typer.echo("  3 finding(s) total --showing 3\n")
    typer.echo(f"  {'SEV':<10} {'RULE':<28} {'SOURCE':<20} {'WHEN':<20} MESSAGE")
    typer.echo(f"  {'-'*10} {'-'*28} {'-'*20} {'-'*20} {'-'*35}")

    for rule_id, sev, source, message in _STORED_FINDINGS:
        color = _SEV_COLOR.get(sev, typer.colors.WHITE)
        sev_label = typer.style(sev.upper().ljust(10), fg=color)
        typer.echo(
            f"  {sev_label} {rule_id:<28} {source:<20} {_ts(140):<20} {message[:45]}"
        )

    typer.echo("\n  Auto-cleanup: findings older than 30 days are deleted on each scan.")
    typer.echo("  Configure   : findings_retention_days / findings_min_severity in config.yaml")
    typer.echo("\n  $ analyzer findings summary")

    typer.echo(f"\n  {sep[:50]}")
    typer.echo("  Total findings : 3")
    typer.echo("\n  By severity:")
    typer.echo(f"    {typer.style('CRITICAL  ', fg=typer.colors.BRIGHT_RED)}     1")
    typer.echo(f"    {typer.style('HIGH      ', fg=typer.colors.RED)}     2")
    typer.echo("\n  Top rules by occurrence:")
    for rule_id, sev, source, message in _STORED_FINDINGS:
        color = _SEV_COLOR.get(sev, typer.colors.WHITE)
        sev_label = typer.style(sev.upper().ljust(10), fg=color)
        typer.echo(f"  {rule_id:<30} {sev_label}     1")
    typer.echo(f"  {sep[:50]}")
    _pause(no_pause)

    # ── 6. Anomaly Detection ───────────────────────────────────────────────
    _h("6 / 7  -- Statistical Anomaly Detection")
    typer.echo("\n  Detects unusual activity by comparing current metrics to a baseline.")
    typer.echo("  Baseline is built automatically from previous scans (>=5 buckets).\n")
    typer.echo("  $ analyzer scan app.log --detect-anomalies\n")

    typer.echo("  Anomaly detected -- source: app.log\n")
    typer.echo(f"  {'FEATURE':<18} {'BASELINE':>10}  {'CURRENT':>10}  {'Z-SCORE':>8}  STATUS")
    typer.echo(f"  {'-'*18} {'-'*10}  {'-'*10}  {'-'*8}  {'-'*15}")

    for feature, baseline, unit, current in _ANOMALY_FEATURES:
        zscore = round((current - baseline) / max(baseline * 0.3, 0.01), 1)
        flag = typer.style("[ANOMALY]", fg=typer.colors.BRIGHT_RED) if abs(zscore) >= 3 else typer.style("ok", fg=typer.colors.GREEN)
        typer.echo(
            f"  {feature:<18} {baseline:>9.1f}   {current:>9.1f}   {zscore:>+7.1f}  {flag}"
        )

    typer.echo(f"\n  >> Finding: [HIGH] Anomaly in error_rate (z=+4.1) at {_ts(140)}")
    typer.echo("\n  Training:  analyzer anomaly learn app.log")
    typer.echo("  Status:    analyzer anomaly status")
    typer.echo("  Reset:     analyzer anomaly reset --source app.log")
    _pause(no_pause)

    # ── 7. LLM Integration ────────────────────────────────────────────────
    _h("7 / 7  -- LLM Integration")
    typer.echo("\n  Supported providers: Ollama (local), Claude, OpenAI, Groq,")
    typer.echo("  Mistral, LM Studio, and any OpenAI-compatible API.\n")

    # llm info
    typer.echo("  $ analyzer llm info\n")
    typer.echo(f"  {sep[:55]}")
    typer.echo("  Provider : ollama")
    typer.echo("  Model    : gemma3:4b")
    typer.echo("  Embed    : nomic-embed-text (via ollama)")
    typer.echo(f"  Cloud    : {typer.style('No --fully local', fg=typer.colors.GREEN)}")
    typer.echo(f"  Status   : {typer.style('ONLINE', fg=typer.colors.GREEN)}")
    typer.echo("\n  Locally available models (3):")
    typer.echo("  * gemma3:4b")
    typer.echo("    llama3.2:3b")
    typer.echo("    nomic-embed-text")
    typer.echo(f"  {sep[:55]}")

    # llm explain
    typer.echo("\n  $ analyzer llm explain a1b2c3d4\n")
    typer.echo("  Explaining [a1b2c3d4] SSH_BRUTE_FORCE ...\n")
    typer.echo("  Provider: ollama  Model: gemma3:4b\n")
    typer.echo("-" * 55)
    _stream_fake(_LLM_EXPLAIN, no_pause=no_pause)
    typer.echo("-" * 55)

    # scan --classify
    typer.echo("\n  $ analyzer scan app.log --classify\n")
    typer.echo("  LLM classification (9 event sample, model: gemma3:4b):\n")
    typer.echo("-" * 55)
    _stream_fake(_LLM_CLASSIFY, delay=0.008, no_pause=no_pause)
    typer.echo("-" * 55)

    # llm ask
    typer.echo('\n  $ analyzer llm ask "any brute force attempts this week?"\n')
    typer.echo("  Q: any brute force attempts this week?")
    typer.echo("  Provider: ollama  Context: 3 chunk(s) (keyword)\n")
    typer.echo("-" * 55)
    _stream_fake(
        "Yes --SSH_BRUTE_FORCE fired twice this week targeting root from 203.0.113.9. "
        "42 authentication failures were recorded across auth.log. "
        "The IP has not successfully authenticated. Recommend blocking via firewall.",
        no_pause=no_pause,
    )
    typer.echo("-" * 55)
    _pause(no_pause)

    # ── Outro ──────────────────────────────────────────────────────────────
    _h("Demo complete")
    typer.echo("""
  Quick-start:

    analyzer scan /var/log/syslog --track-errors --detect-anomalies
    analyzer errors list
    analyzer findings list
    analyzer llm info
    analyzer llm explain <fingerprint>
    analyzer llm ask "what happened last night?"

  Configuration (config.yaml):

    llm:
      provider: ollama          # or: claude, openai, groq, mistral, lm_studio
      model: gemma3:4b
      api_key: ...              # for cloud providers (or set env var)
    findings_retention_days: 30
    findings_min_severity: high

  Run this demo again:  analyzer demo run
  Run without pauses:   analyzer demo run --no-pause
""")
