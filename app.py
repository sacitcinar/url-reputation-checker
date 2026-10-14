#!/usr/bin/env python3
"""URL Reputation Checker: key-optional, passive, stdlib-only CLI."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import tempfile
import urllib.parse
from pathlib import Path
import re
import shutil
import sys
import textwrap

from heuristics import analyze_url
from scoring import assess
from sources import SOURCE_NAMES, SOURCE_ORDER, collect_sources
import utils
import sources
from utils import load_batch, parse_target, read_env, result

VERSION = '1.3.0'
THREAT_NAMES = SOURCE_ORDER[:8]
DOMAIN_NAMES = ['abuseipdb', 'rdap', 'dns', 'asn_geo']


class TTY:
    def __init__(self, disabled: bool = False):
        self.enabled = (not disabled and 'NO_COLOR' not in os.environ and
                        sys.stdout.isatty() and os.environ.get('TERM', '').lower() != 'dumb')
        self.width = max(64, min(110, shutil.get_terminal_size((88, 24)).columns))

    def color(self, value, shade: str, bold: bool = False) -> str:
        if not self.enabled:
            return str(value)
        colors = {'red': '31', 'yellow': '33', 'green': '32', 'cyan': '36',
                  'gray': '90', 'white': '37', 'orange': '33'}
        return f'\033[{"1;" if bold else ""}{colors.get(shade, "37")}m{value}\033[0m'

    def line(self, char='─') -> str:
        return self.color(char * self.width, 'gray')

    def section(self, name: str) -> None:
        print('\n' + self.color(name.upper(), 'cyan', bold=True))
        print(self.color('─' * min(38, self.width), 'gray'))


def safe_text(value) -> str:
    """Replace control characters supplied by external providers or input URL."""
    string = str(value if value is not None else '-')
    string = ''.join(ch if ch.isprintable() else '?' for ch in string)
    return string.replace('\x1b', '?')


def compact(value, width: int = 90) -> str:
    text = safe_text(value)
    return text if len(text) <= width else text[:max(10, width - 3)] + '...'


def status_text(record: dict) -> tuple[str, str]:
    state = record.get('status')
    details = record.get('details') or {}
    name = record.get('source')
    if state == 'skipped':
        return ('Skipped: ' + (record.get('message') or 'Not applicable'), 'gray')
    if state == 'unavailable':
        return ('Unavailable: ' + (record.get('message') or 'Service unavailable'), 'gray')
    if state == 'auth_error':
        return ('Authentication failed', 'yellow')
    if state == 'rate_limited':
        return ('Rate limit exceeded', 'yellow')
    if state == 'timeout':
        return ('Timeout', 'yellow')
    if state == 'error':
        return ('Error: ' + (record.get('message') or 'Unknown provider error'), 'yellow')
    if state == 'partial':
        if name == 'dns':
            failed = ', '.join(details.get('failed_types') or [])
            return (f'Partial DNS ({len(details.get("ips") or [])} IPs; failed: {failed})', 'yellow')
        if name == 'asn_geo':
            return (f'Partial: {len(details.get("ips") or [])} IP record(s)', 'yellow')
        if name == 'abuseipdb':
            return (f'Partial: {len(details.get("ips") or [])} IP(s) assessed', 'yellow')
        return ('Partial result', 'yellow')
    if state == 'not_found':
        return ('Not found (no existing intelligence)', 'gray')
    if state == 'not_listed':
        return ('Not listed', 'green')
    if state == 'listed':
        if name == 'google_safe_browsing':
            threats = ', '.join(details.get('threat_types') or [])
            return ('Threat match: ' + threats, 'red')
        if name == 'urlhaus':
            return (f'Listed / {details.get("url_status") or "status unknown"}', 'red')
        if name == 'phishtank':
            label = 'Verified phishing' if details.get('verified') else 'Unverified listing'
            return (label + (' / active' if details.get('valid') else ' / inactive or unknown'), 'red')
        return ('Listed (' + record.get('match_type', 'unknown') + ' match)', 'red')
    if name == 'virustotal':
        return (f'{details.get("malicious", 0)}/{details.get("total_engines", 0)} malicious / {details.get("suspicious", 0)} suspicious',
                'red' if details.get('malicious', 0) else ('yellow' if details.get('suspicious', 0) else 'green'))
    if name == 'urlscan':
        v = details.get('malicious')
        return ('Archived scan: ' + ('malicious' if v else ('not malicious' if v is False else 'verdict unavailable')),
                'red' if v else 'gray')
    if name == 'abuseipdb':
        entries = details.get('ips') or []
        score = max([int(x.get('abuse_confidence_score') or 0) for x in entries] or [0])
        return (f'{len(entries)} IP(s), max abuse confidence {score}/100',
                'red' if score >= 90 else ('yellow' if score >= 20 else 'cyan'))
    if name == 'rdap':
        age = details.get('age_days')
        if details.get('shared_hosting'):
            return ('Shared hosting: tenant domain age unknown', 'cyan')
        return (f'Registered domain age: {age} days' if age is not None else 'Registration age unavailable',
                'yellow' if age is not None and age < 30 else 'cyan')
    if name == 'dns':
        return (f'{len(details.get("ips") or [])} resolved IP(s)', 'cyan')
    if name == 'asn_geo':
        return (f'{len(details.get("ips") or [])} IP record(s)', 'cyan')
    if name == 'heuristics':
        score = details.get('heuristic_score', 0)
        return (f'{details.get("indicator_count", 0)} indicators / {score}/6 points',
                'yellow' if score else 'cyan')
    return (state or 'Unknown', 'gray')


def print_source(name: str, record: dict, ui: TTY, index: int) -> None:
    display = SOURCE_NAMES.get(name, name)
    message, color = status_text(record)
    space = max(24, min(29, ui.width // 3))
    print('  ' + ui.color(f'{index:02}. {display:<{space}}', 'white') +
          ui.color(compact(message, ui.width - space - 7), color))
    d = record.get('details') or {}
    lines = []
    if name == 'virustotal' and record['status'] == 'completed':
        counts = d.get('total_engines', 0)
        community = d.get('reputation')
        votes = d.get('total_votes') or {}
        lines.append(f'Engines: {counts} | Community reputation: {community if community is not None else "N/A"}'
                     f' | Votes: {votes.get("malicious", 0)} malicious, {votes.get("harmless", 0)} harmless')
        lines.append(f'Last analysis: {d.get("last_analysis_date") or "Unknown"}')
        if d.get('malicious_engines'):
            names = d['malicious_engines']
            lines.append('Malicious engines: ' + ', '.join(names[:6]) +
                         (f' (+{len(names) - 6} more)' if len(names) > 6 else ''))
        if d.get('suspicious_engines'):
            names = d['suspicious_engines']
            lines.append('Suspicious engines: ' + ', '.join(names[:4]) +
                         (f' (+{len(names) - 4} more)' if len(names) > 4 else ''))
    elif name == 'rdap' and record['status'] == 'completed':
        lines.append(f'Registered domain: {d.get("domain") or "Unknown"} | Registered: {d.get("created_at") or "Unknown"}')
        if d.get('shared_hosting'):
            lines.append('Platform registration only; tenant creation date unknown, no age-risk points')
    elif name == 'dns' and record['status'] in ('completed', 'partial'):
        lines.append(f'IP addresses: {", ".join(d.get("ips") or []) or "None returned"}')
        types = d.get('records') or {}
        lines.append('DNS counts: ' + ', '.join(f'{k}={len(v)}' for k, v in types.items()))
    elif name == 'abuseipdb' and record['status'] in ('completed', 'partial'):
        lines += [f'{i.get("ip")}: abuse={i.get("abuse_confidence_score")}/100, reports={i.get("total_reports")}'
                  for i in d.get('ips') or []]
    elif name == 'asn_geo' and record['status'] in ('completed', 'partial'):
        lines += [f'{i.get("ip")}: AS{i.get("asn") or "?"} | {i.get("org") or i.get("isp") or "Unknown"} | {i.get("country") or "Unknown"}'
                  for i in d.get('ips') or []]
    if name in ('asn_geo', 'abuseipdb') and record['status'] in ('completed', 'partial'):
        if d.get('unqueried'):
            lines.append(f'Unqueried IPs: {d["unqueried"]} (IP lookup limit)')
        for failed in d.get('failed_ips') or []:
            lines.append(f'{failed.get("ip")}: {failed.get("status")} ({failed.get("reason")})')
    if name == 'dns' and record['status'] == 'partial' and d.get('failed_types'):
        lines.append('Failed DNS record types: ' + ', '.join(d['failed_types']))
    if name == 'urlscan' and record['status'] == 'completed':
        lines.append(f'Existing scans: {d.get("historical_scans", 0)} | Last scan: {d.get("scan_time") or "Unknown"}')
        if d.get('verdict_note'):
            lines.append(d['verdict_note'])
        if d.get('search_complete') is False:
            lines.append('WARNING: Historical search was incomplete; older matches may exist')
    if name in ('openphish', 'cert_polska', 'phishing_database') and record['status'] in ('listed', 'not_listed'):
        lines.append(f'Local snapshot: {d.get("snapshot_date") or "Unknown date"} | Entries: {d.get("feed_entries", 0)}')
        if name == 'phishing_database':
            lines.append(f'Domain entries: {d.get("domain_entries", 0)} | URL entries: {d.get("url_entries", 0)}')
        if d.get('age_warning'):
            lines.append('WARNING: Snapshot is undated or older than 30 days')
    for line in lines:
        print('      ' + ui.color(compact(line, ui.width - 9), 'gray'))


def print_analysis(report: dict, ui: TTY, index: int | None = None, total: int | None = None) -> None:
    print('\n' + ui.line())
    print(ui.color('  URL REPUTATION CHECKER', 'cyan', bold=True) +
          (ui.color(f'   [{index}/{total}]', 'gray') if index is not None and total else ''))
    print(ui.line())
    print(ui.color('TARGET URL', 'white', bold=True))
    print('  ' + safe_text(report.get('url', '')))
    if report.get('original_url') and report['original_url'] != report['url']:
        print('  ' + ui.color('Original input: ' + safe_text(report['original_url']), 'gray'))
    if report.get('error'):
        ui.section('Input validation')
        print('  ' + ui.color(report['error'], 'red'))
        ui.section('Final assessment')
        print('  Risk Score : N/A')
        print('  Verdict    : ' + ui.color('UNKNOWN', 'gray', bold=True))
        print('  Coverage   : None')
        return

    records = report['sources']
    ui.section('Threat intelligence')
    for i, name in enumerate(THREAT_NAMES, 1):
        print_source(name, records[name], ui, i)
    ui.section('Domain & IP intelligence')
    for i, name in enumerate(DOMAIN_NAMES, len(THREAT_NAMES) + 1):
        print_source(name, records[name], ui, i)
    ui.section('URL heuristics')
    print_source('heuristics', report['heuristics'], ui, 13)
    for indicator in report['heuristics']['details'].get('indicators', []):
        shade = 'yellow' if indicator.get('points') else 'gray'
        print('    ' + ui.color('• ' + compact(indicator.get('type'), 25) + ': ' +
              compact(indicator.get('detail'), ui.width - 38), shade))
    ui.section('Key findings')
    for finding in report['assessment']['evidence'][:8]:
        print('  ' + ui.color('•', 'cyan') + ' ' + compact(finding, ui.width - 5))
    ui.section('Final assessment')
    score = report['assessment']['risk_score']
    verdict = report['assessment']['verdict']
    shade = ('red' if verdict == 'MALICIOUS' else 'orange' if verdict == 'HIGH RISK'
             else 'yellow' if verdict == 'SUSPICIOUS' else 'green' if verdict == 'LIKELY SAFE' else 'gray')
    print('  Risk Score : ' + ui.color(f'{score}/100', shade, bold=True))
    print('  Verdict    : ' + ui.color(verdict, shade, bold=True))
    print('  Coverage   : ' + ui.color(report['assessment']['coverage'], 'cyan') +
          f' ({report["assessment"]["coverage_sources"]} live URL reputation sources; '
          f'{len(report["assessment"]["offline_snapshot_sources"])} recent offline snapshots)')
    print('  ' + ui.color('Risk score is not a probability. No match does not prove safety.', 'gray'))


def _redact_sensitive_path(path: str) -> str:
    """Mask values after known secret-bearing path keys in report presentation.

    This cannot detect arbitrary embedded secrets and does not modify provider
    requests. Query values are still masked regardless of parameter name.
    """
    parts = path.split('/')
    keys = {'token', 'access_token', 'apikey', 'api_key', 'session',
            'sessionid', 'secret', 'password', 'bearer', 'authorization'}
    for i in range(1, len(parts)):
        if parts[i - 1].lower() in keys and parts[i]:
            parts[i] = '[REDACTED]'
    return '/'.join(parts)


def redact_url(value: str) -> str:
    """For reports only: strip userinfo/fragments and mask ALL query values.

    This is display/storage redaction, not a guarantee that path segments lack
    secrets. It does not change which exact URL providers are asked to check.
    """
    try:
        refanged = utils.refang_url_host(str(value))
        parsed = urllib.parse.urlsplit(refanged)
        if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
            return '[REDACTED URL]'
        # Keep original text for ordinary defanged input when safe, otherwise
        # normalize before removing credentials.
        original = str(value)
        masked_path = _redact_sensitive_path(parsed.path)
        if ('?' not in original and '@' not in parsed.netloc and '#'
                not in original and masked_path == parsed.path):
            return original
        host_port = parsed.netloc.rpartition('@')[-1]
        masked_query = '&'.join(
            segment.partition('=')[0] + '=[REDACTED]' if '=' in segment
            else '[REDACTED]' for segment in parsed.query.split('&')
        ) if parsed.query else ''
        return urllib.parse.urlunsplit((parsed.scheme, host_port, masked_path,
                                        masked_query, ''))
    except (ValueError, UnicodeError):
        return '[REDACTED URL]'


def make_report(raw: str, env: dict, *, offline: bool = False,
                providers: set[str] | None = None, redact_secrets: bool = False) -> dict:
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    try:
        target = parse_target(raw)
    except ValueError as exc:
        return {'url': redact_url(raw) if redact_secrets else raw,
                'analyzed_at': now, 'error': str(exc),
                'assessment': {'risk_score': None, 'verdict': 'UNKNOWN', 'coverage': 'None'}}
    records = collect_sources(target, env, offline=offline, providers=providers)
    heuristic = analyze_url(target)
    assessment = assess(records, heuristic)
    return {'url': redact_url(target['url']) if redact_secrets else target['url'],
            'original_url': redact_url(raw) if redact_secrets else raw,
            'host': target['host'], 'registered_domain': target['domain'],
            'analyzed_at': now, 'sources': records, 'heuristics': heuristic,
            'assessment': assessment, 'redacted': redact_secrets}


def md_escape(value) -> str:
    return safe_text(value).replace('\\', '\\\\').replace('|', '\\|').replace('`', '\\`')


def render_markdown(reports: list[dict]) -> str:
    lines = ['# URL Reputation Checker Report', '',
             '> Passive threat intelligence: no target URLs were visited.', '']
    for n, report in enumerate(reports, 1):
        lines += [f'## {n}. `{md_escape(report["url"])}`', '',
                  f'- Analyzed (UTC): {md_escape(report["analyzed_at"])}', '']
        if report.get('error'):
            lines += ['**Input Error:** ' + md_escape(report['error']), '']
            continue
        if report.get('original_url') != report['url']:
            lines += [f'- Original input: `{md_escape(report["original_url"])}`', '']
        lines += ['### Threat Intelligence & Infrastructure', '',
                  '| Source | Status | Result | Risk points |',
                  '|---|---|---|---:|']
        for name in SOURCE_ORDER:
            record = report['sources'][name]
            caption = status_text(record)[0]
            lines.append(f'| {md_escape(SOURCE_NAMES[name])} | {md_escape(record["status"])} | '
                         f'{md_escape(caption)} | {record.get("risk_points", 0)} |')
        hr = report['heuristics']
        lines += [f'| URL Heuristics | completed | {hr["details"]["indicator_count"]} indicators | {hr.get("risk_points", 0)} |',
                  '', '### Evidence', '']
        for finding in report['assessment']['evidence']:
            lines.append('- ' + md_escape(finding))
        lines += ['', '### Final Assessment', '',
                  f'**Risk Score:** {report["assessment"]["risk_score"]}/100  ',
                  f'**Verdict:** {report["assessment"]["verdict"]}  ',
                  f'**Coverage:** {report["assessment"]["coverage"]}  ',
                  f'**Live sources:** {len(report["assessment"]["live_reputation_sources"])}  ',
                  f'**Recent offline snapshots:** {len(report["assessment"]["offline_snapshot_sources"])}  ',
                  '', '**Note:** No result, missing key, or failed lookup does not imply a safe URL.', '']
    return '\n'.join(lines) + '\n'


def report_json(reports: list[dict]) -> str:
    return json.dumps({'tool': 'URL Reputation Checker', 'version': VERSION,
                       'reports': reports}, ensure_ascii=False, indent=2) + '\n'


def save_report(path: Path, reports: list[dict]) -> None:
    """Atomically write files with owner-only permissions on POSIX (0600)."""
    if path.suffix.lower() == '.json':
        content = report_json(reports)
    elif path.suffix.lower() == '.md':
        content = render_markdown(reports)
    else:
        raise ValueError('Output extension must be .json or .md')
    temp_path = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix='.urlcheck-', suffix='.tmp', dir=str(path.parent))
        temp_path = Path(temp_name)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Passive URL reputation checker. No target URL visits.')
    parser.add_argument('target', help='HTTP(S) URL, .txt list, or .csv file with url column')
    parser.add_argument('-o', '--output', metavar='FILE', help='Save additional .json or .md report')
    parser.add_argument('--no-color', action='store_true', help='Disable terminal ANSI colors')
    parser.add_argument('--redact-secrets', action='store_true',
                        help='Mask query values and remove URL credentials/fragments from displayed/saved reports')
    parser.add_argument('--offline', action='store_true', help='Only local threat feeds and heuristics; no network queries')
    parser.add_argument('--providers', metavar='NAMES',
                        help='Comma-separated provider IDs to query (other sources marked skipped)')
    parser.add_argument('--timeout', type=float, metavar='SEC', default=10,
                        help='Per-request provider network timeout (default: 10 seconds)')
    parser.add_argument('--json-stdout', action='store_true',
                        help='Emit report JSON to stdout, without terminal banners')
    parser.add_argument('--fail-on-risk', choices=['SUSPICIOUS', 'HIGH', 'MALICIOUS'],
                        help='Return exit status 3 if URL reaches the selected severity or higher')
    parser.add_argument('--fail-on-unknown', action='store_true',
                        help='Return exit status 4 when a URL verdict is UNKNOWN (optional fail-closed CI policy)')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args(argv)
    if args.output and Path(args.output).suffix.lower() not in ('.json', '.md'):
        parser.error('-o requires a .json or .md filename')
    if not 0 < args.timeout <= 120:
        parser.error('--timeout requires a number > 0 and <= 120')
    utils.TIMEOUT = args.timeout
    sources.TIMEOUT = args.timeout
    selected = None
    if args.providers is not None:
        selected = {v.strip().lower() for v in args.providers.split(',') if v.strip()}
        bad = selected - set(SOURCE_ORDER)
        if not selected or bad:
            parser.error('--providers must list valid IDs: ' + ', '.join(SOURCE_ORDER))
    ui = TTY(disabled=args.no_color or args.json_stdout)
    env = read_env()
    is_file = (Path(args.target).is_file() and
               Path(args.target).suffix.lower() in ('.txt', '.csv'))
    try:
        candidates = load_batch(Path(args.target)) if is_file else [args.target]
    except (ValueError, OSError, UnicodeError) as exc:
        print(ui.color('[!] ' + safe_text(exc), 'red'), file=sys.stderr)
        return 2
    reports = []
    for index, url in enumerate(candidates, 1):
        try:
            report = make_report(url, env, offline=args.offline,
                                 providers=selected, redact_secrets=args.redact_secrets)
        except Exception as exc:
            # Unexpected failure still does not stop the batch. Avoid URL/token
            # leakage when --redact-secrets is enabled.
            report = {'url': redact_url(url) if args.redact_secrets else url,
                      'analyzed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                      'error': f'Analysis failed: {type(exc).__name__}',
                      'assessment': {'risk_score': None, 'verdict': 'UNKNOWN', 'coverage': 'None'}}
        reports.append(report)
        if not args.json_stdout:
            print_analysis(report, ui, index if is_file else None,
                           len(candidates) if is_file else None)
    if args.json_stdout:
        sys.stdout.write(report_json(reports))
    elif is_file:
        counts = {name: sum(r['assessment']['verdict'] == name for r in reports)
                  for name in ('MALICIOUS', 'HIGH RISK', 'SUSPICIOUS', 'LIKELY SAFE', 'UNKNOWN')}
        ui.section('Batch analysis summary')
        print(f'  Total URLs : {len(reports)}')
        for name, count in counts.items():
            print(f'  {name:<13}: {count}')
    if args.output:
        try:
            save_report(Path(args.output), reports)
            if not args.json_stdout:
                print('\n' + ui.color(f'[+] Report saved to: {args.output}', 'green'))
        except OSError as exc:
            print('\n' + ui.color(f'[!] Failed to save report: {exc}', 'red'), file=sys.stderr)
            return 1
    if any(r.get('error') for r in reports):
        return 1
    if args.fail_on_risk:
        levels = {'UNKNOWN': -1, 'LIKELY SAFE': 0, 'SUSPICIOUS': 1,
                  'HIGH RISK': 2, 'MALICIOUS': 3}
        min_level = {'SUSPICIOUS': 1, 'HIGH': 2, 'MALICIOUS': 3}[args.fail_on_risk]
        if any(levels[r['assessment']['verdict']] >= min_level for r in reports):
            return 3
    if args.fail_on_unknown and any(r['assessment']['verdict'] == 'UNKNOWN' for r in reports):
        return 4
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
