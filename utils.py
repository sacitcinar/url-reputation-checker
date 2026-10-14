"""Shared URL parsing, HTTP transport, feed loading, and environment helpers.

Only provider-owned endpoints are contacted; never the submitted URL's origin.
"""
from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data'
USER_AGENT = 'URL-Reputation-Checker/1.0 (passive threat intelligence CLI)'
TIMEOUT = 10
# Fixed, vendored Public Suffix List snapshot (ICANN + PRIVATE sections).
# No application-time network access or background refresh.
PSL_PATH = DATA / 'public_suffix_list.dat'


@lru_cache(maxsize=1)
def suffix_rules() -> tuple[frozenset[str], frozenset[str]]:
    icann, private = set(), set()
    with PSL_PATH.open(encoding='utf-8') as stream:
        for line in stream:
            kind, _, name = line.strip().partition(' ')
            if not name:
                continue
            # Target hostnames are ASCII IDNA; normalize Unicode PSL rules
            # the same way so IDN suffixes match correctly.
            prefix = '!' if name.startswith('!') else '*.' if name.startswith('*.') else ''
            suffix = name[len(prefix):]
            try:
                name = prefix + suffix.encode('idna').decode('ascii').lower()
            except UnicodeError:
                continue
            if kind == 'ICANN':
                icann.add(name)
            elif kind == 'PRIVATE':
                private.add(name)
    return frozenset(icann), frozenset(private)


def public_suffix(host: str, *, include_private: bool = True) -> str:
    """PSL prevailing-rule lookup including wildcard and exception rules.

    Snapshot is static and packaged; unknown TLDs follow PSL '*' default.
    """
    labels = host.lower().rstrip('.').split('.')
    if not labels or not all(labels):
        return host
    official, private = suffix_rules()
    rules = official | private if include_private else official
    best = 1   # PSL default '*' rule
    for i in range(len(labels)):
        suffix = '.'.join(labels[i:])
        if '!' + suffix in rules:
            return '.'.join(labels[i + 1:])
        if suffix in rules:
            best = max(best, len(labels) - i)
        if i and '*.' + suffix in rules:
            best = max(best, len(labels) - i + 1)
    return '.'.join(labels[-best:])


class ProviderError(Exception):
    def __init__(self, status: str, message: str):
        self.status = status
        super().__init__(message)


def read_env() -> dict[str, str]:
    """Read local .env without dependency and without overwriting real environment."""
    values = {}
    path = ROOT / '.env'
    if path.is_file():
        for line in path.read_text('utf-8-sig').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key, value = key.strip(), value.strip()
            if value[:1] in ('"', "'") and value[-1:] == value[:1]:
                value = value[1:-1]
            if re.fullmatch(r'[A-Z][A-Z0-9_]*', key):
                values[key] = value
    # Actual environment takes precedence.
    return {**values, **os.environ}


def registered_domain(host: str, *, include_private: bool = True) -> str:
    """eTLD+1: include PRIVATE suffixes for tenant brand analysis."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.lower().rstrip('.').split('.')
    suffix_labels = public_suffix(host, include_private=include_private).split('.')
    if len(labels) <= len(suffix_labels):
        return host.lower().rstrip('.')
    return '.'.join(labels[-len(suffix_labels) - 1:])


# Recognized CTI defang forms. Refang ONLY the scheme and authority, never
# the path, query, fragment, credentials, or arbitrary text found in them.
_DEFANG_DOT = re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}|<\s*dot\s*>", re.I)
_DEFANG_COLON = re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)|\{\s*:\s*\}")
_DEFANG_PROTOCOLS = {'hxxp': 'http', 'hxxps': 'https', 'h[tt]p': 'http', 'h[tt]ps': 'https'}


def refang_url_host(value: str) -> str:
    """Restore common defanged scheme/authority forms without touching URL content.

    The return value is only text; this function makes no network requests.
    """
    protocol = re.match(r'^([A-Za-z\[\]]+)(?:(?::|\[\s*:\s*\]|\(\s*:\s*\)|\{\s*:\s*\})(?://|\[/\]|\(//\)|\{//\})|\[\s*://\s*\]|\(\s*://\s*\)|\{\s*://\s*\})', value, re.I)
    if not protocol:
        return value
    prefix = protocol.group(1)
    scheme = _DEFANG_PROTOCOLS.get(prefix.lower(), prefix.lower())
    if scheme not in ('http', 'https'):
        return value
    remainder = value[protocol.end():]
    match = re.match(r'([^/?#]*)(.*)', remainder, re.DOTALL)
    if match is None:
        return value
    authority, suffix = match.groups()
    # Do not change userinfo (which can contain phishing decoys).
    userinfo, at, host_port = authority.rpartition('@')
    # Brackets around an IPv6 literal are legal and must not be rewritten.
    host_port = _DEFANG_DOT.sub('.', host_port)
    host_port = _DEFANG_COLON.sub(':', host_port)
    authority = userinfo + at + host_port if at else host_port
    return scheme + '://' + authority + suffix


def rdap_registration_domain(host: str) -> tuple[str, bool]:
    """ICANN registry domain; PRIVATE hosting tenant age is unknown."""
    host = host.lower().rstrip('.')
    icann_domain = registered_domain(host, include_private=False)
    private_suffix = public_suffix(host, include_private=True)
    icann_suffix = public_suffix(host, include_private=False)
    tenant = (private_suffix != icann_suffix and host != private_suffix and
              host.endswith('.' + private_suffix))
    return icann_domain, tenant


def parse_target(raw: str) -> dict:
    value = (raw or '').strip()
    if not value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError('Invalid URL: empty or contains control characters')
    if len(value) > 8192:
        raise ValueError('Invalid URL: exceeds 8192 characters')
    # Accept recognized defanged schemes and authorities, retaining original input.
    refanged = refang_url_host(value)
    if not re.match(r'^https?://', refanged, re.I):
        raise ValueError('URL must begin with http(s):// or a supported defanged equivalent')
    try:
        parsed = urllib.parse.urlsplit(refanged)
        if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
            raise ValueError('Invalid HTTP(S) URL')
        host = parsed.hostname.rstrip('.').encode('idna').decode('ascii').lower()
        if len(host) > 253 or any(len(label) > 63 for label in host.split('.')):
            raise ValueError('Hostname length is invalid')
        if re.search(r'[^a-z0-9.:-]', host):
            raise ValueError('Hostname contains invalid characters')
        try:
            is_ip = ipaddress.ip_address(host).version in (4, 6)
        except ValueError:
            is_ip = False
        if not is_ip and ('.' not in host or any(not p or p.startswith('-') or p.endswith('-') for p in host.split('.'))):
            raise ValueError('Hostname is invalid')
        port = parsed.port
        base = f'[{host}]' if ':' in host else host
        if port is not None:
            base += f':{port}'
        # Userinfo retained for heuristics in raw, never embedded in the cleaned URL.
        path = parsed.path or '/'
        normalized = urllib.parse.urlunsplit((parsed.scheme.lower(), base, path, parsed.query, ''))
        return {'original': value, 'refanged_input': refanged, 'url': normalized, 'host': host, 'domain': registered_domain(host),
                'port': port, 'scheme': parsed.scheme.lower(), 'username': parsed.username,
                'is_ip': is_ip, 'path': path, 'query': parsed.query,
                'fragment': parsed.fragment, 'raw_netloc': parsed.netloc}
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f'Invalid URL: {exc}') from exc


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    """A provider may redirect only within its original HTTPS hostname."""
    def __init__(self, hostname: str):
        self.hostname = hostname

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != 'https' or (parsed.hostname or '').lower() != self.hostname:
            raise ProviderError('error', 'Unsafe provider redirect blocked before connection')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_json(url: str, *, method: str = 'GET', params: dict | None = None,
              headers: dict | None = None, payload: dict | None = None,
              form: dict | None = None) -> dict:
    """Read JSON from a deliberately selected trusted HTTPS provider endpoint."""
    if params:
        url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params)
    if not url.startswith('https://'):
        raise ProviderError('error', 'Blocked non-HTTPS provider endpoint')
    data = None
    hdr = {'User-Agent': USER_AGENT, 'Accept': 'application/json'}
    if headers:
        hdr.update(headers)
    if payload is not None:
        data = json.dumps(payload).encode('utf-8')
        hdr['Content-Type'] = 'application/json'
    elif form is not None:
        data = urllib.parse.urlencode(form).encode('utf-8')
        hdr['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(url, data=data, method=method, headers=hdr)
    try:
        with urllib.request.build_opener(_SameOriginRedirect((urllib.parse.urlsplit(url).hostname or '').lower())).open(req, timeout=TIMEOUT) as response:
            final_host = (urllib.parse.urlsplit(response.geturl()).hostname or '').lower()
            # Prevent provider redirects to the submitted target or unexpected origins.
            allowed = (urllib.parse.urlsplit(url).hostname or '').lower()
            if final_host != allowed:
                raise ProviderError('error', 'Provider redirected to an unexpected hostname')
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ProviderError('error', 'Provider response is too large')
            decoded = json.loads(raw.decode('utf-8'))
            if not isinstance(decoded, dict):
                raise ProviderError('error', 'Provider response must be a JSON object')
            # Some providers return an API-level error with HTTP 200. Never
            # misinterpret an error object as a clean/no-match result.
            if 'error' in decoded:
                detail = decoded['error']
                code = detail.get('code') if isinstance(detail, dict) else None
                label = str(detail.get('status', '')) if isinstance(detail, dict) else ''
                if str(code) == '429' or label == 'RESOURCE_EXHAUSTED':
                    raise ProviderError('rate_limited', 'Provider reported an API-level rate limit')
                if str(code) in ('401', '403') or label in ('PERMISSION_DENIED', 'UNAUTHENTICATED'):
                    raise ProviderError('auth_error', 'Provider denied the API request')
                raise ProviderError('error', 'Provider returned an API-level error')
            return decoded
    except urllib.error.HTTPError as exc:
        status = exc.code
        if status in (408, 504):
            raise ProviderError('timeout', f'Provider timed out (HTTP {status})') from exc
        if status == 429:
            raise ProviderError('rate_limited', 'Rate limit exceeded') from exc
        if status in (401, 403):
            raise ProviderError('auth_error', f'Authentication denied (HTTP {status})') from exc
        if status == 404:
            raise ProviderError('not_found', 'No existing record (HTTP 404)') from exc
        if status >= 500:
            raise ProviderError('unavailable', f'Service unavailable (HTTP {status})') from exc
        raise ProviderError('error', f'Provider returned HTTP {status}') from exc
    except (socket.timeout, TimeoutError) as exc:
        raise ProviderError('timeout', 'Provider timed out') from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ProviderError('unavailable', f'Provider connection failed: {type(exc).__name__}') from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProviderError('error', 'Provider returned malformed JSON') from exc


def result(source: str, status: str, match_type: str = 'none',
           details: dict | None = None, *, evidence: str = '',
           observed_at: str | None = None, message: str = '') -> dict:
    return {'source': source, 'status': status, 'match_type': match_type,
            'details': details or {}, 'evidence': evidence, 'observed_at': observed_at,
            'message': message, 'risk_points': 0}


def error_result(source: str, exc: Exception) -> dict:
    if isinstance(exc, ProviderError):
        return result(source, exc.status, message=str(exc))
    return result(source, 'error', message=f'{type(exc).__name__}: {exc}')


def iso_from_unix(ts) -> str | None:
    try:
        return dt.datetime.fromtimestamp(int(ts), tz=dt.timezone.utc).date().isoformat() if ts else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def feed_info(feed_id: str) -> dict:
    try:
        return json.loads((DATA / 'feeds' / 'metadata.json').read_text(encoding='utf-8')).get(feed_id, {})
    except (OSError, ValueError):
        return {}


def _canonical_unreserved(value: str) -> str:
    """Canonicalize percent escapes conservatively; never decode reserved chars.

    Preserve encoded dot/slash/backslash because security tools or servers may
    interpret them differently. Query order, separators and case stay intact.
    """
    def change(match: re.Match) -> str:
        code = match.group(1).upper()
        decoded = chr(int(code, 16))
        if decoded in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_~':
            return decoded
        return '%' + code
    return re.sub(r'%([0-9A-Fa-f]{2})', change, value)


def normalize_feed_url(value: str) -> str | None:
    """Conservative comparison key for exact URL evidence; no network calls.

    Normalize scheme, IDNA hostname, default port, unreserved percent escapes,
    and empty root path only. Preserve distinct paths and query strings. Never
    use rstrip('/') on the full URL: it destroys meaningful query values.
    """
    try:
        p = urllib.parse.urlsplit(value.strip())
        scheme = p.scheme.lower()
        if scheme not in ('http', 'https') or not p.hostname:
            return None
        host = p.hostname.rstrip('.').encode('idna').decode('ascii').lower()
        if not host or p.username is not None or p.password is not None:
            return None
        port = p.port
        if (scheme, port) in (('https', 443), ('http', 80)):
            port = None
        hostpart = f'[{host}]' if ':' in host else host
        if port is not None:
            hostpart += f':{port}'
        path = _canonical_unreserved(p.path or '/')
        query = _canonical_unreserved(p.query)
        return urllib.parse.urlunsplit((scheme, hostpart, path, query, ''))
    except (ValueError, UnicodeError):
        return None


@lru_cache(maxsize=4)
def load_feed(feed_id: str) -> tuple[frozenset, dict]:
    """Read locally bundled feeds only; no downloads or freshness checks."""
    names = {'openphish': 'openphish.txt', 'cert_polska': 'cert_polska.txt',
             'phishing_database': 'phishing_database.txt',
             'phishing_database_urls': 'phishing_database_urls.txt'}
    path = DATA / 'feeds' / names[feed_id]
    entries = set()
    try:
        with path.open('r', encoding='utf-8-sig') as stream:
            for line in stream:
                val = line.strip()
                if not val or val.startswith('#'):
                    continue
                if feed_id in ('openphish', 'phishing_database_urls'):
                    key = normalize_feed_url(val)
                    if key:
                        entries.add(key)
                else:
                    entries.add(val.lower().rstrip('.'))
    except OSError:
        pass
    return frozenset(entries), feed_info('phishing_database' if feed_id == 'phishing_database_urls' else feed_id)


def _snapshot_stale(snapshot_date) -> bool:
    if not snapshot_date:
        return True
    try:
        return (dt.datetime.now(dt.timezone.utc).date() - dt.date.fromisoformat(snapshot_date)).days > 30
    except (TypeError, ValueError):
        return True


def _domain_match(host: str, entries: frozenset) -> bool:
    # Match exactly the listed host or its subdomains, not arbitrary substring matches.
    pieces = host.split('.')
    return any('.'.join(pieces[i:]) in entries for i in range(max(0, len(pieces) - 1)))


def feed_lookup(feed_id: str, target: dict, scope: str) -> dict:
    entries, info = load_feed(feed_id)
    if feed_id == 'phishing_database':
        url_entries, _ = load_feed('phishing_database_urls')
        if not entries and not url_entries:
            return result(feed_id, 'unavailable', message='No local feed snapshots installed; no automatic download')
        url_match = normalize_feed_url(target['url']) in url_entries if url_entries else False
        domain_match = _domain_match(target['host'], entries) if entries else False
        match_type = 'url' if url_match else 'domain'
        # An absent subset must never be represented as a complete negative result.
        status = ('listed' if url_match or domain_match else
                  'not_listed' if entries and url_entries else 'unavailable')
        details = {'feed_entries': len(entries) + len(url_entries),
                   'domain_entries': len(entries), 'url_entries': len(url_entries),
                   'snapshot_date': info.get('snapshot_date'),
                   'age_warning': _snapshot_stale(info.get('snapshot_date')),
                   'userinfo_stripped_for_matching': bool(target.get('username') is not None or
                                                         '@' in target.get('raw_netloc', '')) and url_match}
        return result(feed_id, status, match_type if status == 'listed' else 'none',
                      details, evidence='Offline ACTIVE domain / exact URL snapshots',
                      observed_at=info.get('snapshot_date'),
                      message='One local dataset missing' if status == 'unavailable' else '')
    if not entries:
        return result(feed_id, 'unavailable', message='No local feed snapshot installed; no automatic download')
    if scope == 'url':
        matched = normalize_feed_url(target['url']) in entries
        match_type = 'url'
    else:
        matched = _domain_match(target['host'], entries)
        match_type = 'domain'
    return result(feed_id, 'listed' if matched else 'not_listed', match_type,
                  {'feed_entries': len(entries), 'snapshot_date': info.get('snapshot_date'),
                   'age_warning': _snapshot_stale(info.get('snapshot_date')),
                   'userinfo_stripped_for_matching': bool(target.get('username') is not None or
                                                         '@' in target.get('raw_netloc', '')) and matched if scope == 'url' else False},
                  evidence='Offline snapshot', observed_at=info.get('snapshot_date'))


def load_batch(path: Path) -> list[str]:
    if not path.is_file():
        raise ValueError(f'Input file not found: {path}')
    if path.suffix.lower() not in ('.txt', '.csv'):
        raise ValueError('Batch input must be a .txt or .csv file')
    if path.stat().st_size > 2_000_000:
        raise ValueError('Batch input is too large (2 MB maximum)')
    if path.suffix.lower() == '.txt':
        urls = [line.strip() for line in path.read_text('utf-8-sig').splitlines()
                if line.strip() and not line.lstrip().startswith('#')]
    else:
        with path.open('r', encoding='utf-8-sig', newline='') as handle:
            rows = list(csv.reader(handle))
        if not rows:
            raise ValueError('CSV file is empty')
        headers = [h.strip().lower() for h in rows[0]]
        index = headers.index('url') if 'url' in headers else 0
        start = 1 if 'url' in headers else 0
        urls = [row[index].strip() for row in rows[start:] if len(row) > index and row[index].strip()]
    if not urls:
        raise ValueError('No URLs found in input file')
    if len(urls) > 10000:
        raise ValueError('Batch is limited to 10,000 URLs')
    return urls
