"""Passive provider integrations. No submitted target is ever fetched or scanned.

All HTTP requests go to known intelligence provider endpoints only. Missing
credentials never stop other lookups. Offline feeds are never refreshed.
"""
from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import re
import socket
import time
import threading
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import (ProviderError, TIMEOUT, USER_AGENT, error_result, feed_lookup,
                   http_json, iso_from_unix, registered_domain, rdap_registration_domain,
                   normalize_feed_url, result)

SOURCE_ORDER = [
    'virustotal', 'google_safe_browsing', 'urlhaus', 'openphish',
    'phishtank', 'cert_polska', 'urlscan', 'phishing_database',
    'abuseipdb', 'rdap', 'dns', 'asn_geo',
]
SOURCE_NAMES = {
    'virustotal': 'VirusTotal', 'google_safe_browsing': 'Google Safe Browsing',
    'urlhaus': 'URLhaus', 'openphish': 'OpenPhish', 'phishtank': 'PhishTank',
    'cert_polska': 'CERT Polska', 'urlscan': 'urlscan.io',
    'phishing_database': 'Phishing.Database', 'abuseipdb': 'AbuseIPDB',
    'rdap': 'RDAP / Domain Age', 'dns': 'DNS Analysis',
    'asn_geo': 'ASN / Geolocation',
}
API_ENV = {
    'virustotal': 'VIRUSTOTAL_API_KEY',
    'google_safe_browsing': 'GOOGLE_SAFE_BROWSING_API_KEY',
    'urlhaus': 'URLHAUS_AUTH_KEY',
    'abuseipdb': 'ABUSEIPDB_API_KEY',
}


def virustotal(target: dict, env: dict) -> dict:
    """Retrieve an EXISTING VirusTotal URL report; never submit/rescan a URL.

    Uses the documented API v3 URL object. Treat unavailable, incomplete,
    and undated reports as inconclusive rather than as clean verdicts.
    """
    key = env.get('VIRUSTOTAL_API_KEY', '').strip()
    if not key:
        return result('virustotal', 'skipped', message='API key not configured')
    # VirusTotal accepts unpadded URL-safe base64 as the URL identifier.
    vt_id = base64.urlsafe_b64encode(target['url'].encode('utf-8')).decode('ascii').rstrip('=')
    data = http_json('https://www.virustotal.com/api/v3/urls/' + vt_id,
                     headers={'x-apikey': key})
    attributes = (data.get('data') or {}).get('attributes')
    if not isinstance(attributes, dict):
        raise ProviderError('error', 'Malformed VirusTotal URL object')
    stats = attributes.get('last_analysis_stats')
    if not isinstance(stats, dict) or not stats:
        return result('virustotal', 'not_found', 'url',
                      message='URL record exists, but no prior analysis statistics')

    keys = ('malicious', 'suspicious', 'harmless', 'undetected', 'timeout')
    counts = {}
    for name in keys:
        try:
            number = int(stats.get(name, 0))
        except (TypeError, ValueError, OverflowError) as exc:
            raise ProviderError('error', f'Invalid VirusTotal {name} count') from exc
        if number < 0:
            raise ProviderError('error', f'Negative VirusTotal {name} count')
        counts[name] = number

    votes = attributes.get('total_votes') or {}
    if not isinstance(votes, dict):
        votes = {}
    detections = attributes.get('last_analysis_results') or {}
    if not isinstance(detections, dict):
        detections = {}
    malicious_names, suspicious_names = [], []
    for engine, values in detections.items():
        if not isinstance(values, dict):
            continue
        category = values.get('category')
        if category == 'malicious':
            malicious_names.append(str(engine))
        elif category == 'suspicious':
            suspicious_names.append(str(engine))
    malicious_names.sort(key=str.casefold)
    suspicious_names.sort(key=str.casefold)
    analyzed = iso_from_unix(attributes.get('last_analysis_date'))
    details = {**counts,
               'total_engines': sum(counts.values()),
               'reputation': attributes.get('reputation'),
               'total_votes': {k: votes.get(k, 0) for k in ('harmless', 'malicious')},
               'last_analysis_date': analyzed,
               'malicious_engines': malicious_names,
               'suspicious_engines': suspicious_names,
               'engine_details_available': bool(detections)}
    return result('virustotal', 'completed', 'url', details,
                  evidence='Existing VirusTotal URL report; no scan requested',
                  observed_at=analyzed,
                  message='Historical analysis date missing' if not analyzed else '')


def google_safe_browsing(target: dict, env: dict) -> dict:
    key = env.get('GOOGLE_SAFE_BROWSING_API_KEY', '').strip()
    if not key:
        return result('google_safe_browsing', 'skipped', message='API key not configured')
    body = {'client': {'clientId': 'url-reputation-checker', 'clientVersion': '1.0'},
            'threatInfo': {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING',
                                           'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                           'platformTypes': ['ANY_PLATFORM'],
                           'threatEntryTypes': ['URL'],
                           'threatEntries': [{'url': target['url']}]}}
    data = http_json('https://safebrowsing.googleapis.com/v4/threatMatches:find',
                     method='POST', params={'key': key}, payload=body)
    if 'error' in data:
        raise ProviderError('error', 'Google Safe Browsing API returned an error object')
    # GSB v4 returns {} for no match, or a list of matches. Unexpected fields
    # and malformed entries are errors, not a clean reputation signal.
    if data and 'matches' not in data:
        raise ProviderError('error', 'Unexpected Google Safe Browsing response fields')
    matches = data.get('matches', [])
    if not isinstance(matches, list) or any(
        not isinstance(m, dict) or not isinstance(m.get('threatType'), str)
        or not m.get('threatType') for m in matches
    ):
        raise ProviderError('error', 'Malformed Google Safe Browsing matches')
    return result('google_safe_browsing', 'listed' if matches else 'not_listed', 'url',
                  {'threat_types': sorted({m['threatType'] for m in matches}),
                   'matches': len(matches)}, evidence='Live Google Safe Browsing lookup')


def urlhaus(target: dict, env: dict) -> dict:
    key = env.get('URLHAUS_AUTH_KEY', '').strip()
    if not key:
        return result('urlhaus', 'skipped', message='API key not configured')
    data = http_json('https://urlhaus-api.abuse.ch/v1/url/', method='POST',
                     headers={'Auth-Key': key}, form={'url': target['url']})
    status = data.get('query_status')
    if status == 'no_results':
        return result('urlhaus', 'not_listed', 'url', evidence='Existing URLhaus record lookup')
    if status != 'ok':
        return result('urlhaus', 'unavailable', message=f'Unexpected API status: {str(status)[:80]}')
    threat = str(data.get('threat') or '')
    activity = str(data.get('url_status') or '')
    return result('urlhaus', 'listed', 'url', {'threat': threat, 'url_status': activity,
                    'date_added': data.get('date_added'), 'tags': data.get('tags') or []},
                  evidence='Recorded malware URL', observed_at=data.get('date_added'))


def openphish(target: dict, env: dict) -> dict:
    return feed_lookup('openphish', target, 'url')


def cert_polska(target: dict, env: dict) -> dict:
    return feed_lookup('cert_polska', target, 'domain')


def phishing_database(target: dict, env: dict) -> dict:
    return feed_lookup('phishing_database', target, 'domain')


def _api_bool(value, field: str) -> bool:
    if type(value) is bool:
        return value
    if isinstance(value, str) and value.lower() in ('true', 'false', 'yes', 'no'):
        return value.lower() in ('true', 'yes')
    raise ProviderError('error', f'PhishTank returned invalid {field} flag')


def phishtank(target: dict, env: dict) -> dict:
    """Read existing PhishTank records; app_key is OPTIONAL upstream.

    Anonymous requests have stricter rate limits, which are surfaced as errors
    rather than being interpreted as negative results. No URL submission.
    """
    key = env.get('PHISHTANK_API_KEY', '').strip()
    form = {'url': target['url'], 'format': 'json'}
    if key:
        form['app_key'] = key
    response = http_json('https://checkurl.phishtank.com/checkurl/', method='POST',
                         form=form,
                         headers={'User-Agent': USER_AGENT + ' (PhishTank URL lookup)'})
    meta = response.get('meta')
    if isinstance(meta, dict) and str(meta.get('status', 'success')).lower() != 'success':
        raise ProviderError('unavailable', 'PhishTank did not return a successful lookup')
    values = response.get('results')
    if not isinstance(values, dict) or 'in_database' not in values:
        raise ProviderError('error', 'Malformed PhishTank response: missing in_database')
    listed = _api_bool(values['in_database'], 'in_database')
    if not listed:
        return result('phishtank', 'not_listed', 'url',
                      {'authenticated': bool(key)}, evidence='PhishTank existing-record lookup')
    if 'verified' not in values or 'valid' not in values:
        raise ProviderError('error', 'Incomplete PhishTank listing: missing verified/valid')
    verified = _api_bool(values['verified'], 'verified')
    online = _api_bool(values['valid'], 'valid')
    return result('phishtank', 'listed', 'url',
                  {'verified': verified, 'valid': online, 'authenticated': bool(key),
                   'verified_at': values.get('verified_at'), 'phish_id': values.get('phish_id')},
                  evidence='PhishTank existing URL record', observed_at=values.get('verified_at'))


URLSCAN_PAGE_SIZE = 100
URLSCAN_MAX_PAGES = 5  # Bound search calls; never conceal truncated search coverage.


def _urlscan_verdict(row: dict) -> bool | None:
    """Extract explicit verdicts only; missing/incompatible is unknown."""
    verdicts = row.get('verdicts')
    overall = verdicts.get('overall') if isinstance(verdicts, dict) else None
    if isinstance(overall, dict) and type(overall.get('malicious')) is bool:
        return overall['malicious']
    fallback = row.get('verdict')
    if isinstance(fallback, dict) and type(fallback.get('malicious')) is bool:
        return fallback['malicious']
    return None


def urlscan(target: dict, env: dict) -> dict:
    """Search historic records only. Never POST a new scan or visit the target.

    An exact task URL match is required, using the same conservative URL
    equivalence rules as local feeds. A capped/incomplete search isn't evidence
    that the URL has never been scanned.
    """
    key = env.get('URLSCAN_API_KEY', '').strip()
    headers = {'api-key': key} if key else {}
    # Validate and quote hostname in Elasticsearch query-string syntax.
    host = target['host'].replace('\\', '\\\\').replace('"', '\\"')
    query = 'task.domain.keyword:"' + host + '"'
    requested = normalize_feed_url(target['url'])
    same_url, domain_only = [], 0
    pagination, previous_cursor, complete = None, None, False
    searched = 0
    pagination_error = None
    sanitized_userinfo = bool(target.get('username') is not None or '@' in target.get('raw_netloc', ''))
    for page_no in range(URLSCAN_MAX_PAGES):
        params = {'q': query, 'size': URLSCAN_PAGE_SIZE}
        if pagination:
            params['search_after'] = pagination
        try:
            payload = http_json('https://urlscan.io/api/v1/search/', params=params,
                                headers=headers)
        except ProviderError as exc:
            if page_no == 0:
                raise  # no valid data to preserve
            pagination_error = exc.status
            break
        try:
            matches = payload.get('results')
            if not isinstance(matches, list):
                raise ProviderError('error', 'urlscan search returned malformed results')
            # Validate the WHOLE page before incorporating any of its rows.
            validated = []
            for row in matches:
                if not isinstance(row, dict):
                    raise ProviderError('error', 'urlscan search contained an invalid record')
                scanned = row.get('task') or {}
                page = row.get('page') or {}
                if not isinstance(scanned, dict) or not isinstance(page, dict):
                    raise ProviderError('error', 'urlscan search record structure is invalid')
                validated.append((row, scanned, page))
        except ProviderError as exc:
            if page_no == 0:
                raise
            pagination_error = exc.status
            break
        searched += len(matches)
        for row, scanned, page in validated:
            candidate = normalize_feed_url(str(scanned.get('url') or ''))
            if candidate is not None and candidate == requested:
                same_url.append(row)
            elif str(page.get('domain') or scanned.get('domain') or '').lower() == target['host']:
                domain_only += 1
        # urlscan returns newest first. The first page already contains the
        # newest exact scan, but paginate to provide accurate bounded coverage.
        if not matches:
            complete = True
            break
        total = payload.get('total')
        total_more = (isinstance(total, int) and total > searched)
        # Some accounts may have smaller per-page quotas. Never assume that
        # a short page exhausts history when the API reports more records.
        if (((len(matches) < URLSCAN_PAGE_SIZE and not total_more) or
             (isinstance(total, int) and searched >= total))
                and not payload.get('has_more')):
            complete = True
            break
        last_sort = matches[-1].get('sort')
        if not isinstance(last_sort, (list, tuple)) or not last_sort or not all(
            isinstance(x, (str, int, float)) for x in last_sort
        ):
            break
        pagination = ','.join(str(value) for value in last_sort)
        if pagination == previous_cursor:
            break
        previous_cursor = pagination
    else:
        # Ran through the capped final page; potentially more entries.
        complete = False
    if not same_url:
        state = 'not_found' if complete else 'partial'
        return result('urlscan', state, 'none',
                      {'domain_scans_found': domain_only, 'results_examined': searched,
                       'search_complete': complete, 'pagination_error': pagination_error,
                       'userinfo_stripped_for_matching': sanitized_userinfo},
                      message=('No matching historical scan; no new scan submitted' if complete
                               else 'Search incomplete; exact URL may have older records' +
                               (f' ({pagination_error})' if pagination_error else '')))
    latest = sorted(same_url, key=lambda d: (d.get('task') or {}).get('time', ''), reverse=True)[0]
    # Do not let a newer inconclusive/benign scan erase older confirmed
    # *exact-URL* malicious findings. The dates remain visible for review.
    positives = [row for row in same_url if _urlscan_verdict(row) is True]
    most_recent_positive = max(
        ((row.get('task') or {}).get('time') or '' for row in positives),
        default=None)
    verdict = _urlscan_verdict(latest)
    scan_id = latest.get('_id') or (latest.get('task') or {}).get('uuid')
    verdict_note = ''
    if verdict is None and isinstance(scan_id, str) and re.fullmatch(
        r'[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}', scan_id
    ):
        # GET only: archived result, NEVER the submitted URL itself.
        try:
            archive = http_json('https://urlscan.io/api/v1/result/' + scan_id + '/',
                                headers=headers)
            verdict = _urlscan_verdict(archive)
        except ProviderError as exc:
            verdict_note = f'Existing result details unavailable: {exc.status}'
    return result('urlscan', 'completed', 'url',
                  {'historical_scans': len(same_url), 'domain_scans_found': domain_only,
                   'malicious': verdict, 'scan_time': (latest.get('task') or {}).get('time'),
                   'scan_id': scan_id, 'results_examined': searched,
                   'historical_malicious': bool(positives),
                   'last_malicious_scan_time': most_recent_positive,
                   'search_complete': complete, 'pagination_error': pagination_error,
                   'userinfo_stripped_for_matching': sanitized_userinfo,
                   'verdict_note': verdict_note},
                  evidence='Previously submitted scan metadata; exact task URL match',
                  observed_at=(latest.get('task') or {}).get('time'),
                  message=verdict_note)


def _rdap_redirect_host_allowed(raw_hostname: str, forbidden_host: str) -> bool:
    """Reject unsafe/misleading names before touching the network.

    RDAP.org's bootstrap can send to authoritative registries, so require
    a registry/RDAP service hostname rather than arbitrary web origins.
    """
    try:
        hostname = raw_hostname.rstrip('.').encode('idna').decode('ascii').lower()
        submitted = forbidden_host.rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        return False
    if not hostname or hostname.endswith(('.localhost', '.local', '.internal', '.test', '.invalid', '.example')):
        return False
    if hostname in ('localhost', 'local', 'internal', 'test', 'invalid', 'example'):
        return False
    # Block literal addresses entirely, including IPv6 and encoded legacy IPv4.
    try:
        ipaddress.ip_address(hostname.strip('[]'))
        return False
    except ValueError:
        pass
    if (hostname.replace('.', '').isdigit() or
            any(part.startswith('0x') for part in hostname.split('.')) or
            any(part.isdigit() and len(part) > 1 and part.startswith('0')
                for part in hostname.split('.'))):
        return False
    if not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', hostname):
        return False
    parent = registered_domain(submitted, include_private=False)
    if (hostname == submitted or hostname.endswith('.' + submitted) or
            hostname == parent or hostname.endswith('.' + parent)):
        return False
    # Do not accept redirects to arbitrary user-owned websites.
    # Valid registries can use e.g. rdap.example, ccrdap.example, nic.example,
    # pubapi.registry.google. Fail closed on uncommon endpoint names.
    labels = hostname.split('.')
    service_labels = labels[:-1]
    rdap_style = any('rdap' in label or label in ('whois', 'nic', 'registry', 'pubapi')
                     for label in service_labels)
    return rdap_style


class _RdapRedirect(urllib.request.HTTPRedirectHandler):
    """Limit registry redirects to publicly routable HTTPS RDAP endpoints."""
    def __init__(self, forbidden_host: str):
        super().__init__()
        self.forbidden_host = forbidden_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            parts = urllib.parse.urlsplit(newurl)
            hostname = parts.hostname or ''
            port = parts.port
        except ValueError as exc:
            raise ProviderError('error', 'Unsafe RDAP registry redirect blocked') from exc
        if (parts.scheme.lower() != 'https' or port not in (None, 443) or
                parts.username is not None or parts.password is not None or
                not _rdap_redirect_host_allowed(hostname, self.forbidden_host)):
            raise ProviderError('error', 'Unsafe RDAP registry redirect blocked')
        # Check provider DNS answers before delegating to urllib. This prevents
        # common loopback/link-local/private-network destinations. The check
        # is not a substitute for connection-time IP pinning against DNS rebinding.
        try:
            records = socket.getaddrinfo(hostname.rstrip('.'), 443, type=socket.SOCK_STREAM)
            if not records or any(not ipaddress.ip_address(item[4][0]).is_global
                                  for item in records):
                raise ProviderError('error', 'RDAP redirect resolved to a non-public IP')
        except (OSError, ValueError) as exc:
            raise ProviderError('unavailable', 'RDAP redirect DNS verification failed') from exc
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _rdap_registrar(data: dict) -> str | None:
    for entity in data.get('entities') or []:
        if 'registrar' not in (entity.get('roles') or []):
            continue
        vcard = entity.get('vcardArray') or []
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for field in vcard[1]:
                if isinstance(field, list) and len(field) > 3 and field[0] == 'fn':
                    return str(field[3])
    return None


def rdap(target: dict, env: dict) -> dict:
    if target['is_ip']:
        return result('rdap', 'skipped', message='IP literal has no domain registration age')
    # Tenant domains on Netlify, GitHub Pages etc. are NOT domain registrations.
    domain, shared = rdap_registration_domain(target['host'])
    url = 'https://rdap.org/domain/' + urllib.parse.quote(domain, safe='')
    opener = urllib.request.build_opener(_RdapRedirect(target['host']))
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT,
                                                  'Accept': 'application/rdap+json'})
    try:
        with opener.open(request, timeout=TIMEOUT) as res:
            final = urllib.parse.urlsplit(res.geturl())
            final_host = (final.hostname or '').rstrip('.').lower()
            if (final.scheme != 'https' or
                    (final_host != 'rdap.org' and
                     not _rdap_redirect_host_allowed(final_host, target['host']))):
                raise ProviderError('error', 'Unsafe RDAP final response origin blocked')
            blob = res.read(1_500_001)
            if len(blob) > 1_500_000:
                raise ProviderError('error', 'RDAP response exceeded size limit')
            data = json.loads(blob.decode('utf-8'))
            if not isinstance(data, dict):
                raise ProviderError('error', 'Unexpected RDAP data format')
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return result('rdap', 'not_found', 'domain',
                          {'domain': domain, 'shared_hosting': shared},
                          message='No RDAP registration record')
        if exc.code == 429:
            raise ProviderError('rate_limited', 'RDAP rate limit exceeded') from exc
        if exc.code in (401, 403):
            raise ProviderError('auth_error', f'RDAP access denied (HTTP {exc.code})') from exc
        raise ProviderError('unavailable', f'RDAP HTTP {exc.code}') from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError('unavailable', f'RDAP unavailable: {type(exc).__name__}') from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderError('error', 'Invalid RDAP JSON') from exc
    created = next((e.get('eventDate') for e in data.get('events', [])
                    if isinstance(e, dict) and e.get('eventAction') == 'registration'), None)
    age = None
    if created:
        try:
            stamp = dt.datetime.fromisoformat(created.replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=dt.timezone.utc)
            age = max(0, (dt.datetime.now(dt.timezone.utc) - stamp).days)
        except (ValueError, TypeError):
            pass
    return result('rdap', 'completed', 'domain',
                  {'domain': domain, 'created_at': created, 'age_days': age,
                   'age_applies_to_target': not shared,
                   'shared_hosting': shared, 'subdomain_age_days': None if shared else age,
                   'registrar': _rdap_registrar(data)},
                  evidence=('Platform registration only; tenant age unknown' if shared
                            else 'RDAP registered-domain age'))


def dns(target: dict, env: dict) -> dict:
    if target['is_ip']:
        return result('dns', 'completed', 'ip',
                      {'ips': [target['host']], 'records': {}, 'note': 'IP literal (DNS skipped)'},
                      evidence='IP literal supplied')
    host = target['host']
    records = {}
    errors = []
    for record_type in ('A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT'):
        try:
            answer = http_json('https://dns.google/resolve', params={'name': host, 'type': record_type})
            raw = answer.get('Answer') or []
            # Data is names/IPs/text from authoritative DNS resolvers; do not connect to them.
            records[record_type] = [r.get('data', '') for r in raw if isinstance(r, dict)][:20]
            if answer.get('Status') not in (0, 3):
                errors.append(record_type)
        except ProviderError:
            errors.append(record_type)
            records[record_type] = []
    ips = []
    for item in records.get('A', []) + records.get('AAAA', []):
        try:
            ips.append(str(ipaddress.ip_address(item)))
        except ValueError:
            continue
    if len(errors) == 6:
        return result('dns', 'unavailable', 'domain',
                      {'ips': [], 'records': records, 'failed_types': errors},
                      message='All DNS-over-HTTPS lookups failed')
    return result('dns', 'partial' if errors else 'completed', 'domain',
                  {'ips': sorted(set(ips)), 'records': records,
                   'failed_types': errors,
                   'ip_resolution_incomplete': bool(set(errors) & {'A', 'AAAA'}),
                   'successful_types': [k for k in records if k not in errors],
                   'provider': 'Google DNS-over-HTTPS'},
                  evidence='Passive DNS lookups via provider; partial results when indicated')


MAX_IP_LOOKUPS = 12  # explicit cap; show omitted IPs rather than silently truncating


def abuseipdb(target: dict, env: dict, ips: list[str]) -> dict:
    key = env.get('ABUSEIPDB_API_KEY', '').strip()
    if not key:
        return result('abuseipdb', 'skipped', message='API key not configured')
    allowed = public_ips(ips)
    if not allowed:
        return result('abuseipdb', 'skipped', message='No public resolved IP address')
    findings, failures = [], []
    for ip in allowed[:MAX_IP_LOOKUPS]:
        try:
            pace('abuseipdb')
            data = http_json('https://api.abuseipdb.com/api/v2/check',
                             params={'ipAddress': ip, 'maxAgeInDays': 90},
                             headers={'Key': key, 'Accept': 'application/json'})
            node = data.get('data')
            if not isinstance(node, dict) or 'abuseConfidenceScore' not in node:
                raise ProviderError('error', 'Invalid AbuseIPDB record')
            findings.append({'ip': ip, 'abuse_confidence_score': node['abuseConfidenceScore'],
                             'total_reports': node.get('totalReports'),
                             'last_reported_at': node.get('lastReportedAt')})
        except ProviderError as exc:
            failures.append({'ip': ip, 'status': exc.status, 'reason': str(exc)})
            if exc.status in ('rate_limited', 'auth_error'):
                break  # do not burn quota after provider rejection
    unqueried = max(0, len(allowed) - len(findings) - len(failures))
    if not findings:
        if failures:
            return result('abuseipdb', failures[0]['status'], 'ip',
                          {'failed_ips': failures, 'unqueried': unqueried},
                          message=failures[0]['reason'])
        return result('abuseipdb', 'unavailable', message='No IP records returned')
    return result('abuseipdb', 'partial' if failures or unqueried else 'completed', 'ip',
                  {'ips': findings, 'failed_ips': failures, 'unqueried': unqueried},
                  evidence='Abuse reports for resolved IPs; shared IPs may be unrelated')


def public_ips(ips: list[str]) -> list[str]:
    unique = []
    for value in ips:
        try:
            item = ipaddress.ip_address(value)
            if item.is_global and str(item) not in unique:
                unique.append(str(item))
        except ValueError:
            pass
    return unique


def asn_geo(target: dict, env: dict, ips: list[str]) -> dict:
    public = public_ips(ips)
    if not public:
        return result('asn_geo', 'skipped', message='No public resolved IP address')
    findings, failures = [], []
    for ip in public[:MAX_IP_LOOKUPS]:
        try:
            pace('asn_geo')
            data = http_json('https://ipwho.is/' + urllib.parse.quote(ip, safe=':'))
            if data.get('success') is not True:
                raise ProviderError('unavailable', 'IP geolocation record unavailable')
            conn = data.get('connection') or {}
            if not isinstance(conn, dict):
                raise ProviderError('error', 'Malformed ASN record')
            findings.append({'ip': ip, 'country': data.get('country'),
                             'country_code': data.get('country_code'),
                             'asn': conn.get('asn'), 'org': conn.get('org'),
                             'isp': conn.get('isp')})
        except ProviderError as exc:
            failures.append({'ip': ip, 'status': exc.status, 'reason': str(exc)})
            if exc.status in ('rate_limited', 'auth_error'):
                break
    unqueried = max(0, len(public) - len(findings) - len(failures))
    if not findings:
        if failures:
            return result('asn_geo', failures[0]['status'], 'ip',
                          {'failed_ips': failures, 'unqueried': unqueried},
                          message=failures[0]['reason'])
        return result('asn_geo', 'unavailable', message='No ASN records returned')
    return result('asn_geo', 'partial' if failures or unqueried else 'completed', 'ip',
                  {'ips': findings, 'failed_ips': failures, 'unqueried': unqueried},
                  evidence='IP geo/ASN context (infrastructure, not domain ownership)')


PROVIDERS = {
    'virustotal': virustotal, 'google_safe_browsing': google_safe_browsing,
    'urlhaus': urlhaus, 'openphish': openphish, 'phishtank': phishtank,
    'cert_polska': cert_polska, 'urlscan': urlscan,
    'phishing_database': phishing_database, 'rdap': rdap, 'dns': dns,
}


# Conservative per-provider pacing across sequential batch analyses.
# These are NOT guaranteed to cover every plan's daily/account quotas.
MIN_INTERVAL = {
    'virustotal': 15.5, 'google_safe_browsing': 1.0,
    'urlhaus': 1.0, 'phishtank': 10.0,
    'urlscan': 2.0, 'abuseipdb': 2.0, 'asn_geo': 1.0,
}
_PACE_LOCKS = {name: threading.Lock() for name in MIN_INTERVAL}
_LAST_QUERY = {}


def pace(name: str) -> None:
    interval = MIN_INTERVAL.get(name, 0)
    if not interval:
        return
    with _PACE_LOCKS[name]:
        elapsed = time.monotonic() - _LAST_QUERY.get(name, -1e9)
        if elapsed < interval:
            time.sleep(interval - elapsed)
        _LAST_QUERY[name] = time.monotonic()


def _scheduled_lookup(name: str, fn, target: dict, env: dict) -> dict:
    # Do not wait for a provider whose optional key is absent.
    key_env = API_ENV.get(name)
    if not key_env or env.get(key_env, '').strip():
        pace(name)
    return fn(target, env)


def collect_sources(target: dict, env: dict, *, offline: bool = False,
                    providers: set[str] | None = None) -> dict[str, dict]:
    """Parallel passive lookup with explicit offline and provider filtering.

    The submitted URL itself is never visited. Disabled sources are returned
    with 'skipped', not a negative reputation verdict.
    """
    selection = set(SOURCE_ORDER) if providers is None else set(providers)
    local = {'openphish', 'cert_polska', 'phishing_database'}
    output = {}

    def enabled(name: str) -> bool:
        if name not in selection:
            output[name] = result(name, 'skipped', message='Excluded by --providers')
            return False
        if offline and name not in local:
            output[name] = result(name, 'skipped', message='Offline mode: network lookup disabled')
            return False
        return True

    with ThreadPoolExecutor(max_workers=4) as executor:
        jobs = {executor.submit(_scheduled_lookup, name, fn, target, env): name
                for name, fn in PROVIDERS.items() if enabled(name)}
        for future in as_completed(jobs):
            name = jobs[future]
            try:
                output[name] = future.result()
            except Exception as exc:
                output[name] = error_result(name, exc)

    ips = (output.get('dns', {}).get('details') or {}).get('ips') or []
    if target['is_ip']:
        ips = [target['host']]
    with ThreadPoolExecutor(max_workers=2) as executor:
        jobs = {}
        for name, fn in (('abuseipdb', abuseipdb), ('asn_geo', asn_geo)):
            if enabled(name):
                if not target['is_ip'] and output.get('dns', {}).get('status') in ('skipped', 'unavailable', 'error', 'timeout', 'rate_limited', 'auth_error'):
                    output[name] = result(name, 'skipped',
                                          message='IP context unavailable: DNS was not successful')
                else:
                    jobs[name] = executor.submit(fn, target, env, ips)
        for name, future in jobs.items():
            try:
                output[name] = future.result()
            except Exception as exc:
                output[name] = error_result(name, exc)
    return {name: output.get(name, result(name, 'skipped', message='Not selected'))
            for name in SOURCE_ORDER}
