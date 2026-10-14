"""Strictly local, explainable URL structure and brand comparison checks."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit
import json
import re
import unicodedata

from utils import DATA, public_suffix, registered_domain, result

SHORTENERS = frozenset('bit.ly tinyurl.com t.co goo.gl is.gd ow.ly buff.ly rebrand.ly cutt.ly shorturl.at tiny.cc rb.gy lnkd.in t.ly bitly.com'.split())
AUTH_WORDS = frozenset('login logon signin signon account verify verification secure update support billing password reset recover confirm identity auth wallet'.split())


@lru_cache(maxsize=1)
def brand_catalog() -> list[dict]:
    data = []
    for filename in ('brands_global.json', 'brands_turkey.json', 'brands_core_security.json'):
        try:
            entries = json.loads((DATA / filename).read_text('utf-8'))
        except (OSError, ValueError):
            entries = []
        for row in entries:
            if isinstance(row, dict) and isinstance(row.get('domains'), list):
                data.append(row)
    return data


def condensed(text: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', unicodedata.normalize('NFKD', text).lower())


def distance_at_most_one(a: str, b: str) -> bool:
    """Substitution, insertion, deletion or transposition distance <= 1."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diffs) == 1:
            return True
        return (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and a[diffs[0]] == b[diffs[1]]
                and a[diffs[1]] == b[diffs[0]])
    if len(a) > len(b):
        a, b = b, a
    i = j = errors = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            errors += 1
            if errors > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return True

# A conservative, explainable subset of UTS #39-style confusable folding.
# Not a complete Unicode security database. Exact spoof detection is limited
# to visually similar Greek/Cyrillic letters used in brand-label comparisons.
_CONFUSABLES = {
    # Cyrillic lowercase
    'а':'a', 'е':'e', 'о':'o', 'р':'p', 'с':'c', 'х':'x', 'у':'y',
    'і':'i', 'ј':'j', 'ѕ':'s', 'ԁ':'d', 'һ':'h', 'ӏ':'l', 'ԛ':'q',
    'к':'k', 'м':'m', 'т':'t', 'в':'b', 'н':'h',
    # Greek lowercase
    'α':'a', 'ο':'o', 'ρ':'p', 'ν':'v', 'ι':'i', 'κ':'k',
    'ε':'e', 'τ':'t', 'χ':'x', 'υ':'u', 'ϲ':'c', 'ѕ':'s',
}


def skeleton(value: str) -> str:
    chars = unicodedata.normalize('NFKC', value).casefold()
    return condensed(''.join(_CONFUSABLES.get(c, c) for c in chars))


def unicode_host(host: str) -> str:
    try:
        return host.encode('ascii').decode('idna')
    except (UnicodeError, ValueError):
        return host


def active_hostname_labels(target: dict) -> list[str]:
    """Return only user-controlled tenant label and subdomain labels.

    Strip the PUBLIC suffix using the vendored PSL. This excludes provider
    platform words such as github, appspot and azurewebsites.
    """
    host_labels = target['host'].split('.')
    domain_labels = target['domain'].split('.')
    return host_labels[:-len(domain_labels)] + [domain_labels[0]]


def brand_identifiers(item: dict) -> set[str]:
    identifiers = {condensed(x) for x in (str(item.get('name', '')),
                   *(str(x) for x in item.get('aliases', [])))}
    identifiers |= {condensed(x.split('.')[0]) for x in item.get('domains', [])}
    return {x for x in identifiers if len(x) >= 5}


def _official_host(target: dict) -> bool:
    return any(target['host'] == d or target['host'].endswith('.' + d)
               for item in brand_catalog() for d in item.get('domains', []))


def _auth_affixes(label: str) -> set[str]:
    """Extract typo candidates adjacent to complete account-context words.

    The brand-like remainder is checked by edit distance; this is NOT a
    generic substring/brand search that would flag unrelated company names.
    """
    results = set()
    for word in AUTH_WORDS:
        if label.startswith(word) and len(label) >= len(word) + 5:
            results.add(label[len(word):])
        if label.endswith(word) and len(label) >= len(word) + 5:
            results.add(label[:-len(word)])
    return results


def unicode_brand_impersonation(target: dict) -> list[dict]:
    """Recognize known-brand Unicode skeletons in tenant/subdomain tokens.

    Pure non-Latin internationalized domains without brand impersonation are
    not escalated. Confusables remain an advisory subset, not full UTS #39.
    """
    decoded = unicode_host(target['host'])
    if decoded == target['host'] or not any(ord(c) > 127 for c in decoded):
        return []
    if _official_host(target):
        return []
    # Extract user-controlled parts; do not treat the platform's own name as
    # a fake brand. IDNA labels can contain hyphens after decoding.
    label_count = len(active_hostname_labels(target))
    active_decoded = decoded.split('.')[:label_count]
    parts = [token for label in active_decoded for token in re.split(r'[-_]', label)]
    for token in parts:
        if not any(ord(c) > 127 for c in token):
            continue
        folded = skeleton(token)
        raw = condensed(token)
        if not folded or folded == raw:
            continue
        # Brand+login/verify can be concatenated without a hyphen.
        folded_candidates = {folded} | _auth_affixes(folded)
        for item in brand_catalog():
            if folded_candidates & brand_identifiers(item):
                return [{'type': 'unicode_confusable_brand', 'brand': item.get('name'),
                         'detail': 'Unicode hostname token visually imitates a known brand',
                         'points': 5}]
    # Some invalid/ambiguous ACE labels embed a valid xn--brand-name followed
    # by a bait suffix; treat as suspicious ONLY with an auth word and a known
    # confusable brand after independently decoding the ACE prefix.
    for ace_label in active_hostname_labels(target):
        if not ace_label.startswith('xn--') or '-' not in ace_label[4:]:
            continue
        for word in AUTH_WORDS:
            separator = '-' + word
            if not ace_label.endswith(separator):
                continue
            candidate = ace_label[:-len(separator)]
            try:
                partial = candidate.encode('ascii').decode('idna')
            except (ValueError, UnicodeError):
                continue
            if skeleton(partial) == condensed(partial):
                continue
            if any(skeleton(partial) in brand_identifiers(item) for item in brand_catalog()):
                return [{'type': 'unicode_confusable_brand',
                         'detail': 'Embedded Punycode segment resembles a brand next to an account keyword',
                         'points': 5}]
    return []


def suspicious_brand(target: dict) -> list[dict]:
    host, domain = target['host'], target['domain']
    registrable_label = domain.split('.')[0]
    if target['is_ip']:
        return []
    # A hosting platform's own PSL PRIVATE suffix is not its tenant label.
    if (public_suffix(host) == host and public_suffix(host, include_private=False) != host):
        return []
    brands = brand_catalog()
    # Any officially listed domain suppresses impersonation on that registrable
    # domain, including subdomains, before fuzzy comparisons begin.
    official_domains = {d.lower() for item in brands for d in item.get('domains', [])}
    if domain in official_domains or any(
        host == official or host.endswith('.' + official)
        for official in official_domains
    ):
        return []
    findings = []
    host_norm = host.lower()
    name_root = condensed(registrable_label)
    # Do not mistake the platform part of foo.github.io or foo.appspot.com
    # for a tenant impersonating GitHub/Google/etc.
    active_labels = host.split('.')[:-len(domain.split('.'))] + [registrable_label]
    tokens = {condensed(t) for t in re.split(r'[-._]', '.'.join(active_labels))}
    for item in brands:
        name = str(item.get('name', ''))
        official = item.get('domains') or []
        aliases = [name, *item.get('aliases', [])]
        identifiers = {condensed(value) for value in aliases if len(condensed(value)) >= 5}
        official_labels = {condensed(d.split('.')[0]) for d in official}
        identifiers |= {x for x in official_labels if len(x) >= 5}
        if not identifiers:
            continue
        # Strong misleading hostname prefix, e.g. paypal.com.other.example.
        if any(host_norm.startswith(d.lower() + '.') for d in official):
            findings.append({'type': 'brand_impersonation', 'brand': name,
                             'detail': f'Official domain appears only as hostname prefix: {official[0]}',
                             'points': 3})
            break
        if any(ident in tokens for ident in identifiers):
            findings.append({'type': 'brand_impersonation', 'brand': name,
                             'detail': 'Recognizable brand token on unrelated registrable domain',
                             'points': 3})
            break
        if any(len(ident) >= 5 and
               (name_root.startswith(ident) or name_root.endswith(ident)) and name_root != ident
               and any(word in name_root for word in AUTH_WORDS) for ident in identifiers):
            findings.append({'type': 'brand_impersonation', 'brand': name,
                             'detail': 'Brand-like domain combined with account/login keywords',
                             'points': 3})
            break
    if findings:
        return findings
    # Single-character near-match is weak evidence and only on full registered
    # label, not arbitrary path/query text.
    for item in brands:
        variants = {condensed(d.split('.')[0]) for d in item.get('domains', [])}
        variants.add(condensed(item.get('name', '')))
        if any(5 <= len(v) <= 20 and name_root != v and
               distance_at_most_one(name_root, v) for v in variants):
            findings.append({'type': 'typosquatting', 'brand': item['name'],
                             'detail': f'Registrable label resembles {item["name"]}', 'points': 3})
            break
    # Combined typo + account bait on the tenant label or any subdomain.
    # Crucially, comparison is per hostname token, NOT the full concatenation.
    labels = active_hostname_labels(target)
    tokens = [condensed(v) for label in labels for v in re.split(r'[-_]', label)]
    has_auth = bool(AUTH_WORDS.intersection(tokens))
    if has_auth:
        for token in tokens:
            if len(token) < 5 or len(token) > 24:
                continue
            for item in brands:
                variants = brand_identifiers(item)
                if any(token != variant and distance_at_most_one(token, variant)
                       for variant in variants):
                    findings.append({'type': 'typosquatting', 'brand': item.get('name'),
                                     'detail': 'Near-brand hostname token combined with account keyword',
                                     'points': 3})
                    return findings
    # No-separator phishing bait such as paypa1login, loginpaypa1, or a
    # tenant label paypa1login.evil.test. Only near-brand remainders adjacent
    # to complete authentication words qualify; no arbitrary substrings.
    if not findings:
        for label in active_hostname_labels(target):
            for candidate in _auth_affixes(condensed(label)):
                for item in brands:
                    if any(candidate != brand and len(brand) >= 5 and
                           distance_at_most_one(candidate, brand)
                           for brand in brand_identifiers(item)):
                        findings.append({'type': 'typosquatting', 'brand': item.get('name'),
                                         'detail': 'Concatenated near-brand and account keyword',
                                         'points': 3})
                        return findings
    return findings


def analyze_url(target: dict) -> dict:
    warnings = []
    original = target.get('refanged_input', target['original'])
    host = target['host']
    raw_netloc = target['raw_netloc']
    raw_host = unicode_host(host)
    scripts = set()
    for ch in raw_host:
        if ord(ch) > 127 and ch.isalpha():
            uname = unicodedata.name(ch, '')
            for script in ('LATIN', 'CYRILLIC', 'GREEK'):
                if script in uname:
                    scripts.add(script)
    if len(scripts) > 1:
        warnings.append({'type': 'homograph', 'detail': 'Mixed writing systems in hostname', 'points': 2})
    elif 'xn--' in host or any(ord(ch) > 127 for ch in raw_host):
        warnings.append({'type': 'punycode', 'detail': 'Internationalized hostname; not necessarily malicious', 'points': 0})
    warnings.extend(unicode_brand_impersonation(target))
    if target['is_ip']:
        warnings.append({'type': 'ip_literal', 'detail': 'URL uses an IP literal as host', 'points': 1})
    if '@' in raw_netloc:
        warnings.append({'type': 'userinfo', 'detail': 'Misleading @/userinfo in URL authority', 'points': 2})
        userinfo = raw_netloc.rpartition('@')[0].lower()
        if any(re.search(r'(?<![a-z0-9])' + re.escape(d.lower()) + r'(?![a-z0-9])', userinfo)
               for b in brand_catalog() for d in b.get('domains', [])):
            warnings.append({'type': 'userinfo_brand_decoy',
                             'detail': 'Official brand domain presented as URL username, not destination',
                             'points': 4})
    pct = re.findall(r'%[0-9A-Fa-f]{2}', original)
    if len(pct) >= 5 or re.search(r'%(?:25|2f|5c|00|2e%2e)', original, re.I):
        warnings.append({'type': 'obfuscation', 'detail': 'Repeated or sensitive percent-encoding', 'points': 1})
    if target['port'] and target['port'] not in (80, 443):
        warnings.append({'type': 'unusual_port', 'detail': f'Explicit port {target["port"]}', 'points': 1})
    if len(original) > 180 or original.count('?') > 2 or target['query'].count('&') >= 7:
        warnings.append({'type': 'complex_url', 'detail': 'Unusually long or parameter-heavy URL', 'points': 1})
    if len(host.split('.')) - len(target['domain'].split('.')) >= 4:
        warnings.append({'type': 'deep_subdomains', 'detail': 'Unusually deep subdomain chain', 'points': 1})
    if any(host == sh or host.endswith('.' + sh) for sh in SHORTENERS):
        warnings.append({'type': 'shortener', 'detail': 'URL shortener; destination not resolved', 'points': 0})
    fragment = target.get('fragment') or ''
    if fragment and any(re.search(r'(?<![a-z])' + re.escape(word) + r'(?![a-z])',
                                   fragment, re.I) for word in AUTH_WORDS):
        warnings.append({'type': 'fragment_auth_route',
                         'detail': 'Client-side URL fragment contains an authentication route',
                         'points': 1})
    if target['scheme'] == 'http':
        warnings.append({'type': 'http', 'detail': 'Unencrypted HTTP scheme (context only)', 'points': 0})
    if not any(w["type"] == "unicode_confusable_brand" for w in warnings):
        warnings.extend(suspicious_brand(target))
    # Avoid double-counting correlated brand impersonation and typosquatting.
    points = min(6, sum(int(w['points']) for w in warnings))
    return result('heuristics', 'completed', 'url',
                  {'checks': 10, 'indicators': warnings,
                   'indicator_count': len([w for w in warnings if w['points'] > 0]),
                   'brand_catalog_size': len(brand_catalog()),
                   'brand_catalog_verified': False,
                   'heuristic_score': points, 'auth_context': any(
                       word in target['path'].lower() for word in
                       ('login', 'signin', 'account', 'verify', 'secure', 'auth', 'reset'))},
                  evidence='Local static URL analysis only')
