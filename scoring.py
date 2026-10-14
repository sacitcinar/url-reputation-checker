"""Conservative evidence scoring; neither a probability nor a calibrated model.

Keep positive evidence distinct from the absence of a blacklist match. Local
snapshots and historical scans are NOT live reputation verification.
"""
from __future__ import annotations

import datetime as dt

# Evidence weights sum to 100. urlscan historical scans remain non-additive;
# authorized user-provided OpenPhish local listings contribute limited evidence.
WEIGHTS = {
    'virustotal': 27, 'google_safe_browsing': 23, 'urlhaus': 11,
    'phishtank': 11, 'cert_polska': 6, 'phishing_database': 6,
    'openphish': 7, 'abuseipdb': 3, 'heuristics': 5, 'rdap': 1,
}
LIVE_URL_REPUTATION = ('virustotal', 'google_safe_browsing', 'urlhaus', 'phishtank')
OFFLINE_REPUTATION = ('cert_polska', 'phishing_database', 'openphish')


def is_recent(date_string, days=90) -> bool:
    if not date_string:
        return False
    try:
        day = dt.date.fromisoformat(str(date_string)[:10])
        delta = (dt.datetime.now(dt.timezone.utc).date() - day).days
        return 0 <= delta <= days
    except (TypeError, ValueError):
        return False


def number(value, default=0) -> int:
    try:
        result = int(value)
        return max(0, result)
    except (TypeError, ValueError, OverflowError):
        return default


def assess(sources: dict[str, dict], heuristic: dict) -> dict:
    records = {**sources, 'heuristics': heuristic}
    evidence, floors, contributions = [], [], {}

    for name, record in records.items():
        score = 0
        status = record.get('status')
        details = record.get('details') or {}
        recent = is_recent(record.get('observed_at'))
        if name == 'virustotal' and status == 'completed':
            mal = number(details.get('malicious'))
            sus = number(details.get('suspicious'))
            # An older report is historical intelligence, not a current
            # reputation verdict; do not let it dominate current score.
            score = min(27, 3 * mal + 2 * sus) if recent else min(3, (mal + sus) // 4)
            if mal or sus:
                evidence.append(f'VirusTotal: {mal} malicious and {sus} suspicious engines' +
                                (' (historical result)' if not recent else ''))
            # A single detection merits review, but not a malicious verdict.
            # Only RECENT corroboration across several engines merits high floors.
            if recent:
                if mal >= 8:
                    floors.append(75)
                elif mal >= 5:
                    floors.append(50)
                elif mal >= 3:
                    floors.append(35)
                elif mal >= 1 or sus >= 2:
                    floors.append(20)
        elif name == 'google_safe_browsing' and status == 'listed':
            score = 25
            floors.append(85)
            evidence.append('Google Safe Browsing: threat-list match')
        elif name == 'urlhaus' and status == 'listed':
            score = 12
            floors.append(85 if str(details.get('url_status', '')).lower() == 'online' else 45)
            evidence.append('URLhaus: recorded malware-distribution URL')
        elif name == 'phishtank' and status == 'listed':
            verified, valid = details.get('verified') is True, details.get('valid') is True
            score = 12 if verified else 4
            if verified and valid:
                floors.append(85)
            elif verified:
                floors.append(45)
            evidence.append('PhishTank: phishing record' +
                            (' (verified)' if verified else ' (unverified)'))
        elif name == 'cert_polska' and status == 'listed':
            score = 7
            if is_recent(record.get('observed_at'), 30):
                floors.append(30)
            evidence.append('CERT Polska: domain matched an offline warning list')
        elif name == 'phishing_database' and status == 'listed':
            score = 6
            scope = record.get('match_type')
            if is_recent(record.get('observed_at'), 30):
                floors.append(45 if scope == 'url' else 25)
            evidence.append(f'Phishing.Database: offline {scope}-level match')
        elif name == 'openphish' and status == 'listed' and record.get('match_type') == 'url':
            # User-installed exact URL snapshot. Unknown date is common for
            # manual installs; flag age uncertainty without silently discarding.
            dated = bool(record.get('observed_at'))
            fresh = dated and is_recent(record['observed_at'], 30)
            score = 7 if fresh else 4
            floors.append(35 if fresh else 20)
            evidence.append('OpenPhish: user-supplied exact URL listing' +
                            ('' if fresh else ' (age not verified/current)'))
        elif name == 'abuseipdb' and status in ('completed', 'partial'):
            top = max([number((row or {}).get('abuse_confidence_score'))
                       for row in details.get('ips', [])] or [0])
            score = 3 if top >= 90 else (2 if top >= 50 else (1 if top >= 20 else 0))
            if score:
                evidence.append(f'AbuseIPDB: shared IP abuse confidence up to {top}/100')
        elif name == 'heuristics' and status == 'completed':
            score = min(5, number(details.get('heuristic_score')))
            if score:
                evidence.append(f'URL heuristics: {number(details.get("indicator_count"))} structural indicators')
            indicators = details.get('indicators') or []
            types = {i.get('type') for i in indicators if isinstance(i, dict)}
            has_login_context = details.get('auth_context') is True
            structural = {'userinfo', 'obfuscation', 'unusual_port', 'homograph',
                          'userinfo_brand_decoy'}
            # Alone, weak username/hostname similarity is noisy (especially
            # with an unverified brand catalog). Keep heuristics advisory and
            # NEVER escalate to MALICIOUS without reputation corroboration.
            if 'unicode_confusable_brand' in types:
                floors.append(35 if has_login_context else 30)
            elif 'userinfo_brand_decoy' in types:
                floors.append(30)
            elif types & {'brand_impersonation', 'typosquatting'}:
                if types & structural:
                    floors.append(35)
                elif has_login_context or 'brand_impersonation' in types:
                    floors.append(20)
                elif 'typosquatting' in types:
                    floors.append(20)  # review; not a malicious verdict
        elif name == 'rdap' and status == 'completed':
            age = details.get('age_days')
            # Platform age for netlify.app/github.io etc must never become
            # the tenant hostname's age, even if the platform is new.
            if details.get('age_applies_to_target', True) and age is not None:
                score = 1 if number(age, 99999) < 30 else 0
            if score:
                evidence.append(f'RDAP: newly registered domain ({age} days)')
        contributions[name] = min(WEIGHTS.get(name, 0), max(0, score))
        record['risk_points'] = contributions[name]

    # Historical urlscan is *not* a current clean reputation source, but an
    # explicit positive on the EXACT URL can contradict a likely-safe verdict.
    # We keep it out of additive weights as agreed; it only supplies a recent
    # minimum review floor. This does not start new urlscan scans.
    archived = records.get('urlscan') or {}
    scan_details = archived.get('details') or {}
    scan_positive = (archived.get('status') == 'completed' and
                     archived.get('match_type') == 'url' and
                     (scan_details.get('malicious') is True or
                      scan_details.get('historical_malicious') is True))
    if scan_positive:
        positive_time = scan_details.get('last_malicious_scan_time') or archived.get('observed_at')
        if is_recent(positive_time, 30):
            floors.append(25)
            evidence.append('urlscan.io: explicit malicious verdict in recent exact-URL archival result')
        else:
            evidence.append('urlscan.io: historical malicious verdict; review age and context')

    raw = min(100, sum(contributions.values()))
    score = max(raw, max(floors, default=0))

    live_sources, offline_sources, historical_sources = [], [], []
    for name in LIVE_URL_REPUTATION:
        record = records.get(name) or {}
        status = record.get('status')
        if status not in ('completed', 'listed', 'not_listed'):
            continue
        if name == 'virustotal' and not is_recent(record.get('observed_at'), 90):
            historical_sources.append(name)
        else:
            live_sources.append(name)
    for name in OFFLINE_REPUTATION:
        record = records.get(name) or {}
        if (record.get('status') in ('listed', 'not_listed') and
                is_recent(record.get('observed_at'), 30)):
            offline_sources.append(name)
    urlscan = records.get('urlscan') or {}
    if urlscan.get('status') == 'completed':
        historical_sources.append('urlscan')
    count = len(live_sources)
    coverage = 'High' if count >= 4 else 'Medium' if count >= 2 else 'Low'

    vt = records.get('virustotal') or {}
    vtd = vt.get('details') or {}
    vt_clean = (vt.get('status') == 'completed' and is_recent(vt.get('observed_at'), 90)
                and number(vtd.get('malicious')) == 0
                and number(vtd.get('suspicious')) == 0
                and number(vtd.get('harmless')) >= 10)
    # Offline 'not listed' and archived urlscan records do not independently
    # substantiate a safe verdict. Also prohibit safe with any listed threat.
    independent_live_negative = any(
        (records.get(n) or {}).get('status') == 'not_listed'
        for n in ('google_safe_browsing', 'urlhaus', 'phishtank')
    )
    threat_listing = any((records.get(n) or {}).get('status') == 'listed'
                         for n in ('google_safe_browsing', 'urlhaus', 'phishtank',
                                   'cert_polska', 'phishing_database', 'openphish'))
    shortener_unresolved = any(
        isinstance(i, dict) and i.get('type') == 'shortener'
        for i in (heuristic.get('details') or {}).get('indicators', [])
    )
    if shortener_unresolved:
        evidence.append('Unresolved short URL: destination not verified; clean verdict withheld')
    low_risk_support = (vt_clean and independent_live_negative and not threat_listing
                        and not scan_positive and not shortener_unresolved)
    if score >= 70:
        verdict = 'MALICIOUS'
    elif score >= 45:
        verdict = 'HIGH RISK'
    elif score >= 20:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'LIKELY SAFE' if low_risk_support else 'UNKNOWN'

    if not evidence:
        evidence.append('No scoring threat indicators were identified in available results')
    incomplete = [name for name, node in records.items()
                  if node.get('status') not in ('completed', 'listed', 'not_listed')]
    if incomplete:
        evidence.append(f'{len(incomplete)} checks were skipped, unavailable, partial or inconclusive')
    return {
        'risk_score': score, 'raw_score': raw, 'verdict': verdict,
        'coverage': coverage, 'coverage_sources': count,
        'live_reputation_sources': live_sources, 'offline_snapshot_sources': offline_sources,
        'historical_scan_sources': historical_sources,
        'evidence': evidence, 'contributions': contributions,
        'method': 'Conservative evidence-weighted heuristic scoring; not a probability',
        'limited_confidence': not low_risk_support,
    }
