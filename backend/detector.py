import re
import socket
import ssl
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone


SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'banking', 'paypal', 'amazon', 'apple', 'microsoft',
    'google', 'password', 'credential', 'wallet', 'payment', 'urgent',
    'suspended', 'unusual', 'activity', 'click', 'free', 'win', 'prize'
]

TRUSTED_DOMAINS = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
    'facebook.com', 'twitter.com', 'github.com', 'linkedin.com', 'netflix.com',
    'adobe.com', 'dropbox.com', 'spotify.com', 'instagram.com', 'youtube.com'
]


class PhishingDetector:

    def analyze_url(self, url: str) -> dict:
        score = 0
        reasons = []
        recommendations = []

        # Normalize
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        path = parsed.path.lower()
        full_url = url.lower()

        # ── Rule 1: URL Length
        if len(url) > 75:
            score += 15
            reasons.append(f'Unusually long URL ({len(url)} characters) — attackers hide malicious paths in long URLs')

        # ── Rule 2: IP address used instead of domain
        ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
        if ip_pattern.match(domain):
            score += 30
            reasons.append('URL uses an IP address instead of a domain name — legitimate sites use domain names')

        # ── Rule 3: @ symbol in URL
        if '@' in url:
            score += 25
            reasons.append('URL contains "@" symbol — browsers ignore everything before @ making it deceptive')

        # ── Rule 4: Multiple subdomains
        subdomains = domain.split('.')
        if len(subdomains) > 4:
            score += 15
            reasons.append(f'Too many subdomains ({len(subdomains) - 2}) — phishers use subdomains to mimic real sites')

        # ── Rule 5: Hyphen in domain
        if '-' in domain:
            score += 10
            reasons.append('Hyphens in domain — often used to mimic legitimate domains (e.g. paypal-secure.com)')

        # ── Rule 6: Fake HTTPS keywords
        fake_https_keywords = ['https-', 'secure-', 'ssl-', 'safe-']
        for kw in fake_https_keywords:
            if kw in domain:
                score += 20
                reasons.append(f'Domain contains security keyword "{kw}" — a common trick to appear trustworthy')
                break

        # ── Rule 7: Suspicious keywords in URL
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
        if found_keywords:
            score += min(len(found_keywords) * 8, 30)
            reasons.append(f'Suspicious keywords found: {", ".join(found_keywords[:5])}')

        # ── Rule 8: Double slashes (redirect trick)
        if '//' in parsed.path:
            score += 10
            reasons.append('Double slashes in path — used to confuse URL parsers and redirect victims')

        # ── Rule 9: Port number in URL
        if parsed.port and parsed.port not in [80, 443]:
            score += 15
            reasons.append(f'Non-standard port {parsed.port} — legitimate sites rarely use unusual ports')

        # ── Rule 10: Typosquatting check
        for trusted in TRUSTED_DOMAINS:
            trusted_base = trusted.split('.')[0]
            if trusted_base in domain and trusted not in domain:
                score += 25
                reasons.append(f'Domain looks like it\'s impersonating "{trusted}" (typosquatting)')
                break

        # ── Rule 11: HTTP instead of HTTPS
        if url.startswith('http://') and not url.startswith('https://'):
            score += 10
            reasons.append('Uses HTTP (not HTTPS) — your data is not encrypted')

        # ── Rule 12: Domain Age (WHOIS)
        domain_age_info = self._check_domain_age(domain)
        if domain_age_info['score'] > 0:
            score += domain_age_info['score']
            reasons.append(domain_age_info['reason'])

        # ── Clamp score
        score = min(score, 100)

        # ── Risk level
        if score >= 60:
            risk_level = 'HIGH'
            verdict = '🚨 Likely Phishing'
            color = 'danger'
        elif score >= 30:
            risk_level = 'MEDIUM'
            verdict = '⚠️ Suspicious'
            color = 'warning'
        else:
            risk_level = 'LOW'
            verdict = '✅ Appears Safe'
            color = 'safe'

        # ── Recommendations
        if risk_level == 'HIGH':
            recommendations = [
                'Do NOT click this link or enter any information',
                'Report it to cybercrime.gov.in or 1930 helpline',
                'If you already clicked, change your passwords immediately',
                'Check your bank accounts for unauthorized transactions'
            ]
        elif risk_level == 'MEDIUM':
            recommendations = [
                'Proceed with caution — verify the sender/source',
                'Do not enter passwords or financial details',
                'Contact the organization directly through their official website',
                'Use a URL checker like Google Safe Browsing'
            ]
        else:
            recommendations = [
                'URL appears safe based on rule-based analysis',
                'Always verify the SSL certificate (padlock icon)',
                'Never share passwords or OTPs on any site'
            ]

        return {
            'url': url,
            'domain': domain,
            'risk_score': score,
            'risk_level': risk_level,
            'verdict': verdict,
            'color': color,
            'reasons': reasons if reasons else ['No suspicious patterns detected'],
            'recommendations': recommendations,
            'checks_performed': 12,
            'analyzed_at': datetime.utcnow().isoformat()
        }

    def _check_domain_age(self, domain: str) -> dict:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation_date).days
                if age_days < 30:
                    return {'score': 30, 'reason': f'Domain is only {age_days} days old — very new domains are high-risk'}
                elif age_days < 180:
                    return {'score': 15, 'reason': f'Domain is only {age_days} days old — recently registered domains are suspicious'}
        except Exception:
            pass
        return {'score': 0, 'reason': ''}
