import re
from datetime import datetime

URGENT_KEYWORDS = [
    'urgent', 'immediately', 'action required', 'account suspended',
    'verify now', 'click here', 'act now', 'limited time', 'expires',
    'confirm your', 'unusual activity', 'unauthorized', 'alert', 'warning',
    'your account will be', 'will be terminated', 'validate', 'reactivate'
]

FINANCIAL_KEYWORDS = [
    'bank account', 'credit card', 'debit card', 'wire transfer', 'routing number',
    'social security', 'ssn', 'password', 'pin number', 'cvv', 'otp',
    'aadhaar', 'pan card', 'upi', 'netbanking', 'paytm', 'gpay'
]

SUSPICIOUS_PATTERNS = [
    r'dear\s+(customer|user|client|valued)',      # Generic greeting
    r'click\s+(?:here|below|the link)',           # Vague click prompts
    r'http[^\s]+(?:login|verify|secure|update)',  # Suspicious URLs
    r'\$[\d,]+\s+(?:prize|reward|cash|won)',      # Prize scams
    r'(?:nigerian|inheritance|lottery)\s+fund',   # 419 scams
    r'(?:free|won|selected|chosen)\s+(?:iphone|gift|prize)',  # Prize lures
]

FAKE_SENDER_PATTERNS = [
    r'@[a-z0-9-]+\.(xyz|top|click|download|gq|ml|cf|tk|pw)$',
    r'support@.*(?:gmail|yahoo|hotmail)\.com',   # Legit companies don't use free email
    r'noreply@.*\.(biz|info|mobi)$',
]


class EmailDetector:

    def analyze_email(self, email_content: str) -> dict:
        score = 0
        reasons = []
        email_lower = email_content.lower()

        # ── Rule 1: Urgency keywords
        found_urgent = [kw for kw in URGENT_KEYWORDS if kw in email_lower]
        if found_urgent:
            score += min(len(found_urgent) * 10, 25)
            reasons.append(f'Urgency tactics detected: "{", ".join(found_urgent[:3])}" — creates panic to bypass critical thinking')

        # ── Rule 2: Financial/sensitive data requests
        found_financial = [kw for kw in FINANCIAL_KEYWORDS if kw in email_lower]
        if found_financial:
            score += min(len(found_financial) * 12, 30)
            reasons.append(f'Requesting sensitive information: {", ".join(found_financial[:3])} — legitimate orgs never ask for these via email')

        # ── Rule 3: Generic greeting
        generic_greetings = ['dear customer', 'dear user', 'dear member', 'valued customer', 'dear account holder']
        if any(g in email_lower for g in generic_greetings):
            score += 15
            reasons.append('Generic greeting used (e.g., "Dear Customer") — real companies address you by name')

        # ── Rule 4: Suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, email_lower):
                score += 10
                reasons.append(f'Suspicious pattern detected: matches known phishing template')
                break

        # ── Rule 5: Suspicious URLs in body
        urls_in_email = re.findall(r'http[s]?://[^\s<>"]+', email_content)
        suspicious_urls = []
        for u in urls_in_email:
            if any(s in u.lower() for s in ['login', 'verify', 'secure', 'update', 'confirm']):
                suspicious_urls.append(u[:50])
        if suspicious_urls:
            score += 20
            reasons.append(f'Suspicious links found in email body: {suspicious_urls[0]}...')

        # ── Rule 6: Mismatched display vs actual link
        display_link_pattern = re.findall(r'(?:href=["\']([^"\']+)["\']|<a[^>]+>([^<]+)</a>)', email_content, re.IGNORECASE)
        if display_link_pattern:
            score += 10
            reasons.append('Email contains HTML links that may disguise the true destination URL')

        # ── Rule 7: Excessive punctuation / caps (spam signal)
        caps_words = len(re.findall(r'\b[A-Z]{3,}\b', email_content))
        if caps_words > 5:
            score += 10
            reasons.append(f'Excessive ALL-CAPS text ({caps_words} instances) — common in spam/phishing emails')

        exclamation = email_content.count('!')
        if exclamation > 3:
            score += 5
            reasons.append(f'Too many exclamation marks ({exclamation}) — pressure tactic used in phishing')

        # ── Rule 8: Sender domain check (if From: header present)
        sender_match = re.search(r'from:\s*([^\n\r]+)', email_content, re.IGNORECASE)
        if sender_match:
            sender = sender_match.group(1).lower()
            for pattern in FAKE_SENDER_PATTERNS:
                if re.search(pattern, sender):
                    score += 20
                    reasons.append(f'Suspicious sender domain: {sender.strip()[:60]} — does not match a legitimate organization')
                    break

        score = min(score, 100)

        if score >= 60:
            risk_level = 'HIGH'
            verdict = '🚨 Phishing Email Detected'
            color = 'danger'
        elif score >= 30:
            risk_level = 'MEDIUM'
            verdict = '⚠️ Suspicious Email'
            color = 'warning'
        else:
            risk_level = 'LOW'
            verdict = '✅ Appears Legitimate'
            color = 'safe'

        recommendations = []
        if risk_level == 'HIGH':
            recommendations = [
                'Do NOT click any links or download attachments',
                'Do NOT reply or provide any personal information',
                'Report to your email provider as phishing/spam',
                'Report to cybercrime.gov.in if you shared sensitive data',
                'Change passwords if you already interacted with this email'
            ]
        elif risk_level == 'MEDIUM':
            recommendations = [
                'Verify by contacting the organization through official channels',
                'Do not use any links in this email — go directly to their website',
                'Check the sender\'s actual email address carefully'
            ]
        else:
            recommendations = [
                'Email appears legitimate based on analysis',
                'Still exercise caution — never share OTPs or passwords',
                'Verify unexpected requests through a phone call'
            ]

        return {
            'risk_score': score,
            'risk_level': risk_level,
            'verdict': verdict,
            'color': color,
            'reasons': reasons if reasons else ['No suspicious patterns detected'],
            'recommendations': recommendations,
            'links_found': len(urls_in_email),
            'analyzed_at': datetime.utcnow().isoformat()
        }
