<div align="center">

```
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

### ⚔ Real-Time Phishing Detection & Awareness System

[![Python](https://img.shields.io/badge/Python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-f7df1e?style=flat-square&logo=javascript&logoColor=black)](https://developer.mozilla.org/docs/Web/JavaScript)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003b57?style=flat-square&logo=sqlite)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-MIT-00cc88?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00cc88?style=flat-square)]()

**No AI. No black box. 100% explainable rule-based detection.**

[Live Demo](#-live-demo) · [Features](#-features) · [Architecture](#-architecture) · [Setup](#-installation) · [API Docs](#-api-reference) · [Report Crime](https://cybercrime.gov.in)

---

</div>

## 📸 Preview

| URL Scanner | Email Detector | Dashboard |
|:-----------:|:--------------:|:---------:|
| 🔗 Analyze any suspicious URL | 📧 Paste email content | 📊 Live threat stats |
| 12 detection rules | 8 behavioral checks | Recent scan history |
| Risk score + explanation | Sender validation | Attack type trends |

---

## ✨ Features

### 🌐 URL Scanner
The core engine — runs every submitted URL through **12 sequential detection rules**:

| Rule | Check | Risk Weight |
|------|-------|-------------|
| `R01` | URL length > 75 characters | +15 pts |
| `R02` | IP address used instead of domain | +30 pts |
| `R03` | `@` symbol in URL (redirect trick) | +25 pts |
| `R04` | More than 4 subdomains | +15 pts |
| `R05` | Hyphen in domain name | +10 pts |
| `R06` | Fake security keywords (`https-`, `secure-`) | +20 pts |
| `R07` | Suspicious keywords in path | up to +30 pts |
| `R08` | Double slashes in path `//` | +10 pts |
| `R09` | Non-standard port number | +15 pts |
| `R10` | Typosquatting against 15 known brands | +25 pts |
| `R11` | HTTP instead of HTTPS | +10 pts |
| `R12` | Domain age < 180 days (WHOIS) | +15–30 pts |

**Risk Tiers:**
```
  0 – 29   →  ✅ Safe        (Green)
 30 – 59   →  ⚠️  Suspicious  (Yellow)
 60 – 100  →  🚨 Phishing    (Red)
```

---

### 📧 Email Phishing Detector
Analyzes pasted email content for:

- **Urgency tactics** — 20+ trigger phrases ("urgent", "suspended", "verify now")
- **Sensitive data requests** — detects asks for passwords, OTPs, Aadhaar, PAN, CVV
- **Generic greetings** — "Dear Customer" instead of your name
- **Suspicious embedded URLs** — links with phishing keywords in href
- **Fake sender domains** — free email providers impersonating corporations
- **CAPS abuse & exclamation marks** — pressure tactics
- **HTML link disguising** — display text ≠ actual href

---

### 📊 Dashboard
Real-time statistics from the SQLite database:
- Total scans performed
- Phishing / Suspicious / Safe breakdown
- URL vs Email scan counts
- 5 most recent scan history with risk badges

---

### 🚨 India-Specific Reporting Guide
Built-in section with direct links to:
- [National Cyber Crime Reporting Portal](https://cybercrime.gov.in) — MHA
- **Cyber Crime Helpline: 1930** — Immediate assistance
- [CERT-In](https://www.cert-in.org.in) — For site takedown requests
- [I4C](https://www.i4c.mha.gov.in) — Coordination centre

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      PHISHGUARD SYSTEM                      │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────┐     HTTP/REST     ┌────────────────────────┐
│   FRONTEND      │ ◄──────────────► │   BACKEND (Flask)       │
│                 │                   │                         │
│  index.html     │                   │  app.py                 │
│  style.css      │                   │  ├─ /api/scan/url       │
│  script.js      │                   │  ├─ /api/scan/email     │
│                 │                   │  ├─ /api/stats          │
│  • Syne font    │                   │  └─ /api/health         │
│  • Space Mono   │                   │                         │
│  • Dark theme   │                   │  detector.py            │
└─────────────────┘                   │  ├─ 12 URL rules        │
                                       │  └─ WHOIS lookup        │
                                       │                         │
                                       │  email_detector.py      │
                                       │  ├─ Keyword engine      │
                                       │  └─ Pattern matching    │
                                       │                         │
                                       │  database.py            │
                                       │  └─ SQLAlchemy + SQLite │
                                       └────────────────────────┘
```

---

## 📁 Project Structure

```
phishguard/
│
├── 📂 backend/
│   ├── app.py              # Flask application entry point
│   ├── detector.py         # URL phishing detection engine (12 rules)
│   ├── email_detector.py   # Email content analysis engine
│   ├── database.py         # SQLAlchemy models
│   └── requirements.txt    # Python dependencies
│
├── 📂 frontend/
│   ├── index.html          # Main HTML (single-page app)
│   ├── 📂 css/
│   │   └── style.css       # Full dark-theme stylesheet
│   └── 📂 js/
│       └── script.js       # All frontend logic
│
└── README.md               # This file
```

---

## 🚀 Installation

### Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.10+ | [python.org](https://python.org) |
| pip | latest | bundled with Python |
| Git | any | [git-scm.com](https://git-scm.com) |

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/yourusername/phishguard.git
cd phishguard
```

---

### Step 2 — Set Up the Backend

```bash
# Navigate to backend
cd backend

# (Recommended) Create a virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

### Step 3 — Start the Flask Server

```bash
python app.py
```

You should see:
```
 * Running on http://127.0.0.1:5000
 * PhishGuard API is live!
```

> ✅ The database (`phishguard.db`) is created automatically on first run.

---

### Step 4 — Launch the Frontend

Open a **new terminal** and serve the frontend:

```bash
cd frontend

# Option A: Python HTTP server (no install needed)
python -m http.server 8080

# Option B: Node.js serve
npx serve .

# Option C: VS Code Live Server extension
# Just right-click index.html → "Open with Live Server"
```

Then open: **[http://localhost:8080](http://localhost:8080)**

---

## 🔌 API Reference

Base URL: `http://localhost:5000/api`

---

### `POST /scan/url`
Analyze a URL for phishing indicators.

**Request:**
```json
{
  "url": "http://paypal-secure-login.xyz/verify?id=123"
}
```

**Response:**
```json
{
  "url": "http://paypal-secure-login.xyz/verify?id=123",
  "domain": "paypal-secure-login.xyz",
  "risk_score": 87,
  "risk_level": "HIGH",
  "verdict": "🚨 Likely Phishing",
  "color": "danger",
  "reasons": [
    "Domain looks like it's impersonating 'paypal.com' (typosquatting)",
    "Domain contains security keyword 'secure-' — a common trick to appear trustworthy",
    "Domain is only 3 days old — very new domains are high-risk",
    "Suspicious keywords found: login, verify"
  ],
  "recommendations": [
    "Do NOT click this link or enter any information",
    "Report it to cybercrime.gov.in or 1930 helpline",
    "If you already clicked, change your passwords immediately",
    "Check your bank accounts for unauthorized transactions"
  ],
  "checks_performed": 12,
  "analyzed_at": "2024-01-15T10:30:00.000Z"
}
```

---

### `POST /scan/email`
Analyze email content for phishing patterns.

**Request:**
```json
{
  "email": "From: support@paypa1.com\nSubject: URGENT: Your account is suspended!\n\nDear Customer, click here to verify..."
}
```

**Response:**
```json
{
  "risk_score": 72,
  "risk_level": "HIGH",
  "verdict": "🚨 Phishing Email Detected",
  "color": "danger",
  "reasons": [
    "Urgency tactics detected: 'urgent', 'suspended', 'verify' — creates panic to bypass critical thinking",
    "Generic greeting used — real companies address you by name",
    "Suspicious sender domain — does not match a legitimate organization"
  ],
  "recommendations": [
    "Do NOT click any links or download attachments",
    "Report to cybercrime.gov.in if you shared sensitive data"
  ],
  "links_found": 2,
  "analyzed_at": "2024-01-15T10:30:00.000Z"
}
```

---

### `GET /stats`
Retrieve dashboard statistics.

**Response:**
```json
{
  "total_scans": 47,
  "phishing_detected": 23,
  "suspicious": 8,
  "safe": 16,
  "url_scans": 35,
  "email_scans": 12,
  "recent_scans": [
    {
      "type": "url",
      "input": "http://amazon-prize-winner.tk...",
      "risk_level": "HIGH",
      "risk_score": 91,
      "timestamp": "2024-01-15 10:30"
    }
  ]
}
```

---

### `GET /health`
Check if the API is running.

**Response:**
```json
{
  "status": "PhishGuard API is running",
  "version": "1.0.0"
}
```

---

## 🧪 Test Cases

Try these URLs in the scanner to see it in action:

```bash
# Should score HIGH (phishing)
http://paypal-secure-login.xyz/verify?user=test@gmail.com
https://192.168.1.1/bank/login
http://amazon-account-update.tk/signin@user

# Should score MEDIUM (suspicious)
https://login-microsoft.com/auth
http://secure-banking-portal.net

# Should score LOW (safe)
https://google.com
https://github.com/microsoft/vscode
```

---

## 🎓 How the Scoring Works

PhishGuard uses a **weighted additive scoring model** — no machine learning, no training data:

```python
def calculate_score(url):
    score = 0

    if len(url) > 75:         score += 15   # Long URL
    if ip_in_domain(url):     score += 30   # IP address
    if "@" in url:            score += 25   # @ trick
    if subdomain_count > 4:   score += 15   # Too many subdomains
    if "-" in domain:         score += 10   # Hyphens
    if fake_https_kw(domain): score += 20   # fake-secure- etc
    if suspicious_words(url): score += 8×n  # Keywords
    if "//" in path:          score += 10   # Double slash
    if odd_port(url):         score += 15   # Port number
    if typosquatting(domain): score += 25   # Brand abuse
    if not https:             score += 10   # No encryption
    if new_domain(whois):     score += 15–30 # Domain age

    return min(score, 100)
```

Each rule is **independently explainable** — no black box, easy to defend in viva.

---

## 🔧 Configuration

You can adjust weights in `detector.py`:

```python
# detector.py — tune these values

URL_LENGTH_THRESHOLD = 75         # Characters
URL_LENGTH_SCORE     = 15         # Points

IP_ADDRESS_SCORE     = 30         # High weight — strong indicator
AT_SYMBOL_SCORE      = 25
SUBDOMAIN_SCORE      = 15
TYPOSQUATTING_SCORE  = 25

DOMAIN_AGE_NEW       = 30         # < 30 days
DOMAIN_AGE_RECENT    = 15         # < 180 days
```

---

## 🌱 Future Enhancements

| Feature | Status | Notes |
|---------|--------|-------|
| 🔌 Google Safe Browsing API | 🔜 Planned | Needs API key |
| 📱 Mobile PWA | 🔜 Planned | Offline support |
| 🧩 Browser Extension | 🔜 Planned | Chrome/Firefox |
| 📊 MongoDB backend | 🔜 Planned | Replace SQLite |
| 🖼️ URL Screenshot Preview | 🔜 Planned | Puppeteer |
| 📨 Email header parsing | 🔜 Planned | Full RFC 5322 |
| 🗃️ PhishTank integration | 🔜 Planned | Free API |

---

## 🛡️ Disclaimer

PhishGuard is an **educational cybersecurity project** built for academic demonstration purposes. It uses rule-based heuristics which may produce false positives/negatives. Do not rely on it as your sole security tool. Always use multiple layers of security.

---

## 📜 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

<div align="center">

**⚔ PhishGuard** — Don't Take The Bait.

Made with 💙 for cybersecurity awareness in India

[![Report Cybercrime](https://img.shields.io/badge/Report_Cybercrime-cybercrime.gov.in-red?style=flat-square)](https://cybercrime.gov.in)
[![Helpline](https://img.shields.io/badge/Helpline-1930-orange?style=flat-square)]()
[![CERT-In](https://img.shields.io/badge/CERT--In-cert--in.org.in-blue?style=flat-square)](https://cert-in.org.in)

</div>
