/* ═══════════════════════════════════════════
   PHISHGUARD — Frontend Script
═══════════════════════════════════════════ */

const API_BASE = 'http://localhost:5000/api';

// ── TERMINAL DEMO ──────────────────────────────────────────────────────────
const terminalLines = [
  { text: '$ phishguard --scan "http://paypal-secure.xyz/login"', cls: 't-cmd', delay: 300 },
  { text: '', delay: 200 },
  { text: '  ◆ Analyzing URL structure...', cls: 't-dim', delay: 600 },
  { text: '  ◆ Checking domain age via WHOIS...', cls: 't-dim', delay: 500 },
  { text: '  ◆ Running 12 detection rules...', cls: 't-dim', delay: 700 },
  { text: '', delay: 200 },
  { text: '  [✗] Domain contains "paypal" — possible typosquatting', cls: 't-warn', delay: 400 },
  { text: '  [✗] Domain contains "secure" — fake trust signal', cls: 't-warn', delay: 300 },
  { text: '  [✗] Domain registered 3 days ago', cls: 't-danger', delay: 300 },
  { text: '  [✗] Keyword "login" in URL path', cls: 't-warn', delay: 300 },
  { text: '', delay: 200 },
  { text: '  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', cls: 't-dim', delay: 100 },
  { text: '  RISK SCORE: 87/100 — 🚨 PHISHING', cls: 't-danger', delay: 400 },
  { text: '  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', cls: 't-dim', delay: 100 },
  { text: '', delay: 400 },
  { text: '$ _', cls: 't-cmd', delay: 100 },
];

async function runTerminalDemo() {
  const el = document.getElementById('terminal-demo');
  if (!el) return;
  el.innerHTML = '';

  for (const line of terminalLines) {
    await sleep(line.delay);
    const p = document.createElement('p');
    p.className = line.cls || '';
    p.textContent = line.text;
    el.appendChild(p);
    el.scrollTop = el.scrollHeight;
  }

  // Loop after pause
  await sleep(3000);
  runTerminalDemo();
}

// ── SCAN URL ───────────────────────────────────────────────────────────────
async function scanURL() {
  const input = document.getElementById('url-input');
  const btn = document.getElementById('url-scan-btn');
  const resultEl = document.getElementById('url-result');
  const url = input.value.trim();

  if (!url) {
    shakeInput(input);
    return;
  }

  setBtnLoading(btn, true);
  resultEl.hidden = true;

  try {
    const res = await fetch(`${API_BASE}/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    renderURLResult(resultEl, data);
    resultEl.hidden = false;
    loadDashboard();
  } catch (err) {
    renderError(resultEl, 'Cannot connect to PhishGuard backend. Make sure Flask is running on port 5000.');
    resultEl.hidden = false;
  } finally {
    setBtnLoading(btn, false);
  }
}

function renderURLResult(el, d) {
  const color = d.color || 'safe';
  const reasons = d.reasons || [];
  const recos = d.recommendations || [];

  const reasonIcon = color === 'danger' ? '✗' : color === 'warning' ? '!' : '✓';

  el.innerHTML = `
    <div class="result-header ${color}">
      <div class="result-verdict">${d.verdict}</div>
      <div class="result-score ${color}">Risk Score: ${d.risk_score}/100</div>
    </div>
    <div class="result-body">
      <div class="result-url-display">🔗 ${escHtml(d.url || '')}</div>

      <div class="score-bar-wrap">
        <div class="score-bar-label">
          <span>Risk Level</span>
          <span>${d.risk_score}%</span>
        </div>
        <div class="score-bar-bg">
          <div class="score-bar-fill ${color}" style="width:0%" id="score-fill-url"></div>
        </div>
      </div>

      <div class="reasons-title">Why This Score?</div>
      <ul class="reasons-list">
        ${reasons.map(r => `
          <li class="reason-item ${color}">
            <span class="reason-icon">${reasonIcon}</span>
            <span>${escHtml(r)}</span>
          </li>`).join('')}
      </ul>

      <div class="divider"></div>
      <div class="reco-title">What To Do</div>
      <ul class="reco-list">
        ${recos.map(r => `<li class="reco-item">${escHtml(r)}</li>`).join('')}
      </ul>

      <div style="margin-top:1rem; font-family: var(--mono); font-size:0.68rem; color:var(--text3)">
        Analyzed at ${d.analyzed_at || new Date().toISOString()} · ${d.checks_performed || 12} rules checked
      </div>
    </div>
  `;

  // Animate bar
  requestAnimationFrame(() => {
    const fill = document.getElementById('score-fill-url');
    if (fill) fill.style.width = d.risk_score + '%';
  });
}

// ── SCAN EMAIL ─────────────────────────────────────────────────────────────
async function scanEmail() {
  const input = document.getElementById('email-input');
  const btn = input.nextElementSibling;
  const resultEl = document.getElementById('email-result');
  const content = input.value.trim();

  if (!content) {
    shakeInput(input);
    return;
  }

  setBtnLoading(btn, true);
  resultEl.hidden = true;

  try {
    const res = await fetch(`${API_BASE}/scan/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: content })
    });
    const data = await res.json();
    renderEmailResult(resultEl, data);
    resultEl.hidden = false;
    loadDashboard();
  } catch (err) {
    renderError(resultEl, 'Cannot connect to PhishGuard backend. Make sure Flask is running on port 5000.');
    resultEl.hidden = false;
  } finally {
    setBtnLoading(btn, false);
  }
}

function renderEmailResult(el, d) {
  const color = d.color || 'safe';
  const reasons = d.reasons || [];
  const recos = d.recommendations || [];
  const reasonIcon = color === 'danger' ? '✗' : color === 'warning' ? '!' : '✓';

  el.innerHTML = `
    <div class="result-header ${color}">
      <div class="result-verdict">${d.verdict}</div>
      <div class="result-score ${color}">Risk Score: ${d.risk_score}/100</div>
    </div>
    <div class="result-body">
      <div class="score-bar-wrap">
        <div class="score-bar-label">
          <span>Phishing Probability</span>
          <span>${d.risk_score}%</span>
        </div>
        <div class="score-bar-bg">
          <div class="score-bar-fill ${color}" style="width:0%" id="score-fill-email"></div>
        </div>
      </div>

      ${d.links_found !== undefined ? `<div style="font-family:var(--mono);font-size:0.72rem;color:var(--text3);margin-bottom:1rem">📎 ${d.links_found} link(s) found in email body</div>` : ''}

      <div class="reasons-title">Detection Findings</div>
      <ul class="reasons-list">
        ${reasons.map(r => `
          <li class="reason-item ${color}">
            <span class="reason-icon">${reasonIcon}</span>
            <span>${escHtml(r)}</span>
          </li>`).join('')}
      </ul>

      <div class="divider"></div>
      <div class="reco-title">Recommended Actions</div>
      <ul class="reco-list">
        ${recos.map(r => `<li class="reco-item">${escHtml(r)}</li>`).join('')}
      </ul>
    </div>
  `;

  requestAnimationFrame(() => {
    const fill = document.getElementById('score-fill-email');
    if (fill) fill.style.width = d.risk_score + '%';
  });
}

// ── DASHBOARD ──────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    const d = await res.json();

    animateNum('d-total', d.total_scans);
    animateNum('d-phishing', d.phishing_detected);
    animateNum('d-suspicious', d.suspicious);
    animateNum('d-safe', d.safe);
    animateNum('hero-total', d.total_scans);
    animateNum('hero-caught', d.phishing_detected + d.suspicious);

    renderRecentScans(d.recent_scans || []);
  } catch (err) {
    // API not available
  }
}

function renderRecentScans(scans) {
  const el = document.getElementById('recent-list');
  if (!el) return;

  if (scans.length === 0) {
    el.innerHTML = '<div class="empty-row">No scans yet — scan a URL or email above!</div>';
    return;
  }

  el.innerHTML = scans.map(s => `
    <div class="recent-row">
      <span class="recent-type ${s.type}">${s.type.toUpperCase()}</span>
      <span class="recent-input">${escHtml(s.input)}</span>
      <span class="badge ${s.risk_level}">${s.risk_level}</span>
      <span class="recent-time">${s.timestamp}</span>
    </div>
  `).join('');
}

// ── HELPERS ────────────────────────────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function setBtnLoading(btn, loading) {
  if (!btn) return;
  const text = btn.querySelector('.btn-text');
  const loader = btn.querySelector('.btn-loader');
  btn.disabled = loading;
  if (text) text.hidden = loading;
  if (loader) loader.hidden = !loading;
}

function shakeInput(el) {
  el.classList.add('shake');
  el.focus();
  setTimeout(() => el.classList.remove('shake'), 500);
}

function animateNum(id, target) {
  const el = document.getElementById(id);
  if (!el || target === undefined) return;
  const start = parseInt(el.textContent) || 0;
  const end = parseInt(target) || 0;
  const duration = 600;
  const startTime = performance.now();

  function update(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (end - start) * eased);
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

function renderError(el, msg) {
  el.innerHTML = `
    <div class="result-header warning">
      <div class="result-verdict">⚠️ Connection Error</div>
    </div>
    <div class="result-body">
      <p style="color:var(--text2);font-size:0.85rem">${msg}</p>
    </div>
  `;
}

function scrollToSection(id) {
  const el = document.getElementById(id);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── NAV ACTIVE ─────────────────────────────────────────────────────────────
function updateActiveNav() {
  const sections = ['scanner', 'email', 'dashboard', 'report'];
  const links = document.querySelectorAll('.nav-link');

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        links.forEach(l => l.classList.remove('active'));
        const active = document.querySelector(`.nav-link[data-section="${entry.target.id}"]`);
        if (active) active.classList.add('active');
      }
    });
  }, { threshold: 0.4 });

  sections.forEach(id => {
    const el = document.getElementById(id);
    if (el) observer.observe(el);
  });
}

// ── ENTER KEY ──────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const urlInput = document.getElementById('url-input');
  if (urlInput) {
    urlInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') scanURL();
    });
  }

  runTerminalDemo();
  loadDashboard();
  updateActiveNav();
});
