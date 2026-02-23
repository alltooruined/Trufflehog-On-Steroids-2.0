// popup.js — Trufflehog on Steroids² Dashboard Logic
import { getAllFindings, getFindingsByOrigin, clearOriginFindings, clearAllFindings, exportCSV, exportFindings, exportSARIF } from './db.js';
import { decodeJWT, analyzeJWT } from './jwt-analyzer.js';

// ── State ───────────────────────────────────────────────────────
let currentOrigin = "";
let allFindings = [];
let selectedFinding = null;

// ── Init ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]?.url) currentOrigin = new URL(tabs[0].url).origin;
  } catch {}
  await loadSettings();
  await refreshFindings();
  setupEventListeners();
});

// ── Settings ────────────────────────────────────────────────────
const ALL_TOGGLES = [
  'generics', 'specifics', 'aws', 'checkEnv', 'checkGit', 'alerts',
  'entropyScanning', 'jwtAnalysis', 'sourceMapScanning', 'networkInterception',
  'aiLocalAnalysis', 'piiDetection', 'securityHeaders', 'storageScanning', 'hydrationScanning',
];

const TOGGLE_DEFAULTS = {
  generics: true, specifics: true, aws: true,
  checkEnv: false, checkGit: false, alerts: true,
  entropyScanning: true, jwtAnalysis: true, sourceMapScanning: true,
  networkInterception: true, aiLocalAnalysis: true,
  piiDetection: true, securityHeaders: true, storageScanning: true, hydrationScanning: true,
};

async function loadSettings() {
  const keys = [...ALL_TOGGLES, 'originDenyList', 'aiClaudeApiKey'];
  const result = await chrome.storage.sync.get(keys);
  for (const toggle of ALL_TOGGLES) {
    const el = document.getElementById(toggle);
    if (!el) continue;
    el.checked = result[toggle] !== undefined ? result[toggle] : (TOGGLE_DEFAULTS[toggle] ?? true);
  }
  const denyListEl = document.getElementById('denyList');
  if (denyListEl && result.originDenyList) denyListEl.value = result.originDenyList.join(', ');
  if (result.aiClaudeApiKey) {
    const btn = document.getElementById('aiAnalyzeAll');
    if (btn) btn.disabled = false;
  }
}

function saveToggle(id) {
  const el = document.getElementById(id);
  if (!el) return;
  chrome.storage.sync.set({ [id]: el.checked });
}

// ── Findings ────────────────────────────────────────────────────
async function refreshFindings() {
  const scope = document.getElementById('scopeFilter')?.value || 'origin';
  allFindings = (scope === 'origin' && currentOrigin)
    ? await getFindingsByOrigin(currentOrigin)
    : await getAllFindings();
  renderFindings();
  updateStats();
}

function renderFindings() {
  const container = document.getElementById('findingsList');
  const sevFilter = document.getElementById('severityFilter')?.value || 'all';
  const typeFilter = document.getElementById('typeFilter')?.value || 'all';

  let filtered = allFindings;
  if (sevFilter !== 'all') filtered = filtered.filter(f => f.severity === sevFilter);
  if (typeFilter !== 'all') filtered = filtered.filter(f => (f.type || 'regex') === typeFilter);

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  filtered.sort((a, b) => {
    const d = (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4);
    return d !== 0 ? d : (b.timestamp || 0) - (a.timestamp || 0);
  });

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state">No findings match your filters</div>';
    return;
  }

  container.innerHTML = filtered.map((f, idx) => {
    const type = f.type || 'regex';
    const typeLabels = {
      regex: 'PAT', entropy: 'ENT', jwt: 'JWT', gitdir: 'GIT',
      pii: 'PII', 'security-header': 'HDR', cors: 'CORS', cookie: 'COOK',
    };
    const typeLabel = typeLabels[type] || type.toUpperCase().substring(0, 4);

    const aiBadge = f.aiAnalysis
      ? `<span class="ai-badge ${f.aiAnalysis.verdict}" title="AI: ${f.aiAnalysis.verdict} (${f.aiAnalysis.confidence}%)">${f.aiAnalysis.confidence}%</span>`
      : '';
    const cvss = f.aiAnalysis?.cvss
      ? `<span class="cvss-badge cvss-${f.aiAnalysis.cvss.rating.toLowerCase()}" title="CVSS: ${f.aiAnalysis.cvss.score}">${f.aiAnalysis.cvss.score}</span>`
      : '';

    const typeClass = `type-${type}`;
    return `
      <div class="finding-card severity-${f.severity}-card ${typeClass}" data-idx="${idx}">
        <div class="finding-header">
          <span class="finding-name">${esc(f.key)}</span>
          <div class="finding-badges">
            ${cvss}${aiBadge}
            <span class="type-badge">${typeLabel}</span>
            <span class="severity-badge ${f.severity}">${f.severity}</span>
          </div>
        </div>
        <div class="finding-match">${esc(f.match || '')}</div>
        <div class="finding-src">${esc(truncSrc(f.src || ''))}</div>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.finding-card').forEach(card => {
    card.addEventListener('click', () => showFindingDetail(filtered[parseInt(card.dataset.idx)]));
  });
}

function updateStats() {
  const stats = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  for (const f of allFindings) {
    stats[f.severity] = (stats[f.severity] || 0) + 1;
    stats.total++;
  }
  setText('#statCritical .stat-count', stats.critical);
  setText('#statHigh .stat-count', stats.high);
  setText('#statMedium .stat-count', stats.medium);
  setText('#statLow .stat-count', stats.low);
  document.getElementById('statTotal').textContent = stats.total;
}

// ── Finding Detail Modal ────────────────────────────────────────
function showFindingDetail(finding) {
  selectedFinding = finding;
  document.getElementById('modalTitle').textContent = finding.key;

  let html = '';
  html += row('Severity', `<span class="severity-badge ${finding.severity}">${finding.severity}</span>`);
  html += row('Type', finding.type || 'regex');
  if (finding.category) html += row('Category', `<span class="category-badge">${esc(finding.category)}</span>`);
  if (finding.mitre) html += row('MITRE', `<span class="mitre-badge">${esc(finding.mitre)}</span>`);
  html += row('Match', `<code>${esc(finding.fullMatch || finding.match || '')}</code>`);
  html += row('Source', esc(finding.src || ''));
  html += row('Page URL', esc(finding.parentUrl || ''));
  html += row('Origin', esc(finding.origin || ''));
  if (finding.encoded) html += row('Decoded From', esc(String(finding.encoded).substring(0, 40) + '...'));
  if (finding.entropy) html += row('Entropy', finding.entropy + ' bits/char');
  if (finding.piiType) html += row('PII Type', finding.piiType);
  if (finding.timestamp) html += row('Found', new Date(finding.timestamp).toLocaleString());

  // JWT details
  if (finding.type === 'jwt' && finding.decoded) {
    html += '<div class="jwt-section"><div class="jwt-section-title">JWT Header</div><pre style="white-space:pre-wrap;word-break:break-all;font-size:10px">' + esc(JSON.stringify(finding.decoded.header, null, 2)) + '</pre></div>';
    html += '<div class="jwt-section"><div class="jwt-section-title">JWT Payload</div><pre style="white-space:pre-wrap;word-break:break-all;font-size:10px">' + esc(JSON.stringify(finding.decoded.payload, null, 2)) + '</pre></div>';
    if (finding.analysis) {
      html += '<div class="jwt-section"><div class="jwt-section-title">JWT Analysis</div>';
      for (const w of finding.analysis) html += `<div class="jwt-warning ${w.severity}">${esc(w.issue)}</div>`;
      html += '</div>';
    }
  }

  // AI Analysis
  if (finding.aiAnalysis) {
    const ai = finding.aiAnalysis;
    const confColor = ai.confidence >= 70 ? 'var(--severity-critical)' : ai.confidence >= 40 ? 'var(--severity-medium)' : 'var(--severity-low)';
    html += `<div class="ai-reasoning">`;
    html += `<div class="ai-reasoning-title">🤖 AI Heuristic Analysis</div>`;
    html += `<div class="ai-confidence" style="background:${confColor}20;color:${confColor}">${ai.verdict.replace(/_/g, ' ').toUpperCase()} — ${ai.confidence}%</div>`;
    if (ai.cvss) html += `<span class="cvss-badge cvss-${ai.cvss.rating.toLowerCase()}">CVSS: ${ai.cvss.score} (${ai.cvss.rating})</span>`;
    for (const r of (ai.reasoning || [])) html += `<div class="ai-reasoning-item">• ${esc(r)}</div>`;
    html += `</div>`;
  }

  // Remediation
  if (finding.remediation) {
    html += `<div class="remediation-box"><div class="remediation-title">🔧 Remediation</div><div class="remediation-text">${esc(finding.remediation)}</div></div>`;
  }

  document.getElementById('modalBody').innerHTML = html;
  document.getElementById('findingModal').style.display = 'flex';
}

function row(label, value) {
  return `<div class="detail-row"><span class="detail-label">${label}</span><span class="detail-value">${value}</span></div>`;
}

// ── JWT Decoder Tool ────────────────────────────────────────────
function handleJWTDecode() {
  const input = document.getElementById('jwtInput').value.trim();
  const output = document.getElementById('jwtOutput');
  if (!input) return;
  const decoded = decodeJWT(input);
  if (!decoded) {
    output.style.display = 'block';
    output.innerHTML = '<span style="color:var(--severity-critical)">Invalid JWT format</span>';
    return;
  }
  const analysis = analyzeJWT(decoded);
  let html = '<div class="jwt-section"><div class="jwt-section-title">Header</div><pre>' + esc(JSON.stringify(decoded.header, null, 2)) + '</pre></div>';
  html += '<div class="jwt-section"><div class="jwt-section-title">Payload</div><pre>' + esc(JSON.stringify(decoded.payload, null, 2)) + '</pre></div>';
  html += '<div class="jwt-section"><div class="jwt-section-title">Analysis</div>';
  for (const w of analysis) html += `<div class="jwt-warning ${w.severity}">• ${esc(w.issue)}</div>`;
  html += '</div>';
  output.style.display = 'block';
  output.innerHTML = html;
}

// ── Event Listeners ─────────────────────────────────────────────
function setupEventListeners() {
  // Tabs
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab)?.classList.add('active');
    });
  });

  // Settings toggles
  for (const t of ALL_TOGGLES) {
    const el = document.getElementById(t);
    if (el) el.addEventListener('change', () => saveToggle(t));
  }

  // Deny list
  const dl = document.getElementById('denyList');
  if (dl) dl.addEventListener('input', () => {
    chrome.storage.sync.set({ originDenyList: dl.value.split(',').map(s => s.trim()).filter(Boolean) });
  });

  // API Key
  document.getElementById('saveApiKey')?.addEventListener('click', () => {
    const key = document.getElementById('aiClaudeApiKey').value.trim();
    chrome.storage.sync.set({ aiClaudeApiKey: key });
    const btn = document.getElementById('aiAnalyzeAll');
    if (btn) btn.disabled = !key;
  });

  // Filters
  for (const id of ['severityFilter', 'typeFilter', 'scopeFilter']) {
    document.getElementById(id)?.addEventListener('change', refreshFindings);
  }

  // Clear buttons
  document.getElementById('clearOrigin')?.addEventListener('click', async () => {
    if (currentOrigin) { await clearOriginFindings(currentOrigin); chrome.action.setBadgeText({ text: '' }); await refreshFindings(); }
  });
  document.getElementById('clearAll')?.addEventListener('click', async () => {
    await clearAllFindings(); chrome.action.setBadgeText({ text: '' }); await refreshFindings();
  });

  // Export buttons
  document.getElementById('exportJSON')?.addEventListener('click', async () => {
    downloadBlob(await exportFindings(), 'trufflehog-findings.json', 'application/json');
  });
  document.getElementById('exportCSV')?.addEventListener('click', async () => {
    downloadBlob(await exportCSV(), 'trufflehog-findings.csv', 'text/csv');
  });
  document.getElementById('exportSARIF')?.addEventListener('click', async () => {
    const sarif = await exportSARIF();
    downloadBlob(sarif, 'trufflehog-findings.sarif.json', 'application/json');
  });

  // JWT decoder
  document.getElementById('decodeJWT')?.addEventListener('click', handleJWTDecode);

  // Open tabs
  document.getElementById('openTabs')?.addEventListener('click', () => {
    const list = (document.getElementById('tabList')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
    chrome.runtime.sendMessage({ openTabs: list });
  });

  // Modal
  document.getElementById('closeModal')?.addEventListener('click', () => {
    document.getElementById('findingModal').style.display = 'none'; selectedFinding = null;
  });
  document.getElementById('findingModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'findingModal') document.getElementById('findingModal').style.display = 'none';
  });
  document.getElementById('modalCopyMatch')?.addEventListener('click', () => {
    if (selectedFinding) navigator.clipboard.writeText(selectedFinding.fullMatch || selectedFinding.match || '');
  });

  // AI Deep Analysis
  document.getElementById('modalAiAnalyze')?.addEventListener('click', async () => {
    if (!selectedFinding) return;
    const btn = document.getElementById('modalAiAnalyze');
    btn.textContent = '🤖 Analyzing...'; btn.disabled = true;
    chrome.runtime.sendMessage({ aiDeepAnalysis: true, finding: selectedFinding }, (response) => {
      btn.textContent = '🤖 Analyze with Claude'; btn.disabled = false;
      if (response?.aiAnalysis) {
        const ai = response.aiAnalysis;
        document.getElementById('modalBody').innerHTML += `<div class="ai-reasoning" style="margin-top:10px">
          <div class="ai-reasoning-title">🤖 Claude Deep Analysis</div>
          <div class="ai-confidence">${ai.confidence}% confidence — ${ai.is_real_secret ? 'REAL SECRET' : 'Likely not real'}</div>
          <div class="ai-reasoning-item"><strong>Impact:</strong> ${esc(ai.impact || 'N/A')}</div>
          <div class="ai-reasoning-item"><strong>Explanation:</strong> ${esc(ai.explanation || '')}</div>
          ${(ai.remediation || []).map(r => `<div class="ai-reasoning-item">→ ${esc(r)}</div>`).join('')}
        </div>`;
      } else if (response?.error) {
        alert('AI Analysis Error: ' + response.error);
      }
    });
  });

  // AI Analyze All Critical
  document.getElementById('aiAnalyzeAll')?.addEventListener('click', async () => {
    const criticals = allFindings.filter(f => f.severity === 'critical');
    if (criticals.length === 0) { alert('No critical findings to analyze'); return; }
    alert(`Starting AI analysis of ${criticals.length} critical finding(s)...`);
    for (const f of criticals) chrome.runtime.sendMessage({ aiDeepAnalysis: true, finding: f });
  });
}

// ── Utilities ───────────────────────────────────────────────────
function esc(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function setText(sel, val) { const el = document.querySelector(sel); if (el) el.textContent = val; }
function truncSrc(s) { return s.length > 60 ? s.substring(0, 30) + '...' + s.substring(s.length - 25) : s; }
function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}
