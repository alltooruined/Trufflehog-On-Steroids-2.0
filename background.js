// background.js — Trufflehog on Steroids²: Service Worker Orchestrator
// Coordinates all detection engines: patterns, entropy, JWT, PII, security headers, AI

import { specifics, generics, aws, getRegexMap, getSeverity, getPatternMeta, denyList } from './patterns.js';
import { scanEntropy } from './entropy.js';
import { scanJWTs } from './jwt-analyzer.js';
import { scanPII } from './pii-detector.js';
import { analyzeSecurityHeaders, analyzeCORS, analyzeCookies } from './security-scanner.js';
import { addFinding, getFindingsByOrigin, getStats, exportSARIF } from './db.js';
import { analyzeLocal, analyzeWithClaude } from './ai-checker.js';

const VERSION = "3.0.0";

// ── Initialization ──────────────────────────────────────────────
chrome.storage.sync.get(['ranOnce_v3'], function(result) {
  if (!result.ranOnce_v3) {
    chrome.storage.sync.set({
      ranOnce_v3: true,
      originDenyList: ["https://www.google.com", "https://www.youtube.com"],
      generics: true,
      specifics: true,
      aws: true,
      checkEnv: false,
      checkGit: false,
      alerts: true,
      entropyScanning: true,
      jwtAnalysis: true,
      sourceMapScanning: true,
      networkInterception: true,
      aiLocalAnalysis: true,
      aiClaudeApiKey: "",
      piiDetection: true,
      securityHeaders: true,
      storageScanning: true,
      hydrationScanning: true,
    });
  }
});

function getSettings() {
  return new Promise(resolve => {
    chrome.storage.sync.get([
      'generics', 'specifics', 'aws', 'checkEnv', 'checkGit', 'alerts',
      'entropyScanning', 'jwtAnalysis', 'sourceMapScanning', 'networkInterception',
      'aiLocalAnalysis', 'aiClaudeApiKey', 'originDenyList',
      'piiDetection', 'securityHeaders', 'storageScanning', 'hydrationScanning',
    ], resolve);
  });
}

function buildRegexMap(settings) {
  const sets = [];
  if (settings.generics !== false) sets.push(generics);
  if (settings.specifics !== false) sets.push(specifics);
  if (settings.aws !== false) sets.push(aws);
  return getRegexMap(sets);
}

function isOriginDenied(url, denyListArr) {
  if (!denyListArr || !Array.isArray(denyListArr)) return false;
  return denyListArr.some(origin => url.startsWith(origin));
}

// ── Base64 decoding ─────────────────────────────────────────────
function getStringsOfSet(word, charSet, threshold = 20) {
  let count = 0, letters = "", strings = [];
  if (!word) return [];
  for (const char of word) {
    if (charSet.indexOf(char) > -1) { letters += char; count++; }
    else { if (count > threshold) strings.push(letters); letters = ""; count = 0; }
  }
  if (count > threshold) strings.push(letters);
  return strings;
}

function getDecodedB64(inputString) {
  const b64CharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  const encodeds = getStringsOfSet(inputString, b64CharSet);
  const decodeds = [];
  for (const encoded of encodeds) {
    try { decodeds.push([encoded, atob(encoded)]); } catch {}
  }
  return decodeds;
}

// ── Core scanner ────────────────────────────────────────────────
async function checkData(data, src, regexes, settings, fromEncoded = false, parentUrl = "", parentOrigin = "") {
  if (!data || data.length === 0) return;
  const findings = [];

  // 1. Regex pattern matching
  for (const key in regexes) {
    const re = new RegExp(regexes[key]);
    let match = re.exec(data);
    if (Array.isArray(match)) match = match.toString();
    if (denyList.includes(match)) continue;
    if (match) {
      const severity = getSeverity(key);
      const meta = getPatternMeta(key);
      const finding = {
        src, match, key, severity, type: "regex",
        category: meta.category || "generic",
        encoded: fromEncoded || undefined,
        parentUrl, origin: parentOrigin,
        verify: meta.verify || null,
        remediation: meta.remediation || null,
        mitre: meta.mitre || null,
      };
      if (settings.aiLocalAnalysis !== false) {
        const contextStart = Math.max(0, data.indexOf(match) - 80);
        const contextEnd = Math.min(data.length, data.indexOf(match) + match.length + 80);
        finding.aiAnalysis = analyzeLocal(finding, data.substring(contextStart, contextEnd));
      }
      findings.push(finding);
    }
  }

  // 2. JWT analysis
  if (settings.jwtAnalysis !== false) {
    for (const jf of scanJWTs(data, src)) {
      jf.origin = parentOrigin; jf.parentUrl = parentUrl;
      if (settings.aiLocalAnalysis !== false) jf.aiAnalysis = analyzeLocal(jf);
      findings.push(jf);
    }
  }

  // 3. Entropy analysis
  if (settings.entropyScanning !== false) {
    for (const ef of scanEntropy(data, src)) {
      ef.origin = parentOrigin; ef.parentUrl = parentUrl;
      if (settings.aiLocalAnalysis !== false) {
        const idx = data.indexOf(ef.fullMatch || ef.match);
        const ctx = data.substring(Math.max(0, idx - 80), Math.min(data.length, idx + (ef.fullMatch || ef.match).length + 80));
        ef.aiAnalysis = analyzeLocal(ef, ctx);
      }
      findings.push(ef);
    }
  }

  // 4. PII detection
  if (settings.piiDetection !== false) {
    for (const pf of scanPII(data, src)) {
      pf.origin = parentOrigin; pf.parentUrl = parentUrl;
      if (settings.aiLocalAnalysis !== false) pf.aiAnalysis = analyzeLocal(pf);
      findings.push(pf);
    }
  }

  // 5. Store & notify
  for (const finding of findings) {
    const added = await addFinding(finding);
    if (added) notifyFinding(finding, settings);
  }

  // 6. Recurse into base64
  const decodedStrings = getDecodedB64(data);
  for (const [encoded, decoded] of decodedStrings) {
    await checkData(decoded, src, regexes, settings, encoded, parentUrl, parentOrigin);
  }
}

// ── Security header analysis handler ────────────────────────────
async function handleSecurityHeaders(headers, url, parentUrl, parentOrigin, settings) {
  if (settings.securityHeaders === false) return;
  const findings = [
    ...analyzeSecurityHeaders(headers, url),
    ...analyzeCORS(headers, url, parentOrigin),
  ];

  // Cookie analysis from set-cookie
  const setCookie = headers["set-cookie"] || headers["Set-Cookie"];
  if (setCookie) {
    findings.push(...analyzeCookies(setCookie, url));
  }

  for (const f of findings) {
    f.origin = parentOrigin; f.parentUrl = parentUrl;
    if (settings.aiLocalAnalysis !== false) f.aiAnalysis = analyzeLocal(f);
    const added = await addFinding(f);
    if (added) notifyFinding(f, settings);
  }
}

// ── Source map scanning ─────────────────────────────────────────
async function scanSourceMap(url, settings, regexes, parentUrl, parentOrigin) {
  try {
    const response = await fetch(url, { credentials: 'omit' });
    if (!response.ok) return;
    const text = await response.text();
    try {
      const map = JSON.parse(text);
      if (map.sources && map.sourcesContent) {
        for (let i = 0; i < map.sourcesContent.length; i++) {
          const content = map.sourcesContent[i];
          const sourceName = map.sources[i] || `source[${i}]`;
          if (content && content.length > 0) {
            await checkData(content, `${url} → ${sourceName}`, regexes, settings, false, parentUrl, parentOrigin);
          }
        }
      }
    } catch {
      if (text.length > 100) await checkData(text, url, regexes, settings, false, parentUrl, parentOrigin);
    }
  } catch {}
}

// ── .git/config analysis ────────────────────────────────────────
async function checkForGitDir(data, url, parentUrl, parentOrigin) {
  if (!data.startsWith("[core]")) return;
  const remoteRegex = /url\s*=\s*(.+)/g;
  let match;
  const remotes = [];
  while ((match = remoteRegex.exec(data)) !== null) remotes.push(match[1].trim());

  const finding = {
    key: "Exposed .git/config", match: `.git dir at ${url}` + (remotes.length > 0 ? ` — remotes: ${remotes.join(', ')}` : ''),
    src: url, severity: "critical", type: "gitdir", category: "infra",
    origin: parentOrigin, parentUrl, remotes,
  };
  const added = await addFinding(finding);
  if (added) notifyFinding(finding, await getSettings());

  for (const remote of remotes) {
    if (remote.match(/\/\/[^:]+:[^@]+@/)) {
      await addFinding({
        key: "Credentials in .git remote URL", match: remote, src: url,
        severity: "critical", type: "regex", category: "scm", origin: parentOrigin, parentUrl,
      });
    }
  }
}

// ── Notifications ───────────────────────────────────────────────
function notifyFinding(finding, settings) {
  if (settings.alerts === false) return;
  const emoji = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" };
  let msg = `${emoji[finding.severity] || "⚪"} [${finding.severity.toUpperCase()}] ${finding.key}: ${finding.match}`;
  if (finding.aiAnalysis) msg += ` | AI: ${finding.aiAnalysis.verdict} (${finding.aiAnalysis.confidence}%)`;
  chrome.notifications.create({
    type: 'basic', iconUrl: 'icon128.png',
    title: `Trufflehog² — ${finding.severity.toUpperCase()}`,
    message: msg.substring(0, 400),
  });
  updateBadge();
}

async function updateBadge() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs?.[0]?.url) return;
    const origin = new URL(tabs[0].url).origin;
    const findings = await getFindingsByOrigin(origin);
    const count = findings.length;
    const hasCritical = findings.some(f => f.severity === "critical");
    chrome.action.setBadgeText({ text: count > 0 ? count.toString() : "" });
    chrome.action.setBadgeBackgroundColor({ color: hasCritical ? '#ff0000' : count > 0 ? '#ff8800' : '#888888' });
  } catch {}
}

chrome.tabs.onActivated.addListener(() => updateBadge());

// ── Message handler ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  (async () => {
    const settings = await getSettings();
    const regexes = buildRegexMap(settings);
    const denied = isOriginDenied(request.parentOrigin || request.origin || "", settings.originDenyList);
    if (denied && !request.getStats && !request.aiDeepAnalysis && !request.openTabs && !request.exportSARIF) return;

    // Page body scan
    if (request.pageBody) {
      await checkData(request.pageBody, request.origin, regexes, settings, false, request.parentUrl, request.parentOrigin);
    }
    // External script scan
    else if (request.scriptUrl) {
      try {
        const response = await fetch(request.scriptUrl, { credentials: 'include' });
        const data = await response.text();
        await checkData(data, request.scriptUrl, regexes, settings, false, request.parentUrl, request.parentOrigin);
        if (settings.sourceMapScanning !== false) {
          const mapMatch = data.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
          if (mapMatch) {
            let mapUrl = mapMatch[1];
            if (!mapUrl.startsWith("http") && !mapUrl.startsWith("data:")) {
              mapUrl = request.scriptUrl.substring(0, request.scriptUrl.lastIndexOf('/') + 1) + mapUrl;
            }
            if (!mapUrl.startsWith("data:")) await scanSourceMap(mapUrl, settings, regexes, request.parentUrl, request.parentOrigin);
          }
        }
      } catch {}
    }
    // Source map scan
    else if (request.sourceMapUrl) {
      if (settings.sourceMapScanning !== false) await scanSourceMap(request.sourceMapUrl, settings, regexes, request.parentUrl, request.parentOrigin);
    }
    // Network interception (XHR/fetch/WS/SSE)
    else if (request.networkBody) {
      if (settings.networkInterception !== false) {
        await checkData(request.networkBody, `[${request.networkType}] ${request.networkUrl}`, regexes, settings, false, request.parentUrl, request.parentOrigin);
      }
    }
    // Full response headers → security analysis
    else if (request.fullResponseHeaders) {
      await handleSecurityHeaders(request.fullResponseHeaders, request.networkUrl, request.parentUrl, request.parentOrigin, settings);
      // Also scan header values for secrets
      const authHeader = request.fullResponseHeaders["authorization"] || "";
      if (authHeader) await checkData(authHeader, `[header:authorization] ${request.networkUrl}`, regexes, settings, false, request.parentUrl, request.parentOrigin);
    }
    // Legacy response headers
    else if (request.responseHeaders) {
      const h = request.responseHeaders;
      if (h.authorization) await checkData(h.authorization, `[header:authorization] ${request.networkUrl}`, regexes, settings, false, request.parentUrl, request.parentOrigin);
      if (h.setCookie) {
        await checkData(h.setCookie, `[header:set-cookie] ${request.networkUrl}`, regexes, settings, false, request.parentUrl, request.parentOrigin);
        const cookieFindings = analyzeCookies(h.setCookie, request.networkUrl);
        for (const cf of cookieFindings) {
          cf.origin = request.parentOrigin; cf.parentUrl = request.parentUrl;
          await addFinding(cf);
        }
      }
    }
    // Request body
    else if (request.requestBody) {
      if (settings.networkInterception !== false) {
        await checkData(request.requestBody, `[request-body] ${request.networkUrl}`, regexes, settings, false, request.parentUrl, request.parentOrigin);
      }
    }
    // localStorage/sessionStorage
    else if (request.storageData) {
      if (settings.storageScanning !== false) {
        for (const item of request.storageData) {
          await checkData(item.value, `[storage:${item.key}]`, regexes, settings, false, request.parentUrl, request.parentOrigin);
        }
      }
    }
    // Hydration data (__NEXT_DATA__, etc.)
    else if (request.hydrationData) {
      if (settings.hydrationScanning !== false) {
        await checkData(request.hydrationData, `[${request.hydrationKey}]`, regexes, settings, false, request.parentUrl, request.parentOrigin);
      }
    }
    // Dynamic content (mutation observer)
    else if (request.dynamicContent) {
      await checkData(request.dynamicContent, `[dynamic-dom]`, regexes, settings, false, request.parentUrl, request.parentOrigin);
    }
    // Meta tag content
    else if (request.metaContent) {
      await checkData(request.metaContent, `[meta:${request.metaName}]`, regexes, settings, false, request.parentUrl, request.parentOrigin);
    }
    // Data attributes
    else if (request.dataAttribute) {
      await checkData(request.dataAttribute, `[${request.dataName}]`, regexes, settings, false, request.parentUrl, request.parentOrigin);
    }
    // .env check
    else if (request.envFile) {
      if (settings.checkEnv) {
        try {
          const response = await fetch(request.envFile, { credentials: 'include' });
          const data = await response.text();
          if (data && !data.includes("<!DOCTYPE") && !data.includes("<html")) {
            await checkData(data, ".env file at " + request.envFile, regexes, settings, false, request.parentUrl, request.parentOrigin);
          }
        } catch {}
      }
    }
    // .git check
    else if (request.gitDir) {
      if (settings.checkGit) {
        try {
          const response = await fetch(request.gitDir, { credentials: 'include' });
          const data = await response.text();
          await checkForGitDir(data, request.gitDir, request.parentUrl, request.parentOrigin);
        } catch {}
      }
    }
    // Open tabs
    else if (request.openTabs) {
      for (const tab of request.openTabs) chrome.tabs.create({ url: tab });
    }
    // Get stats
    else if (request.getStats) {
      sendResponse(await getStats());
    }
    // SARIF export
    else if (request.exportSARIF) {
      const sarif = await exportSARIF();
      sendResponse({ sarif });
    }
    // AI deep analysis
    else if (request.aiDeepAnalysis) {
      if (settings.aiClaudeApiKey) {
        sendResponse(await analyzeWithClaude(request.finding, settings.aiClaudeApiKey));
      } else {
        sendResponse({ error: "No Claude API key configured" });
      }
    }
  })();
  return true;
});

// ── Monitor network for source maps via headers ─────────────────
chrome.webRequest.onHeadersReceived.addListener(
  async function(details) {
    const settings = await getSettings();
    if (settings.sourceMapScanning === false) return;
    const headers = details.responseHeaders || [];
    for (const header of headers) {
      if (header.name.toLowerCase() === "sourcemap" || header.name.toLowerCase() === "x-sourcemap") {
        let mapUrl = header.value;
        if (!mapUrl.startsWith("http")) {
          mapUrl = details.url.substring(0, details.url.lastIndexOf('/') + 1) + mapUrl;
        }
        const regexes = buildRegexMap(settings);
        const tab = details.tabId >= 0 ? await chrome.tabs.get(details.tabId).catch(() => null) : null;
        const parentUrl = tab?.url || details.url;
        const parentOrigin = tab ? new URL(tab.url).origin : new URL(details.url).origin;
        await scanSourceMap(mapUrl, settings, regexes, parentUrl, parentOrigin);
      }
    }
  },
  { urls: ["<all_urls>"], types: ["script"] },
  ["responseHeaders"]
);

console.log(`[Trufflehog on Steroids² v${VERSION}] Service worker loaded — Enterprise Edition`);
