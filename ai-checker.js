// ai-checker.js — AI-powered secret analysis with CVSS-style scoring
// Enhanced for Trufflehog on Steroids²

import { shannonEntropy } from './entropy.js';

// ─── LOCAL HEURISTIC ENGINE ──────────────────────────────────────────

/**
 * Multi-signal scoring to classify a finding's confidence level
 * Returns { confidence: 0-100, verdict, reasoning, cvss }
 */
export function analyzeLocal(finding, contextSnippet = "") {
  let score = 50;
  const reasoning = [];
  const matchStr = finding.fullMatch || finding.match || "";
  const key = finding.key || "";
  const src = finding.src || "";

  // ── Signal 1: Pattern specificity ──
  const criticalPatterns = [
    "AWS Access Key", "AWS Secret", "AWS API Key", "Private Key", "SSH Private Key",
    "Database Connection", "MongoDB SRV", "Redis Connection",
    "Stripe Secret Key", "PlanetScale", "HashiCorp Vault",
    "GCP Service Account", "Azure Storage Account",
  ];
  const highPatterns = [
    "GitHub Personal Access Token", "GitLab Personal Access Token",
    "Slack Bot Token", "Slack User Token",
    "SendGrid API Key", "OpenAI API Key", "Anthropic API Key",
    "Bearer Token", "Credit Card",
  ];
  if (criticalPatterns.some(p => key.includes(p))) {
    score += 30;
    reasoning.push("Matched a critical-severity pattern with distinct format");
  } else if (highPatterns.some(p => key.includes(p))) {
    score += 20;
    reasoning.push("Matched a high-specificity pattern with unique prefix");
  } else if (key.startsWith("Generic")) {
    score -= 15;
    reasoning.push("Generic pattern match — higher false positive risk");
  }

  // ── Signal 2: Entropy analysis ──
  const entropy = shannonEntropy(matchStr);
  if (entropy > 5.0) {
    score += 15;
    reasoning.push(`Very high entropy (${entropy.toFixed(2)} bits/char) — strongly random`);
  } else if (entropy > 4.2) {
    score += 8;
    reasoning.push(`Moderate-high entropy (${entropy.toFixed(2)} bits/char)`);
  } else if (entropy < 2.5) {
    score -= 20;
    reasoning.push(`Low entropy (${entropy.toFixed(2)} bits/char) — likely static identifier`);
  }

  // ── Signal 3: Source context ──
  const srcLower = src.toLowerCase();
  const criticalSources = [".env", ".git/config", "credential", "secrets.", ".pem"];
  const riskySources = ["config", "secret", "internal", "admin", "private", "settings"];
  const safeSources = ["cdn", "jquery", "bootstrap", "react", "angular", "vue", "polyfill", "analytics", "gtag", "fonts.", "fontawesome", "node_modules"];

  if (criticalSources.some(p => srcLower.includes(p))) {
    score += 20;
    reasoning.push("Found in a critical security-sensitive source");
  } else if (riskySources.some(p => srcLower.includes(p))) {
    score += 10;
    reasoning.push("Found in a potentially sensitive source file");
  }
  if (safeSources.some(p => srcLower.includes(p))) {
    score -= 15;
    reasoning.push("Found in a common library/CDN — likely false positive");
  }

  // ── Signal 4: Context keywords (enhanced) ──
  const ctxLower = (contextSnippet || "").toLowerCase();
  const strongSecretWords = ["secret_key", "private_key", "api_key", "access_key", "client_secret", "auth_token", "password", "database_url"];
  const mediumSecretWords = ["secret", "private", "credential", "auth", "token", "key"];
  const benignWords = ["example", "placeholder", "test", "sample", "demo", "fake", "xxx", "todo", "dummy", "mock", "stub", "fixture", "spec"];

  const strongHits = strongSecretWords.filter(w => ctxLower.includes(w)).length;
  const mediumHits = mediumSecretWords.filter(w => ctxLower.includes(w)).length;
  const benignHits = benignWords.filter(w => ctxLower.includes(w)).length;

  if (strongHits > 0) {
    score += strongHits * 8;
    reasoning.push(`Context has ${strongHits} strong secret indicator(s)`);
  } else if (mediumHits > 0) {
    score += mediumHits * 3;
    reasoning.push(`Context has ${mediumHits} secret-related keyword(s)`);
  }
  if (benignHits > 0) {
    score -= benignHits * 12;
    reasoning.push(`Context has ${benignHits} test/placeholder keyword(s) — likely not real`);
  }

  // ── Signal 5: Known test/example values ──
  const testIndicators = [
    /test|example|sample|demo|fake|placeholder|xxx|000|123|deadbeef/i,
    /sk-proj-[a-zA-Z]{10,}$/,  // Non-random project key
    /your[_-]?(?:api|secret|token|key)/i,
    /INSERT[_-]?(?:YOUR|API|KEY|TOKEN)/i,
    /TODO|FIXME|CHANGEME|REPLACEME/i,
  ];
  if (testIndicators.some(p => p.test(matchStr) || p.test(ctxLower))) {
    score -= 25;
    reasoning.push("Contains test/placeholder indicators");
  }

  // ── Signal 6: Length analysis ──
  if (matchStr.length > 100) {
    score += 5;
    reasoning.push("Long secret value — less likely false positive");
  } else if (matchStr.length < 16 && !criticalPatterns.some(p => key.includes(p))) {
    score -= 10;
    reasoning.push("Short match — could be partial/FP");
  }

  // ── Signal 7: Base64 encoded content ──
  if (finding.encoded) {
    score += 10;
    reasoning.push("Found after base64 decode — intentionally obfuscated");
  }

  // ── Signal 8: JWT-specific ──
  if (finding.type === "jwt" && finding.analysis) {
    const criticals = finding.analysis.filter(a => a.severity === "critical").length;
    const highs = finding.analysis.filter(a => a.severity === "high").length;
    if (criticals > 0) { score += 20; reasoning.push(`JWT has ${criticals} critical issue(s)`); }
    if (highs > 0) { score += 10; reasoning.push(`JWT has ${highs} high-severity issue(s)`); }
  }

  // ── Signal 9: Entropy-only ──
  if (finding.type === "entropy") {
    score -= 10;
    reasoning.push("Entropy-only detection — review recommended");
  }

  // ── Signal 10: PII type ──
  if (finding.type === "pii") {
    if (finding.piiType === "credit_card") { score += 15; reasoning.push("Luhn-validated credit card number"); }
    else if (finding.piiType === "ssn") { score += 10; reasoning.push("SSN format with context match"); }
  }

  // ── Signal 11: Security header/CORS findings ──
  if (finding.type === "security-header" || finding.type === "cors" || finding.type === "cookie") {
    score = 70; // These are always confirmed misconfigurations, not secrets
    reasoning.length = 0;
    reasoning.push("Security configuration finding — confirmed misconfiguration");
  }

  // ── Signal 12: Network interception source ──
  if (srcLower.includes("[request-body]")) {
    score += 10;
    reasoning.push("Found in outgoing request body — active secret transmission");
  }
  if (srcLower.includes("[header:authorization]")) {
    score += 15;
    reasoning.push("Found in Authorization header — live credential");
  }

  // Clamp
  score = Math.max(0, Math.min(100, score));

  // Verdict
  let verdict;
  if (score >= 80) verdict = "true_positive";
  else if (score >= 60) verdict = "likely_tp";
  else if (score >= 40) verdict = "needs_review";
  else if (score >= 20) verdict = "likely_fp";
  else verdict = "false_positive";

  // CVSS-style impact rating
  const cvss = computeCVSS(finding, score);

  return { confidence: score, verdict, reasoning, cvss };
}

/**
 * CVSS-style risk scoring
 */
function computeCVSS(finding, confidence) {
  let impact = 0;
  const sev = finding.severity || "info";
  const type = finding.type || "regex";

  // Base impact from severity
  const sevScores = { critical: 9.0, high: 7.0, medium: 5.0, low: 3.0, info: 1.0 };
  impact = sevScores[sev] || 1.0;

  // Adjust for exploitability
  if (type === "pii" && finding.piiType === "credit_card") impact = Math.min(10, impact + 1.5);
  if (type === "jwt") impact = Math.min(10, impact + 0.5);
  if (finding.encoded) impact = Math.min(10, impact + 0.3);

  // Adjust for confidence
  const adjustedScore = impact * (confidence / 100);

  let rating;
  if (adjustedScore >= 7.0) rating = "Critical";
  else if (adjustedScore >= 5.0) rating = "High";
  else if (adjustedScore >= 3.0) rating = "Medium";
  else if (adjustedScore >= 1.0) rating = "Low";
  else rating = "Info";

  return { score: adjustedScore.toFixed(1), rating };
}


// ─── CLAUDE API DEEP ANALYSIS ─────────────────────────────────────

export async function analyzeWithClaude(finding, apiKey) {
  if (!apiKey) return { error: "No API key configured" };

  const redactedMatch = finding.match
    ? finding.match.substring(0, 8) + "..." + finding.match.substring(finding.match.length - 4)
    : "N/A";

  const prompt = `You are a senior security analyst performing secret detection triage. Analyze this finding:

- Pattern: ${finding.key}
- Source: ${finding.src}
- Redacted match: ${redactedMatch}
- Length: ${(finding.fullMatch || finding.match || "").length} chars
- Severity: ${finding.severity}
- Type: ${finding.type}
- Encoded: ${!!finding.encoded}
${finding.type === "jwt" ? `- JWT alg: ${finding.decoded?.header?.alg || "unknown"}` : ""}
${finding.type === "jwt" ? `- JWT has exp: ${!!finding.decoded?.payload?.exp}` : ""}
${finding.type === "entropy" ? `- Entropy: ${finding.entropy} bits/char` : ""}

Respond ONLY in JSON:
{"confidence":<0-100>,"is_real_secret":<bool>,"impact":"<impact>","remediation":["<step1>","<step2>"],"explanation":"<why>"}`;

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 500, messages: [{ role: "user", content: prompt }] }),
    });
    if (!response.ok) { const err = await response.text(); return { error: `API error: ${response.status}` }; }
    const data = await response.json();
    const text = data.content?.[0]?.text || "";
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) return { aiAnalysis: JSON.parse(jsonMatch[0]) };
    return { aiAnalysis: { explanation: text } };
  } catch (err) {
    return { error: `Claude API call failed: ${err.message}` };
  }
}

export async function batchAnalyzeWithClaude(findings, apiKey, maxConcurrent = 2) {
  const results = [];
  for (let i = 0; i < findings.length; i += maxConcurrent) {
    const batch = findings.slice(i, i + maxConcurrent);
    const batchResults = await Promise.all(batch.map(f => analyzeWithClaude(f, apiKey)));
    results.push(...batchResults);
    if (i + maxConcurrent < findings.length) await new Promise(r => setTimeout(r, 1000));
  }
  return results;
}
