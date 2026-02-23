# 🐽 Trufflehog on Steroids² — Enterprise Edition

> The enterprise-grade secret scanner Chrome extension. 160+ detection patterns, AI-powered triage, PII detection, security header analysis, CVSS scoring, and SARIF export.

## What's New (God Edition)

| Feature | Standard Trufflehog | Steroids² |
|---------|------|-----------------|
| **Regex Patterns** | ~10 | **160+** with MITRE ATT&CK mapping & remediation |
| **Entropy Analysis** | ❌ | **Rewritten** - n-gram analysis, aggressive FP suppression |
| **PII Detection** | ❌ | ✅ Credit cards (Luhn), SSNs, IBANs, emails, phones |
| **Security Headers** | ❌ | ✅ CSP, HSTS, X-Frame-Options, CORS, cookie analysis |
| **CORS Misconfiguration** | ❌ | ✅ Wildcard + credentials, origin reflection |
| **Cookie Security** | ❌ | ✅ Missing HttpOnly, Secure, SameSite flags |
| **localStorage Scanning** | ❌ | ✅ Scans localStorage & sessionStorage |
| **Hydration Data Scanning** | ❌ | ✅ __NEXT_DATA__, __NUXT__, __INITIAL_STATE__ |
| **DOM Mutation Observer** | ❌ | ✅ Catches dynamically injected secrets |
| **JWT Analysis** | ❌ | **Enhanced** — JWE detection, algorithm confusion, JWKS |
| **AI Scoring** | ❌ | **12 signals** with CVSS-style risk rating |
| **SARIF Export** | ❌ | ✅ GitHub Advanced Security compatible |
| **Pattern Categories** | ❌ | ✅ 17 categories (cloud, payment, auth, AI, etc.) |
| **MITRE ATT&CK** | ❌ | ✅ Technique IDs on critical patterns |
| **Remediation Guidance** | ❌ | ✅ Per-finding remediation steps |
| **CVSS Risk Score** | ❌ | ✅ Confidence-weighted risk scoring |

### Entropy False Positive Fix (v3.0 Highlight)

The #1 complaint from v2.0 was entropy false positives. v3.0 completely rewrites the entropy engine:

- **Raised thresholds**: hex 3.0→4.0, base64 4.2→4.7
- **Lowered base context score**: 0.6→0.3 (require evidence, not assume)
- **N-gram analysis**: Detects English text patterns and rejects them
- **Character distribution check**: Rejects strings with non-uniform distributions
- **Dictionary word detection**: Filters strings containing common words
- **Comprehensive blocklist**: 100+ prefixes for JS/CSS/HTML identifiers
- **Structural analysis**: Detects camelCase, snake_case, CSS values, HTML attributes
- **Safe source skipping**: Skips CDN libraries, polyfills, analytics entirely
- **Function call context**: Ignores strings inside .getElementById(), etc.

## Architecture

```
manifest.json              MV3 manifest
├── background.js          Service worker, orchestrates all engines
├── inject.js              Content script, page scanning, DOM observer, storage scan
├── interceptor.js         Page-level XHR/fetch/WS/SSE interception
├── patterns.js            160+ regex patterns with categories & MITRE mapping
├── entropy.js             Rewritten entropy scanner with aggressive FP filtering
├── jwt-analyzer.js        JWT/JWE decode, algorithm confusion, JWKS detection
├── pii-detector.js        NEW: Credit cards (Luhn), SSNs, emails, phones, IBANs
├── security-scanner.js    NEW: CSP, CORS, HSTS, cookies, security headers
├── ai-checker.js          12-signal heuristic AI with CVSS scoring
├── db.js                  IndexedDB storage with SARIF export
├── popup.html/css/js      Enterprise security dashboard
└── icons                  Extension icons
```

## Detection Engines

### 1. Pattern Matching (160+ Signatures)
17 categories: Cloud (AWS/GCP/Azure/DO), Git platforms, CI/CD, Messaging, Payments, Auth & Identity, Email, Observability, Database, AI/ML, Infrastructure, SaaS, Social, Registry, Secrets Management, Crypto Material, Generic.

Each pattern includes severity, category, MITRE ATT&CK technique ID, and remediation guidance.

### 2. Entropy Analysis (Rewritten)
Shannon entropy with n-gram analysis, character distribution scoring, and context-aware thresholds. Comprehensive false positive filtering eliminates CSS values, JS identifiers, HTML attributes, common library code, and dictionary words.

### 3. PII Detection
- **Credit Cards**: Visa, Mastercard, Amex, Discover, JCB validated with Luhn algorithm
- **SSNs**: US Social Security Numbers with context validation
- **IBANs**: International Bank Account Numbers
- **Emails**: Context-aware (only flags emails in data/API contexts, not HTML)
- **Phone Numbers**: International formats with context validation

### 4. Security Header Analysis
- **CSP**: Checks for unsafe-inline, unsafe-eval, wildcards, data: URIs
- **HSTS**: Validates max-age duration
- **Clickjacking**: X-Frame-Options and frame-ancestors
- **CORS**: Wildcard origins, credential reflection, sensitive header exposure
- **Cookies**: HttpOnly, Secure, SameSite flag validation
- **Info Disclosure**: Server, X-Powered-By header leaks

### 5. Network Interception
Hooks `fetch()`, `XMLHttpRequest`, `WebSocket`, `EventSource`. Captures full response headers for security analysis. Scans both response bodies and request bodies.

### 6. Source Map Scanning
Discovers `.js.map` files via sourceMappingURL comments, response headers, and URL patterns. Parses source maps and scans each original source file.

### 7. Storage & Hydration Scanning
- Scans `localStorage` and `sessionStorage` for leaked secrets
- Scans framework hydration data: `__NEXT_DATA__`, `__NUXT__`, `__INITIAL_STATE__`, `__APP_STATE__`, `__PRELOADED_STATE__`
- DOM Mutation Observer catches dynamically injected secrets

### 8. JWT Analysis
Detects JWTs and JWEs. Analyzes:
- `alg: none`, HMAC (crackable), embedded JWKs (algorithm confusion)
- Missing/excessive expiration, missing nbf/iat
- Sensitive PII claims, privilege escalation claims
- External JWKS URL references (jku, x5u)

### 9. AI Triage

**Local Heuristics (12 signals):**
1. Pattern specificity scoring
2. Entropy analysis
3. Source context (critical/risky/safe)
4. Strong vs medium context keywords
5. Test/placeholder detection
6. Match length analysis
7. Base64 encoding detection
8. JWT issue severity
9. Detection type weighting
10. PII type validation
11. Security misconfiguration detection
12. Network source analysis

Produces: confidence (0-100), verdict (true_positive → false_positive), CVSS-style risk score.

**Claude API (optional):** Sends redacted metadata for deep analysis with impact assessment and remediation.

## Export Formats

- **JSON**: Full metadata including AI analysis, JWT data, CVSS scores
- **CSV**: Flat format for spreadsheet analysis
- **SARIF**: GitHub Advanced Security / CI/CD pipeline compatible

## Install

1. Clone or download this repository
2. Open `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked" and select the extension directory
5. Click the Trufflehog icon to open the dashboard

## Security Notes

- Runs entirely locally, no data leaves your browser (unless Claude API is enabled)
- Claude API sends only redacted metadata, never raw secrets
- Network interception is passive reads only, never modifies
- `.env` and `.git` probing is off by default (active scanning)
- PII findings are masked in the UI (card numbers, SSNs, emails)

## Credits

Based on the original [Trufflehog Chrome Extension](https://github.com/trufflesecurity/Trufflehog-Chrome-Extension) by Truffle Security.
