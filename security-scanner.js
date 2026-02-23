// security-scanner.js — Security header, CORS, CSP, cookie analysis engine
// Enterprise module for Trufflehog on Steroids²

/**
 * Analyze security headers from a response
 * @param {Object} headers - Response headers object { name: value }
 * @param {string} url - The URL these headers came from
 * @returns {Array} Array of security findings
 */
export function analyzeSecurityHeaders(headers, url) {
  if (!headers || typeof headers !== "object") return [];
  const findings = [];
  const h = normalizeHeaders(headers);

  // ── Content-Security-Policy ──
  if (!h["content-security-policy"]) {
    findings.push({
      key: "Missing Content-Security-Policy Header",
      match: `No CSP header on ${truncUrl(url)}`,
      src: url, severity: "medium", type: "security-header",
      category: "headers", remediation: "Add a Content-Security-Policy header to prevent XSS and injection attacks.",
    });
  } else {
    const csp = h["content-security-policy"];
    if (csp.includes("'unsafe-inline'")) {
      findings.push({
        key: "CSP allows unsafe-inline",
        match: `CSP includes 'unsafe-inline' — XSS risk`, src: url,
        severity: "high", type: "security-header", category: "headers",
        remediation: "Remove 'unsafe-inline' and use nonces or hashes instead.",
      });
    }
    if (csp.includes("'unsafe-eval'")) {
      findings.push({
        key: "CSP allows unsafe-eval",
        match: `CSP includes 'unsafe-eval' — code injection risk`, src: url,
        severity: "high", type: "security-header", category: "headers",
      });
    }
    if (csp.includes("*") && !csp.includes("*.")) {
      findings.push({
        key: "CSP has wildcard source",
        match: `CSP includes wildcard (*) — overly permissive`, src: url,
        severity: "medium", type: "security-header", category: "headers",
      });
    }
    if (csp.includes("data:")) {
      findings.push({
        key: "CSP allows data: URIs",
        match: `CSP includes 'data:' source — potential XSS vector`, src: url,
        severity: "medium", type: "security-header", category: "headers",
      });
    }
  }

  // ── Strict-Transport-Security ──
  if (!h["strict-transport-security"]) {
    findings.push({
      key: "Missing HSTS Header",
      match: `No Strict-Transport-Security on ${truncUrl(url)}`,
      src: url, severity: "medium", type: "security-header", category: "headers",
      remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    });
  } else {
    const hsts = h["strict-transport-security"];
    const maxAge = parseInt((hsts.match(/max-age=(\d+)/) || [])[1] || "0");
    if (maxAge < 31536000) {
      findings.push({
        key: "HSTS max-age too short",
        match: `HSTS max-age=${maxAge} (< 1 year)`, src: url,
        severity: "low", type: "security-header", category: "headers",
      });
    }
  }

  // ── X-Frame-Options ──
  if (!h["x-frame-options"] && !(h["content-security-policy"] || "").includes("frame-ancestors")) {
    findings.push({
      key: "Missing Clickjacking Protection",
      match: `No X-Frame-Options or frame-ancestors CSP`, src: url,
      severity: "medium", type: "security-header", category: "headers",
    });
  }

  // ── X-Content-Type-Options ──
  if (!h["x-content-type-options"]) {
    findings.push({
      key: "Missing X-Content-Type-Options",
      match: `No nosniff header — MIME sniffing risk`, src: url,
      severity: "low", type: "security-header", category: "headers",
    });
  }

  // ── Referrer-Policy ──
  if (!h["referrer-policy"]) {
    findings.push({
      key: "Missing Referrer-Policy",
      match: `No Referrer-Policy — may leak sensitive URL paths`, src: url,
      severity: "low", type: "security-header", category: "headers",
    });
  }

  // ── Permissions-Policy ──
  if (!h["permissions-policy"] && !h["feature-policy"]) {
    findings.push({
      key: "Missing Permissions-Policy",
      match: `No Permissions-Policy — browser features unrestricted`, src: url,
      severity: "low", type: "security-header", category: "headers",
    });
  }

  // ── Server header leak ──
  if (h["server"]) {
    findings.push({
      key: "Server Header Information Disclosure",
      match: `Server: ${h["server"]}`, src: url,
      severity: "low", type: "security-header", category: "headers",
      remediation: "Remove or obfuscate the Server header to reduce fingerprinting.",
    });
  }

  // ── X-Powered-By leak ──
  if (h["x-powered-by"]) {
    findings.push({
      key: "X-Powered-By Information Disclosure",
      match: `X-Powered-By: ${h["x-powered-by"]}`, src: url,
      severity: "low", type: "security-header", category: "headers",
    });
  }

  return findings;
}

/**
 * Analyze CORS configuration
 * @param {Object} headers - Response headers
 * @param {string} url - Request URL
 * @param {string} requestOrigin - The origin that made the request
 * @returns {Array} Array of CORS findings
 */
export function analyzeCORS(headers, url, requestOrigin) {
  const findings = [];
  const h = normalizeHeaders(headers);
  const acao = h["access-control-allow-origin"];

  if (!acao) return findings;

  if (acao === "*") {
    const acac = h["access-control-allow-credentials"];
    if (acac === "true") {
      findings.push({
        key: "CORS: Wildcard Origin with Credentials",
        match: `ACAO: * with ACAC: true — credential theft risk`, src: url,
        severity: "critical", type: "cors", category: "cors",
        remediation: "Never combine Access-Control-Allow-Origin: * with credentials. Use specific origins.",
      });
    } else {
      findings.push({
        key: "CORS: Wildcard Origin",
        match: `Access-Control-Allow-Origin: * — open to all origins`, src: url,
        severity: "medium", type: "cors", category: "cors",
      });
    }
  }

  // Check if origin is reflected (potential misconfiguration)
  if (acao === requestOrigin && h["access-control-allow-credentials"] === "true") {
    findings.push({
      key: "CORS: Origin Reflection with Credentials",
      match: `Reflects ${requestOrigin} with credentials — verify this is intentional`, src: url,
      severity: "high", type: "cors", category: "cors",
      remediation: "Verify the origin whitelist. Do not blindly reflect the Origin header.",
    });
  }

  // Check exposed headers
  const exposedHeaders = h["access-control-expose-headers"];
  if (exposedHeaders) {
    const sensitive = ["authorization", "set-cookie", "x-api-key"];
    for (const sh of sensitive) {
      if (exposedHeaders.toLowerCase().includes(sh)) {
        findings.push({
          key: "CORS: Sensitive Header Exposed",
          match: `Exposes '${sh}' via Access-Control-Expose-Headers`, src: url,
          severity: "medium", type: "cors", category: "cors",
        });
      }
    }
  }

  return findings;
}

/**
 * Analyze Set-Cookie headers for security issues
 * @param {string|Array} setCookieHeaders - Set-Cookie header value(s)
 * @param {string} url - The URL the cookies came from
 * @returns {Array} Array of cookie security findings
 */
export function analyzeCookies(setCookieHeaders, url) {
  const findings = [];
  if (!setCookieHeaders) return findings;

  const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  const isHTTPS = url.startsWith("https://");

  for (const cookie of cookies) {
    if (!cookie) continue;
    const cookieName = (cookie.split("=")[0] || "").trim();
    const lower = cookie.toLowerCase();

    // Sensitive cookie names that MUST have security flags
    const isSensitive = /(?:session|token|auth|jwt|sid|csrf|xsrf)/i.test(cookieName);

    if (!lower.includes("httponly") && isSensitive) {
      findings.push({
        key: "Cookie Missing HttpOnly Flag",
        match: `'${cookieName}' — accessible to JavaScript (XSS risk)`, src: url,
        severity: "high", type: "cookie", category: "cookies",
        remediation: "Add HttpOnly flag to prevent JavaScript access.",
      });
    }

    if (isHTTPS && !lower.includes("secure") && isSensitive) {
      findings.push({
        key: "Cookie Missing Secure Flag",
        match: `'${cookieName}' — may be sent over HTTP`, src: url,
        severity: "medium", type: "cookie", category: "cookies",
      });
    }

    if (!lower.includes("samesite") && isSensitive) {
      findings.push({
        key: "Cookie Missing SameSite Attribute",
        match: `'${cookieName}' — CSRF risk without SameSite`, src: url,
        severity: "medium", type: "cookie", category: "cookies",
      });
    }

    if (lower.includes("samesite=none") && !lower.includes("secure")) {
      findings.push({
        key: "Cookie SameSite=None without Secure",
        match: `'${cookieName}' — SameSite=None requires Secure flag`, src: url,
        severity: "medium", type: "cookie", category: "cookies",
      });
    }
  }
  return findings;
}

// ── Helpers ──────────────────────────────────────────────────────

function normalizeHeaders(headers) {
  const normalized = {};
  if (Array.isArray(headers)) {
    for (const h of headers) {
      normalized[h.name.toLowerCase()] = h.value;
    }
  } else {
    for (const [k, v] of Object.entries(headers)) {
      normalized[k.toLowerCase()] = v;
    }
  }
  return normalized;
}

function truncUrl(url) {
  if (!url) return "";
  return url.length > 60 ? url.substring(0, 30) + "..." + url.substring(url.length - 25) : url;
}
