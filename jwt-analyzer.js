// jwt-analyzer.js — JWT decode, analysis, weakness detection, JWE detection
// Enhanced for Trufflehog on Steroids²

function b64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  try { return atob(str); }
  catch { return null; }
}

export function decodeJWT(token) {
  const parts = token.split('.');
  if (parts.length < 2 || parts.length > 3) return null;

  try {
    const headerRaw = b64UrlDecode(parts[0]);
    const payloadRaw = b64UrlDecode(parts[1]);
    if (!headerRaw || !payloadRaw) return null;

    const header = JSON.parse(headerRaw);
    let payload;
    try { payload = JSON.parse(payloadRaw); }
    catch { payload = { _raw: payloadRaw }; }

    // Detect if this is actually a JWE (5 parts)
    const isJWE = parts.length === 5 || (header.enc && header.alg);

    return {
      header, payload, signature: parts[2] || null,
      hasSignature: parts.length === 3 && (parts[2] || "").length > 0,
      raw: token, isJWE,
    };
  } catch { return null; }
}

export function analyzeJWT(decoded) {
  if (!decoded) return [];
  const warnings = [];
  const { header, payload, hasSignature, isJWE } = decoded;

  // 1. Algorithm checks
  const alg = (header.alg || "").toLowerCase();
  if (alg === "none") {
    warnings.push({ issue: "Algorithm set to 'none' — unsigned token!", severity: "critical",
      remediation: "Reject tokens with alg:none. Enforce algorithm validation server-side." });
  } else if (alg.startsWith("hs")) {
    warnings.push({
      issue: `HMAC algorithm (${header.alg}) — symmetric key, crackable with hashcat -m 16500`,
      severity: "high",
      remediation: "Consider migrating to asymmetric algorithms (RS256, ES256). If using HMAC, ensure key is ≥256 bits.",
    });
  } else if (alg.startsWith("rs") || alg.startsWith("ps")) {
    warnings.push({ issue: `Uses RSA algorithm (${header.alg})`, severity: "info" });
  } else if (alg.startsWith("es")) {
    warnings.push({ issue: `Uses ECDSA algorithm (${header.alg})`, severity: "info" });
  }

  // 2. Algorithm confusion attack surface
  if (header.jwk) {
    warnings.push({
      issue: "Token embeds a JWK in header — algorithm confusion attack vector",
      severity: "critical",
      remediation: "Never trust embedded JWKs. Validate against a server-side JWKS.",
    });
  }
  if (header.jku) {
    warnings.push({
      issue: `Token references external JWKS URL: ${header.jku}`,
      severity: "high",
      remediation: "Whitelist allowed JWKS URLs server-side. Verify the jku domain.",
    });
  }
  if (header.x5u) {
    warnings.push({
      issue: `Token references external x509 URL: ${header.x5u}`,
      severity: "high",
      remediation: "Whitelist allowed certificate URLs.",
    });
  }

  // 3. No signature
  if (!hasSignature && !isJWE) {
    warnings.push({ issue: "Token has no signature segment", severity: "critical" });
  }

  // 4. Expiry checks
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp) {
    if (payload.exp < now) {
      const expDate = new Date(payload.exp * 1000).toISOString();
      warnings.push({ issue: `Token expired at ${expDate}`, severity: "info" });
    } else {
      const remainingSec = payload.exp - now;
      const remainingDays = Math.floor(remainingSec / 86400);
      if (remainingDays > 365) {
        warnings.push({ issue: `Token valid for ${remainingDays} days — excessively long-lived`, severity: "high",
          remediation: "Reduce token lifetime. Use refresh tokens for long sessions." });
      } else if (remainingDays > 30) {
        warnings.push({ issue: `Token expires in ${remainingDays} days`, severity: "medium" });
      } else {
        warnings.push({ issue: `Token expires in ${remainingDays}d ${Math.floor((remainingSec % 86400) / 3600)}h`, severity: "info" });
      }
    }
  } else {
    warnings.push({ issue: "No expiration claim (exp) — token never expires", severity: "high",
      remediation: "Always set exp claim. Use short-lived tokens with refresh mechanism." });
  }

  // 5. No not-before or issued-at
  if (!payload.nbf && !payload.iat) {
    warnings.push({ issue: "No nbf/iat claims — cannot detect replay attacks", severity: "medium" });
  }

  // 6. Sensitive claims
  const sensitiveClaims = ["email", "phone", "phone_number", "address", "ssn", "credit_card", "password", "secret", "dob", "date_of_birth"];
  for (const claim of sensitiveClaims) {
    if (payload[claim]) {
      warnings.push({ issue: `Contains sensitive PII claim: ${claim}`, severity: "medium",
        remediation: `Remove '${claim}' from JWT payload. Fetch PII from API using the sub claim.` });
    }
  }

  // 7. Admin/privilege claims
  const privClaims = ["admin", "role", "roles", "scope", "scopes", "permissions", "is_admin", "is_superuser", "groups", "group", "authorities"];
  for (const claim of privClaims) {
    if (payload[claim]) {
      const val = typeof payload[claim] === "object" ? JSON.stringify(payload[claim]) : payload[claim];
      const valStr = String(val);
      const isElevated = /admin|superuser|root|owner|god|full[_-]?access/i.test(valStr);
      warnings.push({
        issue: `Privilege claim: ${claim} = ${valStr.substring(0, 80)}${valStr.length > 80 ? '...' : ''}`,
        severity: isElevated ? "high" : "medium",
      });
    }
  }

  // 8. Issuer / Audience / Subject info
  if (payload.iss) warnings.push({ issue: `Issuer: ${payload.iss}`, severity: "info" });
  if (payload.aud) {
    const aud = Array.isArray(payload.aud) ? payload.aud.join(", ") : payload.aud;
    warnings.push({ issue: `Audience: ${aud}`, severity: "info" });
  }
  if (payload.sub) warnings.push({ issue: `Subject: ${payload.sub}`, severity: "info" });

  // 9. JWE-specific checks
  if (isJWE) {
    warnings.push({ issue: "This is a JWE (encrypted token) — payload may contain additional secrets", severity: "medium" });
    if (header.enc) warnings.push({ issue: `Encryption algorithm: ${header.enc}`, severity: "info" });
  }

  // 10. Key ID — useful for JWKS correlation
  if (header.kid) {
    warnings.push({ issue: `Key ID (kid): ${header.kid}`, severity: "info" });
  }

  return warnings;
}

export function scanJWTs(text, src) {
  const jwtRegex = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
  const findings = [];
  let match;

  while ((match = jwtRegex.exec(text)) !== null) {
    const token = match[0];
    const decoded = decodeJWT(token);
    if (!decoded) continue;

    const analysis = analyzeJWT(decoded);
    const maxSeverity = analysis.reduce((max, w) => {
      const order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (order[w.severity] || 0) > (order[max] || 0) ? w.severity : max;
    }, "info");

    findings.push({
      key: decoded.isJWE ? "JSON Web Encryption Token" : "JSON Web Token",
      match: token.substring(0, 40) + "...",
      fullMatch: token, src, severity: maxSeverity,
      type: "jwt", decoded: {
        header: decoded.header, payload: decoded.payload,
        hasSignature: decoded.hasSignature, isJWE: decoded.isJWE,
      },
      analysis,
    });
  }
  return findings;
}
