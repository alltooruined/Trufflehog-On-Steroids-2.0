// pii-detector.js — PII detection engine for Trufflehog on Steroids²
// Detects: Credit cards (with Luhn), SSNs, emails, phone numbers, IBANs

/**
 * Scan text for PII
 * @param {string} text - Text to scan
 * @param {string} src - Source identifier
 * @returns {Array} Array of PII findings
 */
export function scanPII(text, src) {
  if (!text || text.length < 10) return [];
  const findings = [];
  const seen = new Set();

  // ── Credit Card Numbers (with Luhn validation) ──
  // Match 13-19 digit sequences that could be card numbers
  const ccRegex = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g;
  let match;
  while ((match = ccRegex.exec(text)) !== null) {
    const num = match[0].replace(/[\s-]/g, "");
    if (seen.has(num)) continue;
    if (luhnCheck(num)) {
      seen.add(num);
      const brand = getCardBrand(num);
      findings.push({
        key: `Credit Card Number (${brand})`,
        match: maskCard(num),
        fullMatch: num,
        src, severity: "critical", type: "pii", category: "pii",
        piiType: "credit_card",
        remediation: "Remove or tokenize credit card numbers. Ensure PCI DSS compliance.",
      });
    }
  }

  // Also check for spaced/dashed formats: 4111 1111 1111 1111 or 4111-1111-1111-1111
  const ccSpacedRegex = /\b(4[0-9]{3}[\s-][0-9]{4}[\s-][0-9]{4}[\s-][0-9]{4}|5[1-5][0-9]{2}[\s-][0-9]{4}[\s-][0-9]{4}[\s-][0-9]{4}|3[47][0-9]{2}[\s-][0-9]{6}[\s-][0-9]{5})\b/g;
  while ((match = ccSpacedRegex.exec(text)) !== null) {
    const num = match[0].replace(/[\s-]/g, "");
    if (seen.has(num)) continue;
    if (luhnCheck(num)) {
      seen.add(num);
      const brand = getCardBrand(num);
      findings.push({
        key: `Credit Card Number (${brand})`,
        match: maskCard(num),
        fullMatch: num,
        src, severity: "critical", type: "pii", category: "pii",
        piiType: "credit_card",
      });
    }
  }

  // ── Social Security Numbers (US) ──
  const ssnRegex = /\b(?!000|666|9\d{2})([0-8]\d{2})-(?!00)(\d{2})-(?!0000)(\d{4})\b/g;
  while ((match = ssnRegex.exec(text)) !== null) {
    const ssn = match[0];
    if (seen.has(ssn)) continue;
    // Context check — only flag if near PII keywords
    const contextStart = Math.max(0, match.index - 60);
    const context = text.substring(contextStart, match.index + ssn.length + 30).toLowerCase();
    if (/(?:ssn|social|security|tax|ein|itin|tin)/.test(context)) {
      seen.add(ssn);
      findings.push({
        key: "US Social Security Number",
        match: `***-**-${ssn.slice(-4)}`,
        fullMatch: ssn,
        src, severity: "critical", type: "pii", category: "pii",
        piiType: "ssn",
        remediation: "Remove SSN immediately. Report potential PII exposure per data protection policies.",
      });
    }
  }

  // ── Email Addresses (only flag in suspicious contexts) ──
  const emailRegex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
  let emailCount = 0;
  while ((match = emailRegex.exec(text)) !== null && emailCount < 5) {
    const email = match[0];
    if (seen.has(email)) continue;
    // Only flag emails that appear in response bodies/data, not in standard HTML
    const contextStart = Math.max(0, match.index - 80);
    const context = text.substring(contextStart, match.index).toLowerCase();
    if (/(?:email|mail|user|account|customer|contact|recipient|address)/.test(context)) {
      seen.add(email);
      emailCount++;
      findings.push({
        key: "Email Address (PII)",
        match: maskEmail(email),
        fullMatch: email,
        src, severity: "low", type: "pii", category: "pii",
        piiType: "email",
      });
    }
  }

  // ── Phone Numbers ──
  // International format
  const phoneRegex = /\b\+?1?[\s.-]?\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}\b/g;
  let phoneCount = 0;
  while ((match = phoneRegex.exec(text)) !== null && phoneCount < 5) {
    const phone = match[0];
    if (seen.has(phone)) continue;
    const contextStart = Math.max(0, match.index - 60);
    const context = text.substring(contextStart, match.index).toLowerCase();
    if (/(?:phone|tel|mobile|cell|fax|call|sms|whatsapp|contact)/.test(context)) {
      seen.add(phone);
      phoneCount++;
      findings.push({
        key: "Phone Number (PII)",
        match: maskPhone(phone),
        fullMatch: phone,
        src, severity: "low", type: "pii", category: "pii",
        piiType: "phone",
      });
    }
  }

  // ── IBAN (International Bank Account Number) ──
  const ibanRegex = /\b[A-Z]{2}[0-9]{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}\b/g;
  while ((match = ibanRegex.exec(text)) !== null) {
    const iban = match[0].replace(/\s/g, "");
    if (seen.has(iban)) continue;
    if (iban.length >= 15 && iban.length <= 34) {
      seen.add(iban);
      findings.push({
        key: "IBAN (Bank Account)",
        match: iban.substring(0, 4) + "..." + iban.slice(-4),
        fullMatch: iban,
        src, severity: "high", type: "pii", category: "pii",
        piiType: "iban",
      });
    }
  }

  return findings;
}

// ── Luhn algorithm for credit card validation ──
function luhnCheck(numStr) {
  const digits = numStr.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function getCardBrand(num) {
  if (/^4/.test(num)) return "Visa";
  if (/^5[1-5]/.test(num)) return "Mastercard";
  if (/^3[47]/.test(num)) return "Amex";
  if (/^6(?:011|5)/.test(num)) return "Discover";
  if (/^3(?:0[0-5]|[68])/.test(num)) return "Diners";
  if (/^(?:2131|1800|35)/.test(num)) return "JCB";
  return "Unknown";
}

function maskCard(num) {
  return num.slice(0, 6) + "******" + num.slice(-4);
}

function maskEmail(email) {
  const [user, domain] = email.split("@");
  return user[0] + "***@" + domain;
}

function maskPhone(phone) {
  const digits = phone.replace(/\D/g, "");
  return "***-***-" + digits.slice(-4);
}
