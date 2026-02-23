// entropy.js — Shannon entropy analysis for secret detection
// REWRITTEN: Aggressive false-positive suppression for enterprise use

/**
 * Calculate Shannon entropy of a string
 * @param {string} str - Input string
 * @returns {number} Entropy in bits per character
 */
export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ── Character sets ──────────────────────────────────────────────
const HEX_CHARS = "0123456789abcdefABCDEF";
const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// ── RAISED thresholds — the #1 fix for false positives ──────────
// Previous values were too low (hex: 3.0, base64: 4.2)
// Secrets typically have entropy > 4.5 for hex, > 4.8 for base64
const THRESHOLDS = {
  hex:       4.0,   // was 3.0 — raised significantly
  base64:    4.7,   // was 4.2 — raised
  base64url: 4.7,   // was 4.2 — raised
};

// Minimum length to even consider — raised from 16 to 20
const MIN_SECRET_LENGTH = 20;

// Maximum length — very long strings are usually not secrets
const MAX_SECRET_LENGTH = 500;

// ── COMPREHENSIVE false positive dictionary ─────────────────────
// This is the enterprise-grade blocklist
const FP_EXACT_PREFIXES = [
  // JavaScript / TypeScript keywords and common patterns
  "function", "return", "undefined", "null", "true", "false", "object", "string",
  "number", "boolean", "symbol", "typeof", "instanceof", "prototype", "constructor",
  "arguments", "default", "export", "import", "require", "module",
  "console", "window", "document", "navigator", "location",
  "Promise", "async", "await", "class", "extends", "super", "static",
  "const", "let", "var", "this", "new", "delete", "void",
  "throw", "catch", "finally", "switch", "case", "break", "continue",
  "debugger", "eval", "with", "yield", "enum", "implements", "interface",
  "package", "private", "protected", "public",
  // CSS property names and values
  "background", "transparent", "important", "inherit", "none", "initial",
  "relative", "absolute", "fixed", "sticky", "inline", "block", "flex",
  "grid", "table", "hidden", "visible", "overflow", "scroll", "auto",
  "border", "margin", "padding", "font", "color", "display", "position",
  "transform", "transition", "animation", "opacity", "zIndex", "cursor",
  "pointer", "normal", "bold", "italic", "center", "left", "right",
  "nowrap", "wrap", "stretch", "baseline", "space", "between", "around",
  "linear", "ease", "cubic", "bezier", "translate", "rotate", "scale",
  "webkit", "moz", "ms",
  // HTML tags / attributes
  "button", "input", "select", "option", "textarea", "label",
  "header", "footer", "section", "article", "aside", "main",
  "div", "span", "img", "src", "href", "alt", "title", "class",
  "style", "width", "height", "type", "value", "name", "id",
  "placeholder", "disabled", "readonly", "checked", "selected",
  // Common library / framework identifiers
  "react", "angular", "vue", "svelte", "jquery", "lodash",
  "bootstrap", "tailwind", "material", "antd", "chakra",
  "webpack", "babel", "rollup", "vite", "parcel", "esbuild",
  "express", "fastify", "koa", "hapi", "nest", "next", "nuxt", "gatsby",
  "node_modules", "package", "component", "container", "wrapper",
  "Provider", "Consumer", "Context", "Reducer", "Dispatch",
  "useState", "useEffect", "useRef", "useMemo", "useCallback",
  "createElement", "createContext", "createRef", "forwardRef",
  "Fragment", "Suspense", "ErrorBoundary", "StrictMode",
  // Data URIs / MIME types / encoding patterns
  "data:image", "data:text", "data:application",
  "text/html", "text/css", "text/javascript", "text/plain",
  "application/json", "application/xml", "application/octet",
  "image/png", "image/jpeg", "image/gif", "image/svg",
  "charset", "utf", "ascii", "unicode",
  // Common hashing / crypto function outputs (not secrets themselves)
  "sha256", "sha384", "sha512", "md5", "hmac",
  // Base64 of common mime types / empty content
  "AAAA", // very common in base64 encoded content
  // Source map references
  "sourceMappingURL", "sourceMap",
  // URL patterns
  "https", "http", "localhost", "googleapis", "cloudflare",
  "amazonaws", "azure", "microsoft", "google", "facebook",
  "twitter", "github", "gitlab", "bitbucket",
];

// Regex patterns for common false positive structures
const FP_REGEX_PATTERNS = [
  /^(.{1,4})\1{3,}$/,                     // Repeated short patterns (aaaa, abcabc)
  /^0{8,}$/,                               // All zeros
  /^f{8,}$/i,                              // All f's
  /^[0-9a-f]{2}([0-9a-f]{2})\1{4,}/i,     // Repeating hex pairs
  /^(?:0123456789|abcdefghij|ABCDEFGHIJ)/,  // Sequential chars
  /^[A-Z]{2,4}[a-z]+[A-Z][a-z]+/,          // camelCase identifiers (e.g., getElementById)
  /^(?:get|set|has|is|on|do)[A-Z]/,         // Method name patterns
  /^(?:handle|render|create|update|delete|fetch|parse|format|validate|convert)[A-Z]/,
  /^[a-z]+(?:Handler|Listener|Callback|Factory|Builder|Manager|Service|Controller|Repository|Adapter|Helper|Util)/,
  /^(?:__)[a-zA-Z]/,                        // Dunder methods/properties
  /^(?:px|em|rem|vh|vw|%|pt|pc|cm|mm|in)$/,  // CSS units
  /^#[0-9a-fA-F]{3,8}$/,                    // Hex colors
  /^rgb[a]?\([^)]+\)$/,                      // RGB colors
  /^hsl[a]?\([^)]+\)$/,                      // HSL colors
  /^[0-9]+(?:\.[0-9]+)?(?:px|em|rem|%|vh|vw|pt|s|ms)$/,  // CSS numeric values
  /^data:[a-zA-Z]+\/[a-zA-Z0-9+.-]+/,       // Data URIs
  /^[a-z][a-zA-Z0-9]*\([^)]*\)$/,           // Function calls
  /^@(?:media|keyframes|import|charset|font-face|supports|layer)/,  // CSS at-rules
  /^(?:v[0-9]+\.|[0-9]+\.[0-9]+\.[0-9]+)/,  // Version strings
  /^[A-Z_]{2,}$/,                            // ALL_CAPS constant names
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)/,        // Date strings
  /^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/,
  /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i,  // UUIDs are not secrets
  /^(?:en|fr|de|es|it|pt|ja|ko|zh|ru|ar)[-_][A-Z]{2}$/,  // Locale strings
  /^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/,  // HTTP methods
  /^(?:Content-Type|Accept|Authorization|Cache-Control|User-Agent)/i,  // HTTP headers
  /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,  // Emails (handled by PII detector)
  /^(?:serif|sans-serif|monospace|cursive|fantasy|system-ui)/,  // Font families
  /^(?:none|auto|inherit|initial|unset|revert)$/,  // CSS global values
];

// Known safe long hex strings that appear frequently in web pages
const FP_KNOWN_HASHES = new Set([
  // Common integrity hashes, webpack chunk IDs, etc are often long hex strings
  // We don't store specific values — the regex patterns above catch the structures
]);

// Common words that appear in base64-encoded content that aren't secrets
const FP_DICTIONARY_WORDS = [
  "the", "and", "for", "are", "but", "not", "you", "all", "can", "her",
  "was", "one", "our", "out", "day", "had", "has", "his", "how", "its",
  "may", "new", "now", "old", "see", "way", "who", "boy", "did", "get",
  "let", "put", "say", "she", "too", "use",
  "that", "with", "have", "this", "will", "your", "from", "they", "been",
  "call", "come", "each", "find", "first", "give", "good", "help", "here",
  "just", "know", "like", "long", "look", "make", "many", "most", "much",
  "must", "name", "over", "only", "part", "than", "them", "then", "time",
  "very", "want", "well", "what", "when", "which", "work", "year",
  "about", "after", "could", "every", "great", "might", "never", "other",
  "right", "still", "their", "there", "these", "think", "those", "under",
  "where", "while", "world", "would", "should", "before", "between",
];

/**
 * Extract contiguous strings from a given character set
 */
function extractStringsOfCharset(text, charset, minLen = MIN_SECRET_LENGTH) {
  const results = [];
  let current = "";
  let startIdx = 0;
  for (let i = 0; i < text.length; i++) {
    if (charset.includes(text[i])) {
      if (current.length === 0) startIdx = i;
      current += text[i];
    } else {
      if (current.length >= minLen && current.length <= MAX_SECRET_LENGTH) {
        results.push({ value: current, start: startIdx, end: i });
      }
      current = "";
    }
  }
  if (current.length >= minLen && current.length <= MAX_SECRET_LENGTH) {
    results.push({ value: current, start: startIdx, end: text.length });
  }
  return results;
}

/**
 * AGGRESSIVE false positive filter — the core of the FP fix
 * Returns true if the string is almost certainly NOT a secret
 */
function isFalsePositive(str, text, startIdx) {
  const lower = str.toLowerCase();

  // 1. Check prefix blocklist
  for (const prefix of FP_EXACT_PREFIXES) {
    if (lower.startsWith(prefix.toLowerCase())) return true;
  }

  // 2. Check regex patterns
  for (const re of FP_REGEX_PATTERNS) {
    if (re.test(str)) return true;
  }

  // 3. Character distribution analysis — secrets should have UNIFORM distribution
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const uniqueChars = Object.keys(freq).length;
  const maxFreq = Math.max(...Object.values(freq));
  const avgFreq = str.length / uniqueChars;

  // If any single character appears way too often, likely not a secret
  if (maxFreq > str.length * 0.35) return true;
  // If too few unique characters for the length, likely not random
  if (uniqueChars < Math.min(str.length * 0.3, 10)) return true;

  // 4. Check for embedded dictionary words (2+ consecutive words = not a secret)
  let wordHits = 0;
  for (const word of FP_DICTIONARY_WORDS) {
    if (lower.includes(word)) wordHits++;
    if (wordHits >= 2) return true;
  }

  // 5. N-gram analysis — check for common English bigrams
  const commonBigrams = ["th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar", "st"];
  let bigramHits = 0;
  for (let i = 0; i < lower.length - 1; i++) {
    if (commonBigrams.includes(lower.substring(i, i + 2))) bigramHits++;
  }
  // If >30% of bigrams are common English, this is probably text, not a secret
  if (bigramHits / (lower.length - 1) > 0.30) return true;

  // 6. Check surrounding context for assignment patterns
  // If there's NO assignment context, penalize heavily
  const lookback = text.substring(Math.max(0, startIdx - 50), startIdx);
  const lookforward = text.substring(Math.min(text.length, startIdx + str.length), Math.min(text.length, startIdx + str.length + 20));

  // If the string is inside a function call like .getElementById("...") it's not a secret
  if (/\.\w+\(\s*["']?$/.test(lookback)) return true;
  // If it's a CSS property value
  if (/:\s*$/.test(lookback) && /[;}]/.test(lookforward)) {
    // Could be CSS OR could be "password: abc123" — check for secret keywords
    const lookbackLower = lookback.toLowerCase();
    const hasSecretKeyword = /(?:key|secret|token|password|passwd|pwd|auth|credential|api_key|apikey|access_key)/.test(lookbackLower);
    if (!hasSecretKeyword) return true;
  }
  // HTML attribute values
  if (/(?:class|id|style|data-(?!key|token|secret|api)|aria-|role|tabindex|href|src|alt|title|placeholder|name|for|action|method|type|rel|target)\s*=\s*["']?$/.test(lookback)) return true;

  // 7. Structured data patterns (JSON keys, XML tags, etc.)
  if (/^[a-zA-Z][a-zA-Z0-9]*$/.test(str) && str.length < 30) return true; // Single camelCase/PascalCase word
  if (/^[a-z]+(?:_[a-z]+){2,}$/.test(str)) return true; // snake_case identifiers

  return false;
}

/**
 * Context scoring — checks surrounding text for secret-like context
 * Returns a multiplier (0.0 to 1.5)
 * REVISED: More conservative, requires stronger signals
 */
function contextScore(text, startIdx) {
  const lookback = text.substring(Math.max(0, startIdx - 100), startIdx).toLowerCase();

  // High-confidence secret context keywords
  const strongKeywords = [
    "secret", "password", "passwd", "pwd", "private_key", "private-key",
    "api_key", "api-key", "apikey", "access_key", "access-key",
    "secret_key", "secret-key", "auth_token", "auth-token",
    "bearer", "credential", "signing_key", "signing-key",
    "encryption_key", "encryption-key", "master_key", "master-key",
    "database_url", "database-url", "connection_string",
    "client_secret", "client-secret", "app_secret", "app-secret",
  ];

  // Medium-confidence keywords
  const mediumKeywords = [
    "key", "token", "auth", "session", "encrypt", "decrypt",
    "hmac", "hash", "salt", "aws", "azure", "gcp",
    "webhook", "endpoint", "authorization",
    "redis", "mongo", "postgres", "mysql",
    "s3", "bucket", "cloud",
  ];

  let score = 0.3; // LOWERED base score (was 0.6) — require context to pass

  for (const kw of strongKeywords) {
    if (lookback.includes(kw)) {
      score = Math.min(score + 0.5, 1.5);
    }
  }
  for (const kw of mediumKeywords) {
    if (lookback.includes(kw)) {
      score = Math.min(score + 0.2, 1.5);
    }
  }

  // Assignment operators boost confidence
  if (/[=:]\s*["']?\s*$/.test(lookback.slice(-20))) score += 0.2;
  // Inside quotes after assignment
  if (/=\s*["']$/.test(lookback.trimEnd())) score += 0.15;
  // Environment variable pattern: KEY=value
  if (/^[A-Z_]+=/.test(text.substring(Math.max(0, startIdx - 60), startIdx + 5))) score += 0.3;
  // .env file format
  if (/^[A-Z][A-Z0-9_]*=/.test(text.substring(Math.max(0, startIdx - 60), startIdx + 5))) score += 0.3;

  return Math.min(score, 1.5);
}

/**
 * Scan text for high-entropy strings that may be secrets
 * ENTERPRISE EDITION: Much stricter filtering
 * @param {string} text - Full text to scan
 * @param {string} src - Source identifier (URL, filename, etc.)
 * @returns {Array} Array of entropy findings
 */
export function scanEntropy(text, src) {
  if (!text || text.length < MIN_SECRET_LENGTH) return [];

  // Skip scanning known-safe sources entirely
  const srcLower = (src || "").toLowerCase();
  const safeSources = [
    "jquery", "bootstrap", "react", "angular", "vue", "lodash", "moment",
    "polyfill", "gtag", "analytics", "fonts.googleapis", "cdn.jsdelivr",
    "cdnjs.cloudflare", "unpkg.com", "fontawesome", "tailwind",
    "d3.min", "chart.min", "three.min", "gsap", "anime.min",
  ];
  if (safeSources.some(s => srcLower.includes(s))) return [];

  const findings = [];
  const seen = new Set();

  const charsets = [
    { name: "hex", chars: HEX_CHARS, threshold: THRESHOLDS.hex },
    { name: "base64", chars: BASE64_CHARS, threshold: THRESHOLDS.base64 },
    { name: "base64url", chars: BASE64URL_CHARS, threshold: THRESHOLDS.base64url },
  ];

  for (const { name, chars, threshold } of charsets) {
    const candidates = extractStringsOfCharset(text, chars);
    for (const candidate of candidates) {
      if (seen.has(candidate.value)) continue;

      // AGGRESSIVE false positive check — the main improvement
      if (isFalsePositive(candidate.value, text, candidate.start)) continue;

      const entropy = shannonEntropy(candidate.value);
      if (entropy < threshold) continue;

      const ctx = contextScore(text, candidate.start);
      const adjustedEntropy = entropy * ctx;

      // STRICTER final threshold — require adjusted entropy to exceed threshold
      if (adjustedEntropy < threshold) continue;

      // EXTRA: Require either high raw entropy OR strong context
      if (entropy < threshold + 0.3 && ctx < 0.8) continue;

      seen.add(candidate.value);
      const truncated = candidate.value.length > 40
        ? candidate.value.substring(0, 20) + "..." + candidate.value.substring(candidate.value.length - 10)
        : candidate.value;

      // Determine severity based on both entropy and context
      let severity = "low";
      if (entropy > 5.0 && ctx >= 1.0) severity = "critical";
      else if (entropy > 4.8 && ctx >= 0.8) severity = "high";
      else if (entropy > 4.5 && ctx >= 0.6) severity = "medium";

      findings.push({
        key: `High Entropy String (${name})`,
        match: truncated,
        fullMatch: candidate.value,
        src: src,
        entropy: entropy.toFixed(2),
        contextScore: ctx.toFixed(2),
        severity,
        type: "entropy",
      });
    }
  }
  return findings;
}
