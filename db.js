// db.js — IndexedDB storage engine with SARIF export
// Enhanced for Trufflehog on Steroids²

const DB_NAME = "trufflehog_steroids_v2";
const DB_VERSION = 3;
const STORE_FINDINGS = "findings";

let dbInstance = null;

function openDB() {
  if (dbInstance) return Promise.resolve(dbInstance);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (db.objectStoreNames.contains(STORE_FINDINGS)) db.deleteObjectStore(STORE_FINDINGS);
      const store = db.createObjectStore(STORE_FINDINGS, { keyPath: "id", autoIncrement: true });
      store.createIndex("origin", "origin", { unique: false });
      store.createIndex("severity", "severity", { unique: false });
      store.createIndex("timestamp", "timestamp", { unique: false });
      store.createIndex("key", "key", { unique: false });
      store.createIndex("type", "type", { unique: false });
      store.createIndex("origin_key_match", ["origin", "key", "match"], { unique: false });
    };
    req.onsuccess = (e) => { dbInstance = e.target.result; resolve(dbInstance); };
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function addFinding(finding) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_FINDINGS, "readwrite");
    const store = tx.objectStore(STORE_FINDINGS);
    const idx = store.index("origin_key_match");
    const lookup = idx.get([finding.origin, finding.key, finding.match]);
    lookup.onsuccess = () => {
      if (lookup.result) { resolve(null); return; }
      const record = { ...finding, timestamp: Date.now() };
      const addReq = store.add(record);
      addReq.onsuccess = () => resolve(record);
      addReq.onerror = (e) => reject(e.target.error);
    };
    lookup.onerror = () => {
      const record = { ...finding, timestamp: Date.now() };
      const addReq = store.add(record);
      addReq.onsuccess = () => resolve(record);
      addReq.onerror = (e) => reject(e.target.error);
    };
  });
}

export async function getFindingsByOrigin(origin) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_FINDINGS, "readonly");
    const idx = tx.objectStore(STORE_FINDINGS).index("origin");
    const req = idx.getAll(origin);
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function getAllFindings() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_FINDINGS, "readonly");
    const req = tx.objectStore(STORE_FINDINGS).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function getFindingsBySeverity(severity) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_FINDINGS, "readonly");
    const idx = tx.objectStore(STORE_FINDINGS).index("severity");
    const req = idx.getAll(severity);
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function getStats() {
  const all = await getAllFindings();
  const stats = {
    total: all.length,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byOrigin: {},
    byType: {},
    byCategory: {},
    recentFindings: [],
  };
  for (const f of all) {
    stats.bySeverity[f.severity] = (stats.bySeverity[f.severity] || 0) + 1;
    stats.byOrigin[f.origin] = (stats.byOrigin[f.origin] || 0) + 1;
    const type = f.type || "regex";
    stats.byType[type] = (stats.byType[type] || 0) + 1;
    if (f.category) stats.byCategory[f.category] = (stats.byCategory[f.category] || 0) + 1;
  }
  stats.recentFindings = all.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)).slice(0, 20);
  return stats;
}

export async function clearOriginFindings(origin) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_FINDINGS, "readwrite");
    const idx = tx.objectStore(STORE_FINDINGS).index("origin");
    const req = idx.openCursor(origin);
    req.onsuccess = (e) => { const c = e.target.result; if (c) { c.delete(); c.continue(); } else resolve(); };
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function clearAllFindings() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_FINDINGS, "readwrite");
    const req = tx.objectStore(STORE_FINDINGS).clear();
    req.onsuccess = () => resolve();
    req.onerror = (e) => reject(e.target.error);
  });
}

export async function exportFindings() {
  return JSON.stringify(await getAllFindings(), null, 2);
}

export async function exportCSV() {
  const all = await getAllFindings();
  const headers = ["timestamp", "severity", "origin", "key", "match", "src", "type", "category", "parentUrl", "encoded"];
  const rows = [headers.join(",")];
  for (const f of all) {
    const row = headers.map(h => {
      let val = f[h] || "";
      if (typeof val === "object") val = JSON.stringify(val);
      return `"${String(val).replace(/"/g, '""')}"`;
    });
    rows.push(row.join(","));
  }
  return rows.join("\n");
}

/**
 * Export findings in SARIF format (GitHub Advanced Security compatible)
 */
export async function exportSARIF() {
  const all = await getAllFindings();
  const sevMap = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

  const results = all.map((f, i) => ({
    ruleId: `THS-${(f.type || "regex").toUpperCase()}-${String(i + 1).padStart(4, "0")}`,
    level: sevMap[f.severity] || "note",
    message: { text: `${f.key}: ${f.match}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.src || f.parentUrl || "unknown" },
        region: { startLine: 1 },
      }
    }],
    properties: {
      severity: f.severity,
      type: f.type || "regex",
      category: f.category || "unknown",
      origin: f.origin || "",
      confidence: f.aiAnalysis?.confidence || null,
      verdict: f.aiAnalysis?.verdict || null,
    },
  }));

  const sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "Trufflehog on Steroids²",
          version: "3.0.0",
          informationUri: "https://github.com/trufflehog-steroids",
          rules: [...new Set(all.map(f => f.key))].map((name, i) => ({
            id: `THS-${String(i + 1).padStart(4, "0")}`,
            name: name,
            shortDescription: { text: name },
          })),
        },
      },
      results,
    }],
  };
  return JSON.stringify(sarif, null, 2);
}
