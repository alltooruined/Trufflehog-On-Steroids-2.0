// inject.js — Content script: page scanning, network interception, DOM analysis
// Enhanced for Trufflehog on Steroids²

(function() {
  'use strict';
  const CHANNEL = "__trufflehog_intercept__";

  // ── 1. Inject the page-level interceptor ──
  try {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('interceptor.js');
    script.onload = function() { this.remove(); };
    (document.head || document.documentElement).appendChild(script);
  } catch (e) {}

  // ── 2. Listen for intercepted network data ──
  window.addEventListener(CHANNEL, function(event) {
    const detail = event.detail;
    if (!detail) return;
    const base = { parentUrl: window.location.href, parentOrigin: window.location.origin };

    if (detail.type === "fetch_response" || detail.type === "xhr_response") {
      chrome.runtime.sendMessage({ networkBody: detail.body, networkUrl: detail.url, networkType: detail.type, ...base });
    } else if (detail.type === "websocket_message" || detail.type === "sse_message") {
      chrome.runtime.sendMessage({ networkBody: detail.body, networkUrl: detail.url, networkType: detail.type, ...base });
    } else if (detail.type === "response_headers") {
      chrome.runtime.sendMessage({
        responseHeaders: { authorization: detail.authorization || "", setCookie: detail.setCookie || "" },
        networkUrl: detail.url, ...base,
      });
    } else if (detail.type === "response_headers_full") {
      chrome.runtime.sendMessage({ fullResponseHeaders: detail.headers, networkUrl: detail.url, ...base });
    } else if (detail.type === "request_body") {
      chrome.runtime.sendMessage({ requestBody: detail.body, networkUrl: detail.url, ...base });
    }
  });

  // ── 3. Scan page body ──
  chrome.runtime.sendMessage({
    pageBody: document.documentElement.innerHTML,
    origin: window.origin,
    parentUrl: window.location.href,
    parentOrigin: window.origin,
  });

  // ── 4. Enumerate and scan external scripts ──
  setTimeout(function() {
    for (let i = 0; i < document.scripts.length; i++) {
      if (document.scripts[i].src) {
        let scriptSRC = document.scripts[i].src;
        if (scriptSRC.startsWith("//")) scriptSRC = location.protocol + scriptSRC;
        chrome.runtime.sendMessage({ scriptUrl: scriptSRC, parentUrl: window.location.href, parentOrigin: window.origin });
      }
    }

    // ── 5. Source map discovery ──
    const inlineScripts = document.querySelectorAll('script:not([src])');
    for (const script of inlineScripts) {
      const mapMatch = script.textContent.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
      if (mapMatch) {
        let mapUrl = mapMatch[1];
        if (mapUrl.startsWith("data:")) continue;
        if (!mapUrl.startsWith("http")) mapUrl = new URL(mapUrl, window.location.href).href;
        chrome.runtime.sendMessage({ sourceMapUrl: mapUrl, parentUrl: window.location.href, parentOrigin: window.origin });
      }
    }

    for (let i = 0; i < document.scripts.length; i++) {
      if (document.scripts[i].src) {
        const srcUrl = document.scripts[i].src;
        for (const mapUrl of [srcUrl + ".map", srcUrl.replace(/\.js$/, ".js.map"), srcUrl.replace(/\.min\.js$/, ".js.map")]) {
          chrome.runtime.sendMessage({ sourceMapUrl: mapUrl, parentUrl: window.location.href, parentOrigin: window.origin });
        }
      }
    }
  }, 2000);

  // ── 6. Check for .env and .git exposure ──
  const origin = window.location.origin;
  const newPath = window.location.pathname.substr(0, window.location.pathname.lastIndexOf("/"));
  const newHref = origin + newPath;

  chrome.runtime.sendMessage({ envFile: newHref + "/.env", parentUrl: window.location.href, parentOrigin: window.origin });
  chrome.runtime.sendMessage({ gitDir: newHref + "/.git/config", parentUrl: window.location.href, parentOrigin: window.origin });
  if (newPath !== "") {
    chrome.runtime.sendMessage({ envFile: origin + "/.env", parentUrl: window.location.href, parentOrigin: window.origin });
    chrome.runtime.sendMessage({ gitDir: origin + "/.git/config", parentUrl: window.location.href, parentOrigin: window.origin });
  }

  // ── 7. Scan meta tags and data attributes ──
  for (const meta of document.querySelectorAll('meta[content]')) {
    const content = meta.getAttribute('content') || "";
    const name = meta.getAttribute('name') || meta.getAttribute('property') || "";
    if (content.length > 15) {
      chrome.runtime.sendMessage({ metaContent: content, metaName: name, parentUrl: window.location.href, parentOrigin: window.origin });
    }
  }

  for (const el of document.querySelectorAll('[data-api-key], [data-token], [data-secret], [data-key], [data-auth]')) {
    for (const attr of el.attributes) {
      if (attr.name.startsWith('data-') && attr.value.length > 10) {
        chrome.runtime.sendMessage({ dataAttribute: attr.value, dataName: attr.name, parentUrl: window.location.href, parentOrigin: window.origin });
      }
    }
  }

  // ── 8. Scan localStorage and sessionStorage ──
  setTimeout(() => {
    try {
      const storageItems = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const val = localStorage.getItem(key);
        if (val && val.length > 15 && val.length < 5000) {
          storageItems.push({ key, value: val });
        }
      }
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const val = sessionStorage.getItem(key);
        if (val && val.length > 15 && val.length < 5000) {
          storageItems.push({ key, value: val });
        }
      }
      if (storageItems.length > 0) {
        chrome.runtime.sendMessage({
          storageData: storageItems,
          parentUrl: window.location.href,
          parentOrigin: window.origin,
        });
      }
    } catch (e) {}
  }, 3000);

  // ── 9. DOM Mutation Observer — catch dynamically added secrets ──
  let mutationScanTimeout = null;
  const observer = new MutationObserver((mutations) => {
    // Debounce: collect mutations and scan in batches
    if (mutationScanTimeout) clearTimeout(mutationScanTimeout);
    mutationScanTimeout = setTimeout(() => {
      let addedText = "";
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            // Check for script elements with src
            if (node.tagName === "SCRIPT" && node.src) {
              chrome.runtime.sendMessage({ scriptUrl: node.src, parentUrl: window.location.href, parentOrigin: window.origin });
            }
            // Collect text from added elements
            const text = node.textContent || "";
            if (text.length > 20 && text.length < 50000) {
              addedText += text + "\n";
            }
          }
        }
      }
      if (addedText.length > 50) {
        chrome.runtime.sendMessage({
          dynamicContent: addedText.substring(0, 100000),
          parentUrl: window.location.href,
          parentOrigin: window.origin,
        });
      }
    }, 2000);
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });

  // ── 10. Scan window.__NEXT_DATA__ and similar hydration data ──
  setTimeout(() => {
    const hydrationKeys = ["__NEXT_DATA__", "__NUXT__", "__INITIAL_STATE__", "__APP_STATE__", "__PRELOADED_STATE__"];
    for (const key of hydrationKeys) {
      try {
        const data = window[key];
        if (data && typeof data === "object") {
          const json = JSON.stringify(data);
          if (json.length > 50 && json.length < 500000) {
            chrome.runtime.sendMessage({
              hydrationData: json,
              hydrationKey: key,
              parentUrl: window.location.href,
              parentOrigin: window.origin,
            });
          }
        }
      } catch (e) {}
    }
  }, 2500);
})();
