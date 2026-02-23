// interceptor.js — Page-level network interception
// Enhanced for Trufflehog on Steroids² — captures full headers for security analysis

(function() {
  'use strict';

  const MAX_BODY_SIZE = 500000;
  const CHANNEL = "__trufflehog_intercept__";

  function sendToExtension(data) {
    window.dispatchEvent(new CustomEvent(CHANNEL, { detail: data }));
  }

  // ── Intercept fetch() ──
  const originalFetch = window.fetch;
  window.fetch = function(...args) {
    return originalFetch.apply(this, args).then(response => {
      const cloned = response.clone();
      const url = typeof args[0] === "string" ? args[0] : args[0]?.url || "";
      const contentType = cloned.headers?.get("content-type") || "";

      if (contentType.includes("text") || contentType.includes("json") || contentType.includes("javascript") || contentType.includes("xml")) {
        cloned.text().then(body => {
          if (body && body.length < MAX_BODY_SIZE) {
            sendToExtension({ type: "fetch_response", url, body, contentType });
          }
        }).catch(() => {});
      }

      // Capture ALL response headers for security analysis
      try {
        const allHeaders = {};
        response.headers.forEach((value, name) => { allHeaders[name] = value; });
        if (Object.keys(allHeaders).length > 0) {
          sendToExtension({ type: "response_headers_full", url, headers: allHeaders });
        }
      } catch (e) {}

      // Legacy: specific header checks
      const authHeader = response.headers?.get("authorization") || "";
      const setCookie = response.headers?.get("set-cookie") || "";
      if (authHeader || setCookie) {
        sendToExtension({ type: "response_headers", url, authorization: authHeader, setCookie });
      }

      return response;
    });
  };

  // ── Intercept XMLHttpRequest ──
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this.__trufflehog_url = url;
    this.__trufflehog_method = method;
    return originalXHROpen.apply(this, [method, url, ...rest]);
  };

  XMLHttpRequest.prototype.send = function(body) {
    this.addEventListener("load", function() {
      try {
        const contentType = this.getResponseHeader("content-type") || "";
        if (contentType.includes("text") || contentType.includes("json") || contentType.includes("javascript") || contentType.includes("xml")) {
          const responseBody = this.responseText;
          if (responseBody && responseBody.length < MAX_BODY_SIZE) {
            sendToExtension({ type: "xhr_response", url: this.__trufflehog_url || "", body: responseBody, contentType });
          }
        }

        // Capture all response headers
        const rawHeaders = this.getAllResponseHeaders();
        if (rawHeaders) {
          const headers = {};
          rawHeaders.trim().split(/[\r\n]+/).forEach(line => {
            const parts = line.split(': ');
            const name = parts.shift();
            headers[name.toLowerCase()] = parts.join(': ');
          });
          sendToExtension({ type: "response_headers_full", url: this.__trufflehog_url || "", headers });
        }
      } catch (e) {}
    });

    if (body && typeof body === "string" && body.length < MAX_BODY_SIZE) {
      sendToExtension({ type: "request_body", url: this.__trufflehog_url || "", body });
    }

    return originalXHRSend.apply(this, arguments);
  };

  // ── Intercept WebSocket ──
  const OriginalWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    const ws = protocols ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
    sendToExtension({ type: "websocket_connect", url });
    ws.addEventListener("message", function(event) {
      try {
        const data = typeof event.data === "string" ? event.data : null;
        if (data && data.length < MAX_BODY_SIZE) {
          sendToExtension({ type: "websocket_message", url, body: data });
        }
      } catch (e) {}
    });
    return ws;
  };
  window.WebSocket.prototype = OriginalWebSocket.prototype;
  window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
  window.WebSocket.OPEN = OriginalWebSocket.OPEN;
  window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
  window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;

  // ── Intercept EventSource (SSE) ──
  const OriginalEventSource = window.EventSource;
  if (OriginalEventSource) {
    window.EventSource = function(url, config) {
      const es = new OriginalEventSource(url, config);
      es.addEventListener("message", function(event) {
        if (event.data && event.data.length < MAX_BODY_SIZE) {
          sendToExtension({ type: "sse_message", url, body: event.data });
        }
      });
      return es;
    };
    window.EventSource.prototype = OriginalEventSource.prototype;
  }
})();
