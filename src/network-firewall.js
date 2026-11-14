/** Page-level request guard. This is defense-in-depth, not an OS/browser firewall. */
export const ALLOWED_MODEL_HOSTS = Object.freeze([
  'huggingface.co', 'cdn-lfs.huggingface.co', 'cdn-lfs-us-1.huggingface.co',
  'cdn-lfs-eu-1.huggingface.co', 'cdn.jsdelivr.net', 'cas-bridge.xethub.hf.co',
  'transfer.xethub.hf.co', 'us.aws.cdn.hf.co'
]);
const READ_METHODS = new Set(['GET', 'HEAD']);
const SAFE_LOCAL_PROTOCOLS = new Set(['blob:', 'data:']);
const SENSITIVE_QUERY = /^(?:token|access_token|auth_token|api_key|apikey|key|secret|client_secret|password|passwd|auth|authorization|signature|credential|session|code|email|username|phone|address)$/i;
const xhrState = new WeakMap();

function normalizedMethod(method) { return String(method || 'GET').trim().toUpperCase(); }
function redactUrl(raw, base) {
  try {
    const url = new URL(String(raw || ''), base);
    if (url.protocol === 'data:') return 'data:[omitted]';
    if (url.protocol === 'blob:') return 'blob:[local resource]';
    if (url.username) url.username = '[REDACTED]';
    if (url.password) url.password = '[REDACTED]';
    for (const key of [...url.searchParams.keys()]) if (SENSITIVE_QUERY.test(key)) url.searchParams.set(key, '[REDACTED]');
    return url.toString().slice(0, 1600);
  } catch { return '[unparseable URL omitted]'; }
}

export class NetworkFirewall {
  constructor(options = {}) {
    this.airGapLockdown = Boolean(options.airGapLockdown);
    this.auditLog = [];
    this.listeners = new Set();
    this.installed = false;
    this.installErrors = [];
    this.targetGlobal = null;
    this.originalFetch = null;
    this.originalXhrOpen = null;
    this.originalXhrSend = null;
    this.originalSendBeacon = null;
  }
  getBaseUrl() { return this.targetGlobal?.location?.href || globalThis.location?.href || 'https://localvault.invalid/'; }
  getOrigin() { try { return new URL(this.getBaseUrl()).origin; } catch { return 'https://localvault.invalid'; } }
  onAuditEvent(listener) { if (typeof listener !== 'function') return () => {}; this.listeners.add(listener); return () => this.listeners.delete(listener); }
  recordEvent(entry) {
    const event = Object.freeze({ id: `fw_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, timestamp: new Date().toISOString(), ...entry });
    this.auditLog.unshift(event);
    if (this.auditLog.length > 250) this.auditLog.length = 250;
    for (const listener of this.listeners) { try { listener(event); } catch { /* observers cannot affect policy */ } }
    return event;
  }
  setAirGapLockdown(enabled) {
    this.airGapLockdown = Boolean(enabled);
    this.recordEvent({ method: 'SYSTEM', url: 'localvault://airgap-policy', action: this.airGapLockdown ? 'LOCKDOWN_ENABLED' : 'LOCKDOWN_DISABLED', reason: this.airGapLockdown ? 'External page-level requests are denied.' : 'Approved read-only model destinations are available.' });
  }
  inspectRequest(input, method = 'GET', body = null, options = {}) {
    const rawUrl = typeof input === 'string' ? input : input?.url || String(input || '');
    const verb = normalizedMethod(method);
    const logUrl = redactUrl(rawUrl, this.getBaseUrl());
    const decide = (allowed, action, reason) => { const item = { allowed, action, method: verb, url: logUrl, reason }; this.recordEvent(item); return item; };
    if (!READ_METHODS.has(verb)) return decide(false, 'BLOCKED_METHOD', `Outbound ${verb} requests are not permitted.`);
    if (body !== null && body !== undefined) return decide(false, 'BLOCKED_PAYLOAD', 'Requests carrying a body are not permitted.');
    let url;
    try { url = new URL(rawUrl, this.getBaseUrl()); } catch { return decide(false, 'BLOCKED_INVALID_URL', 'The request URL could not be parsed.'); }
    if (url.username || url.password) return decide(false, 'BLOCKED_CREDENTIAL_URL', 'URLs containing embedded credentials are not permitted.');
    if (SAFE_LOCAL_PROTOCOLS.has(url.protocol)) {
      if (url.protocol === 'blob:' && url.origin !== this.getOrigin()) return decide(false, 'BLOCKED_CROSS_ORIGIN_BLOB', 'Cross-origin blob URLs are blocked.');
      return decide(true, 'ALLOWED_LOCAL', 'Local generated resource.');
    }
    if (!['http:', 'https:'].includes(url.protocol)) return decide(false, 'BLOCKED_PROTOCOL', 'Unsupported request protocol.');
    if (url.origin === this.getOrigin()) return decide(true, 'ALLOWED_SAME_ORIGIN', 'Same-origin application resource.');
    if (this.airGapLockdown) return decide(false, 'BLOCKED_AIRGAP', 'External requests are disabled by strict page-level lockdown.');
    if (url.protocol !== 'https:') return decide(false, 'BLOCKED_PROTOCOL', 'External requests must use HTTPS.');
    if (url.port && url.port !== '443') return decide(false, 'BLOCKED_PORT', 'Non-standard HTTPS ports are blocked.');
    if (!ALLOWED_MODEL_HOSTS.includes(url.hostname.toLowerCase())) return decide(false, 'BLOCKED_UNAPPROVED_HOST', 'External hostname is not approved.');
    if (options.credentials === 'include') return decide(false, 'BLOCKED_CREDENTIALS', 'Cross-origin credential requests are blocked.');
    if (options.mode === 'no-cors') return decide(false, 'BLOCKED_NO_CORS', 'Opaque external no-cors requests are blocked.');
    return decide(true, 'ALLOWED_READONLY', 'HTTPS read-only request to an approved model/library host.');
  }
  install(target = globalThis) {
    if (this.installed || !target) return this;
    this.targetGlobal = target;
    this.installErrors = [];
    const firewall = this;
    if (typeof target.fetch === 'function') {
      this.originalFetch = target.fetch;
      try {
        target.fetch = async function localVaultFetch(input, init = {}) {
          const method = init.method || input?.method || 'GET';
          const body = Object.hasOwn(init, 'body') ? init.body : input?.body ?? null;
          let external = false;
          try { external = new URL(typeof input === 'string' ? input : input.url, firewall.getBaseUrl()).origin !== firewall.getOrigin(); } catch { /* inspectRequest records invalid URL */ }
          const verdict = firewall.inspectRequest(input, method, body, { credentials: init.credentials || input?.credentials, mode: init.mode || input?.mode, external });
          if (!verdict.allowed) throw new TypeError(`[LocalVault Firewall] ${verdict.reason}`);
          return firewall.originalFetch.call(target, input, init);
        };
      } catch (error) { this.installErrors.push(`fetch: ${error?.message || error}`); }
    }
    const XHR = target.XMLHttpRequest;
    if (typeof XHR === 'function' && XHR.prototype) {
      const proto = XHR.prototype;
      this.originalXhrOpen = proto.open;
      this.originalXhrSend = proto.send;
      try {
        proto.open = function localVaultXhrOpen(method, url, ...rest) { xhrState.set(this, { method: normalizedMethod(method), url: String(url || '') }); return firewall.originalXhrOpen.call(this, method, url, ...rest); };
        proto.send = function localVaultXhrSend(body) { const info = xhrState.get(this) || { method: 'GET', url: '' }; const verdict = firewall.inspectRequest(info.url, info.method, body ?? null); if (!verdict.allowed) throw new TypeError(`[LocalVault Firewall] ${verdict.reason}`); return firewall.originalXhrSend.call(this, body); };
      } catch (error) { this.installErrors.push(`XMLHttpRequest: ${error?.message || error}`); }
    }
    if (target.navigator && typeof target.navigator.sendBeacon === 'function') {
      this.originalSendBeacon = target.navigator.sendBeacon;
      try { target.navigator.sendBeacon = (url, data) => { firewall.inspectRequest(url, 'POST', data === undefined ? 'beacon' : data); return false; }; }
      catch (error) { this.installErrors.push(`sendBeacon: ${error?.message || error}`); }
    }
    this.installed = true;
    this.recordEvent({ method: 'SYSTEM', url: 'localvault://firewall-install', action: this.installErrors.length ? 'PARTIAL_INSTALL' : 'INSTALLED', reason: this.installErrors.length ? this.installErrors.join('; ') : 'Available page-level request interceptors installed.' });
    return this;
  }
  uninstall(target = this.targetGlobal || globalThis) {
    if (!this.installed || !target) return;
    if (this.originalFetch) target.fetch = this.originalFetch;
    if (this.originalXhrOpen && target.XMLHttpRequest?.prototype) { target.XMLHttpRequest.prototype.open = this.originalXhrOpen; target.XMLHttpRequest.prototype.send = this.originalXhrSend; }
    if (this.originalSendBeacon && target.navigator) { try { target.navigator.sendBeacon = this.originalSendBeacon; } catch { /* browser may expose a read-only method */ } }
    this.installed = false; this.targetGlobal = null;
    this.originalFetch = this.originalXhrOpen = this.originalXhrSend = this.originalSendBeacon = null;
  }
  getStats() {
    let allowed = 0; let blocked = 0;
    for (const event of this.auditLog) { if (event.action?.startsWith('BLOCKED')) blocked++; else if (event.action?.startsWith('ALLOWED')) allowed++; }
    return { totalEvents: this.auditLog.length, allowed, blocked, airGapLockdown: this.airGapLockdown, installed: this.installed, installErrors: [...this.installErrors], allowedHosts: [...ALLOWED_MODEL_HOSTS] };
  }
}
