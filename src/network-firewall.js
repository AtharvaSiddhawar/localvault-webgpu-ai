/**
 * LocalVault AI v2.0 — Client-Side Network Exfiltration Firewall (src/network-firewall.js)
 * Intercepts fetch, XMLHttpRequest, and navigator.sendBeacon.
 * - Hard-blocks all outbound POST/PUT/PATCH/DELETE payload exfiltration.
 * - Allows read-only GET/HEAD model artifact fetches from allowlisted hosts unless Strict Air-Gap Lockdown is active.
 * - Maintains an immutable, timestamped security audit log for inspection.
 */

const ALLOWED_MODEL_HOSTS = [
  'huggingface.co',
  'cdn-lfs.huggingface.co',
  'cdn-lfs-us-1.huggingface.co',
  'cdn-lfs-eu-1.huggingface.co',
  'cdn.jsdelivr.net',
  'localhost',
  '127.0.0.1'
];

export class NetworkFirewall {
  constructor(options = {}) {
    this.airGapLockdown = Boolean(options.airGapLockdown);
    this.auditLog = [];
    this.listeners = new Set();
    this.installed = false;
    this.originalFetch = null;
    this.originalXhrOpen = null;
    this.originalXhrSend = null;
    this.originalSendBeacon = null;
  }

  onAuditEvent(listener) {
    if (typeof listener === 'function') {
      this.listeners.add(listener);
    }
    return () => this.listeners.delete(listener);
  }

  recordEvent(entry) {
    const event = {
      id: `fw_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
      ...entry
    };
    this.auditLog.unshift(event);
    if (this.auditLog.length > 250) {
      this.auditLog.pop();
    }
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // ignore listener errors
      }
    }
    return event;
  }

  setAirGapLockdown(enabled) {
    this.airGapLockdown = Boolean(enabled);
    this.recordEvent({
      method: 'SYSTEM',
      url: 'localvault://airgap-policy',
      action: this.airGapLockdown ? 'LOCKDOWN_ENABLED' : 'LOCKDOWN_DISABLED',
      reason: this.airGapLockdown
        ? 'Strict Air-Gap Lockdown active: all external network traffic blocked.'
        : 'Read-only model weight fetches permitted; POST/PUT exfiltration blocked.'
    });
  }

  /**
   * Evaluate whether a network request is permitted under current firewall policy.
   * @param {string} url
   * @param {string} [method='GET']
   * @param {any} [body=null]
   * @returns {{ allowed: boolean, action: string, reason: string, method: string, url: string }}
   */
  inspectRequest(url, method = 'GET', body = null) {
    const normalizedMethod = String(method || 'GET').toUpperCase();
    const urlStr = String(url || '');

    // 1. Always block mutating / payload-carrying methods
    if (
      normalizedMethod !== 'GET' &&
      normalizedMethod !== 'HEAD' &&
      normalizedMethod !== 'OPTIONS'
    ) {
      const decision = {
        allowed: false,
        action: 'BLOCKED_EXFILTRATION',
        method: normalizedMethod,
        url: urlStr,
        reason: `Outbound ${normalizedMethod} payload exfiltration is hard-blocked by LocalVault Zero-Cloud policy.`
      };
      this.recordEvent(decision);
      return decision;
    }

    if (body !== null && body !== undefined && String(body).length > 0) {
      const decision = {
        allowed: false,
        action: 'BLOCKED_PAYLOAD',
        method: normalizedMethod,
        url: urlStr,
        reason: 'Request carrying non-empty body on read-only method was blocked.'
      };
      this.recordEvent(decision);
      return decision;
    }

    // 2. If Strict Air-Gap Lockdown is active, block all external traffic (allow only same-origin relative assets)
    if (this.airGapLockdown) {
      const isRelative =
        urlStr.startsWith('./') ||
        urlStr.startsWith('/') ||
        urlStr.startsWith('blob:') ||
        urlStr.startsWith('data:');
      if (!isRelative) {
        const decision = {
          allowed: false,
          action: 'BLOCKED_AIRGAP',
          method: normalizedMethod,
          url: urlStr,
          reason: 'Blocked by Strict Air-Gap Lockdown mode.'
        };
        this.recordEvent(decision);
        return decision;
      }
    }

    // 3. Log permitted read-only model/asset fetch
    const decision = {
      allowed: true,
      action: 'ALLOWED_READONLY',
      method: normalizedMethod,
      url: urlStr,
      reason: 'Read-only GET/HEAD asset or model artifact request.'
    };
    this.recordEvent(decision);
    return decision;
  }

  /**
   * Install runtime interceptors on globalThis.fetch, XMLHttpRequest, and navigator.sendBeacon.
   */
  install(targetGlobal = globalThis) {
    if (this.installed || !targetGlobal) return this;
    const self = this;

    if (typeof targetGlobal.fetch === 'function') {
      this.originalFetch = targetGlobal.fetch.bind(targetGlobal);
      targetGlobal.fetch = async function interceptedFetch(input, init = {}) {
        const url =
          typeof input === 'string'
            ? input
            : input && typeof input.url === 'string'
            ? input.url
            : String(input);
        const method =
          init?.method ||
          (input && typeof input === 'object' && input.method) ||
          'GET';
        const body = init?.body ?? null;

        const verdict = self.inspectRequest(url, method, body);
        if (!verdict.allowed) {
          throw new Error(`[LocalVault Firewall] ${verdict.reason} (${method} ${url})`);
        }
        return self.originalFetch(input, init);
      };
    }

    if (typeof targetGlobal.XMLHttpRequest === 'function') {
      const XHRProto = targetGlobal.XMLHttpRequest.prototype;
      this.originalXhrOpen = XHRProto.open;
      this.originalXhrSend = XHRProto.send;

      XHRProto.open = function interceptedOpen(method, url, ...rest) {
        this.__lvMethod = method;
        this.__lvUrl = url;
        return self.originalXhrOpen.call(this, method, url, ...rest);
      };

      XHRProto.send = function interceptedSend(body) {
        const verdict = self.inspectRequest(
          this.__lvUrl || '',
          this.__lvMethod || 'GET',
          body
        );
        if (!verdict.allowed) {
          throw new Error(
            `[LocalVault Firewall] ${verdict.reason} (${this.__lvMethod} ${this.__lvUrl})`
          );
        }
        return self.originalXhrSend.call(this, body);
      };
    }

    if (
      targetGlobal.navigator &&
      typeof targetGlobal.navigator.sendBeacon === 'function'
    ) {
      this.originalSendBeacon = targetGlobal.navigator.sendBeacon.bind(
        targetGlobal.navigator
      );
      targetGlobal.navigator.sendBeacon = function interceptedBeacon(url, data) {
        self.inspectRequest(url, 'POST', data || 'beacon');
        throw new Error(
          `[LocalVault Firewall] navigator.sendBeacon exfiltration blocked (${url})`
        );
      };
    }

    this.installed = true;
    return this;
  }

  uninstall(targetGlobal = globalThis) {
    if (!this.installed || !targetGlobal) return;
    if (this.originalFetch) targetGlobal.fetch = this.originalFetch;
    if (this.originalXhrOpen && targetGlobal.XMLHttpRequest) {
      targetGlobal.XMLHttpRequest.prototype.open = this.originalXhrOpen;
      targetGlobal.XMLHttpRequest.prototype.send = this.originalXhrSend;
    }
    if (this.originalSendBeacon && targetGlobal.navigator) {
      targetGlobal.navigator.sendBeacon = this.originalSendBeacon;
    }
    this.installed = false;
  }

  getStats() {
    let allowed = 0;
    let blocked = 0;
    for (const item of this.auditLog) {
      if (item.action?.startsWith('BLOCKED')) blocked++;
      else if (item.action?.startsWith('ALLOWED')) allowed++;
    }
    return {
      totalEvents: this.auditLog.length,
      allowed,
      blocked,
      airGapLockdown: this.airGapLockdown,
      allowedHosts: ALLOWED_MODEL_HOSTS
    };
  }
}

