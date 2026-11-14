/**
 * Client-Side Network Exfiltration Firewall & Air-Gap Lockdown
 */

export class NetworkFirewall {
  constructor(onLogCallback = null) {
    this.airGapLocked = false;
    this.logs = [];
    this.onLogCallback = onLogCallback;
    this.installed = false;
  }

  install() {
    if (this.installed || typeof window === 'undefined') return;
    this.installed = true;

    const self = this;

    const originalFetch = window.fetch.bind(window);
    window.fetch = async function (input, init = {}) {
      const url = typeof input === 'string' ? input : input?.url || String(input);
      const method = (init?.method || (typeof input === 'object' && input?.method) || 'GET').toUpperCase();

      if (self.shouldBlock(url, method)) {
        self.record(method, url, 'BLOCKED (Air-Gap Lockdown)', true);
        throw new Error(`[LocalVault Firewall] Blocked outbound ${method} request to ${url}`);
      }

      self.record(method, url, 'ALLOWED (Read-Only Weight/Asset Fetch)', false);
      return originalFetch(input, init);
    };

    if (window.XMLHttpRequest) {
      const origOpen = window.XMLHttpRequest.prototype.open;
      window.XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        const cleanMethod = String(method || 'GET').toUpperCase();
        const cleanUrl = String(url || '');
        if (self.shouldBlock(cleanUrl, cleanMethod)) {
          self.record(cleanMethod, cleanUrl, 'BLOCKED (Air-Gap / XHR)', true);
          throw new Error(`[LocalVault Firewall] Blocked XHR ${cleanMethod} to ${cleanUrl}`);
        }
        self.record(cleanMethod, cleanUrl, 'ALLOWED (XHR Read)', false);
        return origOpen.call(this, method, url, ...rest);
      };
    }

    if (navigator.sendBeacon) {
      navigator.sendBeacon = function (url) {
        self.record('BEACON', String(url), 'BLOCKED (Zero-Telemetry Policy)', true);
        return false;
      };
    }
  }

  shouldBlock(url, method) {
    if (url.startsWith('blob:') || url.startsWith('data:')) {
      return false;
    }
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return true;
    }
    if (this.airGapLocked && /^https?:\/\//i.test(url)) {
      const isSameOrigin = url.startsWith(window.location.origin);
      if (!isSameOrigin) return true;
    }
    return false;
  }

  setAirGapLockdown(locked) {
    this.airGapLocked = Boolean(locked);
    this.record(
      'SYSTEM',
      'localvault://airgap-switch',
      this.airGapLocked ? 'STRICT AIR-GAP LOCKED (All external traffic blocked)' : 'Air-Gap Unlocked (Model CDN reads permitted)',
      false
    );
  }

  record(method, url, status, blocked) {
    const entry = {
      time: new Date().toLocaleTimeString(),
      method,
      url: url.length > 85 ? url.slice(0, 82) + '...' : url,
      status,
      blocked
    };
    this.logs.unshift(entry);
    if (this.logs.length > 50) this.logs.pop();
    if (typeof this.onLogCallback === 'function') {
      this.onLogCallback(this.logs, entry);
    }
  }
  }
