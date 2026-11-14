
/**
 * LocalVault AI — Network Request Firewall
 *
 * Intercepts:
 * - fetch()
 * - XMLHttpRequest
 * - navigator.sendBeacon()
 *
 * Security policy:
 * - Allows GET and HEAD only.
 * - Blocks requests carrying payloads.
 * - Allows same-origin application resources.
 * - Allows HTTPS requests to explicitly approved hosts.
 * - Blocks unapproved external hosts and suspicious URLs.
 * - Strict Air-Gap mode blocks all external requests.
 *
 * IMPORTANT:
 * This is a client-side request guard, NOT a complete network firewall.
 * It does not automatically intercept requests from Web Workers,
 * Service Workers, WebSockets, WebRTC or browser-managed connections.
 */

const ALLOWED_MODEL_HOSTS = Object.freeze([
  'huggingface.co',
  'cdn-lfs.huggingface.co',
  'cdn-lfs-us-1.huggingface.co',
  'cdn-lfs-eu-1.huggingface.co',
  'cdn.jsdelivr.net',
  'cas-bridge.xethub.hf.co',
  'transfer.xethub.hf.co'
]);

const ALLOWED_METHODS = new Set(['GET', 'HEAD']);

const LOCAL_PROTOCOLS = new Set(['blob:', 'data:']);

const SENSITIVE_QUERY_KEYS =
  /^(?:token|access_token|api_key|apikey|key|secret|password|passwd|auth|authorization|signature|credential|session|code)$/i;

const xhrMetadata = new WeakMap();

function normalizeMethod(method) {
  return String(method || 'GET').trim().toUpperCase();
}

function sanitizeUrlForLog(rawUrl, baseUrl) {
  const source = String(rawUrl || '');

  try {
    const parsed = new URL(source, baseUrl);

    // Never expose URL-embedded credentials in logs.
    if (parsed.username || parsed.password) {
      parsed.username = '[REDACTED]';
      parsed.password = '[REDACTED]';
    }

    // Remove sensitive query parameter values.
    for (const key of [...parsed.searchParams.keys()]) {
      if (SENSITIVE_QUERY_KEYS.test(key)) {
        parsed.searchParams.set(key, '[REDACTED]');
      }
    }

    return parsed.toString().slice(0, 2000);
  } catch {
    return source.slice(0, 2000);
  }
}

export class NetworkFirewall {
  constructor(options = {}) {
    this.airGapLockdown = Boolean(options.airGapLockdown);

    this.auditLog = [];
    this.listeners = new Set();

    this.installed = false;
    this.targetGlobal = null;

    this.originalFetch = null;
    this.originalXhrOpen = null;
    this.originalXhrSend = null;
    this.originalSendBeacon = null;

    this.installErrors = [];
  }

  getBaseUrl() {
    const location =
      this.targetGlobal?.location ||
      globalThis.location;

    return location?.href || 'https://localvault.invalid/';
  }

  getOrigin() {
    try {
      return new URL(this.getBaseUrl()).origin;
    } catch {
      return 'https://localvault.invalid';
    }
  }

  onAuditEvent(listener) {
    if (typeof listener !== 'function') {
      return () => {};
    }

    this.listeners.add(listener);

    return () => this.listeners.delete(listener);
  }

  recordEvent(entry) {
    const event = Object.freeze({
      id: `fw_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
      ...entry
    });

    this.auditLog.unshift(event);

    if (this.auditLog.length > 250) {
      this.auditLog.pop();
    }

    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Audit listener errors must not affect request handling.
      }
    }

    return event;
  }

  setAirGapLockdown(enabled) {
    this.airGapLockdown = Boolean(enabled);

    this.recordEvent({
      method: 'SYSTEM',
      url: 'localvault://airgap-policy',
      action: this.airGapLockdown
        ? 'LOCKDOWN_ENABLED'
        : 'LOCKDOWN_DISABLED',
      reason: this.airGapLockdown
        ? 'Strict lockdown enabled. External requests are denied.'
        : 'Strict lockdown disabled. Approved read-only destinations are permitted.'
    });
  }

  /**
   * Evaluate a request against the current firewall policy.
   *
   * @param {string} url
   * @param {string} [method='GET']
   * @param {any} [body=null]
   * @returns {{allowed:boolean,action:string,reason:string,method:string,url:string}}
   */
  inspectRequest(url, method = 'GET', body = null) {
    const normalizedMethod = normalizeMethod(method);
    const rawUrl = String(url || '');
    const baseUrl = this.getBaseUrl();
    const loggedUrl = sanitizeUrlForLog(rawUrl, baseUrl);

    const decide = (allowed, action, reason) => {
      const decision = {
        allowed,
        action,
        method: normalizedMethod,
        url: loggedUrl,
        reason
      };

      this.recordEvent(decision);
      return decision;
    };

    // 1. Permit only read-only HTTP methods.
    if (!ALLOWED_METHODS.has(normalizedMethod)) {
      return decide(
        false,
        'BLOCKED_METHOD',
        `Outbound ${normalizedMethod} requests are not permitted.`
      );
    }

    // 2. Block any request with a supplied body.
    if (body !== null && body !== undefined) {
      return decide(
        false,
        'BLOCKED_PAYLOAD',
        'Requests carrying a body are not permitted.'
      );
    }

    // 3. Parse and normalize the destination.
    let parsedUrl;

    try {
      parsedUrl = new URL(rawUrl, baseUrl);
    } catch {
      return decide(
        false,
        'BLOCKED_INVALID_URL',
        'The request URL could not be safely parsed.'
      );
    }

    // 4. Never accept embedded URL credentials.
    if (parsedUrl.username || parsedUrl.password) {
      return decide(
        false,
        'BLOCKED_CREDENTIAL_URL',
        'URLs containing embedded credentials are not permitted.'
      );
    }

    // 5. Permit local generated resources.
    if (LOCAL_PROTOCOLS.has(parsedUrl.protocol)) {
      if (
        parsedUrl.protocol === 'blob:' &&
        parsedUrl.origin !== this.getOrigin()
      ) {
        return decide(
          false,
          'BLOCKED_CROSS_ORIGIN_BLOB',
          'Blob URL does not belong to this application origin.'
        );
      }

      return decide(
        true,
        'ALLOWED_LOCAL',
        'Local generated resource.'
      );
    }

    // 6. Permit the application to load its own resources.
    if (parsedUrl.origin === this.getOrigin()) {
      return decide(
        true,
        'ALLOWED_SAME_ORIGIN',
        'Same-origin application resource.'
      );
    }

    // 7. Strict lockdown blocks all external traffic.
    if (this.airGapLockdown) {
      return decide(
        false,
        'BLOCKED_AIRGAP',
        'External traffic is disabled by Strict Air-Gap Lockdown.'
      );
    }

    // 8. External requests must use HTTPS.
    if (parsedUrl.protocol !== 'https:') {
      return decide(
        false,
        'BLOCKED_PROTOCOL',
        'External requests must use HTTPS.'
      );
    }

    // 9. Exact hostname allowlist. Similar-looking domains are rejected.
    const hostname = parsedUrl.hostname.toLowerCase();

    if (!ALLOWED_MODEL_HOSTS.includes(hostname)) {
      return decide(
        false,
        'BLOCKED_UNAPPROVED_HOST',
        'External hostname is not on the approved model/library list.'
      );
    }

    // 10. Only standard HTTPS port is accepted.
    if (parsedUrl.port && parsedUrl.port !== '443') {
      return decide(
        false,
        'BLOCKED_PORT',
        'Non-standard external ports are not permitted.'
      );
    }

    return decide(
      true,
      'ALLOWED_READONLY',
      'HTTPS read-only request to an approved model/library host.'
    );
  }

  /**
   * Install fetch, XMLHttpRequest and sendBeacon interceptors.
   */
  install(targetGlobal = globalThis) {
    if (this.installed || !targetGlobal) {
      return this;
    }

    this.targetGlobal = targetGlobal;

    const firewall = this;

    // ----------------------------------------------------------
    // fetch()
    // ----------------------------------------------------------

    if (typeof targetGlobal.fetch === 'function') {
      const originalFetch = targetGlobal.fetch;

      this.originalFetch = originalFetch;

      try {
        targetGlobal.fetch = async function interceptedFetch(
          input,
          init = {}
        ) {
          const options = init || {};

          const requestUrl =
            typeof input === 'string'
              ? input
              : input && typeof input.url === 'string'
                ? input.url
                : String(input);

          const requestMethod =
            options.method ||
            (input && typeof input === 'object' && input.method) ||
            'GET';

          const requestBody =
            Object.prototype.hasOwnProperty.call(options, 'body')
              ? options.body
              : input && typeof input === 'object'
                ? input.body ?? null
                : null;

          const verdict = firewall.inspectRequest(
            requestUrl,
            requestMethod,
            requestBody
          );

          if (!verdict.allowed) {
            throw new Error(
              `[LocalVault Firewall] ${verdict.reason}`
            );
          }

          return originalFetch.call(
            targetGlobal,
            input,
            init
          );
        };
      } catch (error) {
        this.installErrors.push(
          `fetch interceptor: ${error?.message || String(error)}`
        );
      }
    }

    // ----------------------------------------------------------
    // XMLHttpRequest
    // ----------------------------------------------------------

    if (typeof targetGlobal.XMLHttpRequest === 'function') {
      const prototype = targetGlobal.XMLHttpRequest.prototype;

      this.originalXhrOpen = prototype.open;
      this.originalXhrSend = prototype.send;

      try {
        prototype.open = function interceptedOpen(
          method,
          url,
          ...rest
        ) {
          xhrMetadata.set(this, {
            method: normalizeMethod(method),
            url: String(url || '')
          });

          return firewall.originalXhrOpen.call(
            this,
            method,
            url,
            ...rest
          );
        };

        prototype.send = function interceptedSend(body) {
          const metadata = xhrMetadata.get(this) || {
            method: 'GET',
            url: ''
          };

          const verdict = firewall.inspectRequest(
            metadata.url,
            metadata.method,
            body
          );

          if (!verdict.allowed) {
            throw new Error(
              `[LocalVault Firewall] ${verdict.reason}`
            );
          }

          return firewall.originalXhrSend.call(
            this,
            body
          );
        };
      } catch (error) {
        this.installErrors.push(
          `XMLHttpRequest interceptor: ${error?.message || String(error)}`
        );
      }
    }

    // ----------------------------------------------------------
    // navigator.sendBeacon()
    // ----------------------------------------------------------

    if (
      targetGlobal.navigator &&
      typeof targetGlobal.navigator.sendBeacon === 'function'
    ) {
      const navigatorObject = targetGlobal.navigator;

      this.originalSendBeacon =
        navigatorObject.sendBeacon;

      try {
        navigatorObject.sendBeacon = function interceptedBeacon(
          url,
          data
        ) {
          firewall.inspectRequest(
            url,
            'POST',
            data === undefined ? 'beacon' : data
          );

          // Do not send the payload.
          return false;
        };
      } catch (error) {
        this.installErrors.push(
          `sendBeacon interceptor: ${error?.message || String(error)}`
        );
      }
    }

    this.installed = true;

    this.recordEvent({
      method: 'SYSTEM',
      url: 'localvault://firewall-install',
      action: this.installErrors.length
        ? 'PARTIAL_INSTALL'
        : 'INSTALLED',
      reason: this.installErrors.length
        ? this.installErrors.join('; ')
        : 'Available request interceptors installed.'
    });

    return this;
  }

  /**
   * Restore the original browser methods.
   */
  uninstall(targetGlobal = this.targetGlobal || globalThis) {
    if (!this.installed || !targetGlobal) {
      return;
    }

    if (this.originalFetch) {
      targetGlobal.fetch = this.originalFetch;
    }

    if (
      this.originalXhrOpen &&
      targetGlobal.XMLHttpRequest
    ) {
      targetGlobal.XMLHttpRequest.prototype.open =
        this.originalXhrOpen;

      targetGlobal.XMLHttpRequest.prototype.send =
        this.originalXhrSend;
    }

    if (
      this.originalSendBeacon &&
      targetGlobal.navigator
    ) {
      try {
        targetGlobal.navigator.sendBeacon =
          this.originalSendBeacon;
      } catch {
        // Some browsers expose read-only navigator methods.
      }
    }

    this.installed = false;
    this.targetGlobal = null;
  }

  /**
   * Return a summary of recorded firewall events.
   */
  getStats() {
    let allowed = 0;
    let blocked = 0;

    for (const event of this.auditLog) {
      if (event.action?.startsWith('BLOCKED')) {
        blocked++;
      } else if (event.action?.startsWith('ALLOWED')) {
        allowed++;
      }
    }

    return {
      totalEvents: this.auditLog.length,
      allowed,
      blocked,
      airGapLockdown: this.airGapLockdown,
      installed: this.installed,
      installErrors: [...this.installErrors],
      allowedHosts: [...ALLOWED_MODEL_HOSTS]
    };
  }
}
