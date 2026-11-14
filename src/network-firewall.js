
/**
 * LocalVault AI — Browser Network Request Guard
 *
 * Intercepts supported page-level:
 * - fetch()
 * - XMLHttpRequest
 * - navigator.sendBeacon()
 *
 * Policy:
 * - Permits GET and HEAD only.
 * - Blocks payload-bearing requests.
 * - Permits same-origin resources.
 * - Permits HTTPS requests to exact approved model/library hosts.
 * - Blocks unapproved external destinations.
 * - Supports Strict Air-Gap Lockdown for intercepted page requests.
 *
 * LIMITATIONS:
 * This is not a complete network firewall.
 * It does not control browser-managed redirects, module imports,
 * Web Workers, Service Workers, WebSockets, WebRTC or OS-level traffic.
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

const LOCAL_PROTOCOLS = new Set([
  'blob:',
  'data:'
]);

const SENSITIVE_QUERY_KEYS =
  /^(?:token|access_token|auth_token|api_key|apikey|key|secret|client_secret|password|passwd|auth|authorization|signature|credential|session|code|email|username|phone|address|state)$/i;

const xhrMetadata = new WeakMap();

function normalizeMethod(method) {
  return String(method || 'GET')
    .trim()
    .toUpperCase();
}

/**
 * Redact sensitive URL components before audit logging.
 */
function sanitizeUrlForLog(rawUrl, baseUrl) {
  const source = String(rawUrl || '');

  try {
    const parsed = new URL(source, baseUrl);

    if (parsed.protocol === 'data:') {
      return 'data:[local resource omitted]';
    }

    if (parsed.protocol === 'blob:') {
      return 'blob:[local resource]';
    }

    if (parsed.username || parsed.password) {
      parsed.username = '[REDACTED]';
      parsed.password = '[REDACTED]';
    }

    for (const key of [...parsed.searchParams.keys()]) {
      if (SENSITIVE_QUERY_KEYS.test(key)) {
        parsed.searchParams.set(key, '[REDACTED]');
      }
    }

    return parsed.toString().slice(0, 2000);
  } catch {
    // Do not log an unparseable URL because it may contain a secret.
    return '[unparseable URL omitted]';
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
      this.auditLog.length = 250;
    }

    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Audit UI errors must not affect request policy.
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
        ? 'External page-level requests are denied by lockdown policy.'
        : 'Approved read-only external page requests are permitted.'
    });
  }

  /**
   * Evaluate a request against the firewall policy.
   *
   * @param {string|URL|Request} url
   * @param {string} [method='GET']
   * @param {*} [body=null]
   * @param {object} [options]
   */
  inspectRequest(
    url,
    method = 'GET',
    body = null,
    options = {}
  ) {
    const normalizedMethod = normalizeMethod(method);
    const rawUrl = String(
      url && typeof url.url === 'string'
        ? url.url
        : url || ''
    );

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

    // 1. Only read-only methods are permitted.
    if (!ALLOWED_METHODS.has(normalizedMethod)) {
      return decide(
        false,
        'BLOCKED_METHOD',
        `Outbound ${normalizedMethod} requests are not permitted.`
      );
    }

    // 2. Reject supplied request bodies.
    if (body !== null && body !== undefined) {
      return decide(
        false,
        'BLOCKED_PAYLOAD',
        'Requests carrying a body are not permitted.'
      );
    }

    // 3. Validate optional Fetch request controls.
    if (options.credentials === 'include' && options.external === true) {
      return decide(
        false,
        'BLOCKED_CREDENTIALS',
        'Credential-bearing cross-origin requests are not permitted.'
      );
    }

    if (options.mode === 'no-cors' && options.external === true) {
      return decide(
        false,
        'BLOCKED_NO_CORS',
        'Opaque no-cors external requests are not permitted.'
      );
    }

    // 4. Parse and normalize the destination.
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

    // 5. Reject credentials embedded in the URL.
    if (parsedUrl.username || parsedUrl.password) {
      return decide(
        false,
        'BLOCKED_CREDENTIAL_URL',
        'URLs containing embedded credentials are not permitted.'
      );
    }

    // 6. Permit local generated resources.
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

    // 7. Permit same-origin application resources.
    if (parsedUrl.origin === this.getOrigin()) {
      return decide(
        true,
        'ALLOWED_SAME_ORIGIN',
        'Same-origin application resource.'
      );
    }

    // 8. Strict lockdown blocks external page-level requests.
    if (this.airGapLockdown) {
      return decide(
        false,
        'BLOCKED_AIRGAP',
        'External traffic is disabled by the page-level lockdown policy.'
      );
    }

    // 9. All external requests must use HTTPS.
    if (parsedUrl.protocol !== 'https:') {
      return decide(
        false,
        'BLOCKED_PROTOCOL',
        'External requests must use HTTPS.'
      );
    }

    // 10. Exact hostname matching prevents suffix spoofing.
    const hostname = parsedUrl.hostname.toLowerCase();

    if (!ALLOWED_MODEL_HOSTS.includes(hostname)) {
      return decide(
        false,
        'BLOCKED_UNAPPROVED_HOST',
        'External hostname is not on the approved model/library list.'
      );
    }

    // 11. Only the standard HTTPS port is accepted.
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
   * Install supported page-level request interceptors.
   */
  install(targetGlobal = globalThis) {
    if (this.installed || !targetGlobal) {
      return this;
    }

    this.targetGlobal = targetGlobal;
    this.installErrors = [];

    const firewall = this;

    // ----------------------------------------------------------
    // fetch()
    // ----------------------------------------------------------

    if (typeof targetGlobal.fetch === 'function') {
      this.originalFetch = targetGlobal.fetch;

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

          let destinationOrigin = null;

          try {
            destinationOrigin = new URL(
              requestUrl,
              firewall.getBaseUrl()
            ).origin;
          } catch {
            // inspectRequest will report the invalid URL.
          }

          const isExternal =
            destinationOrigin !== null &&
            destinationOrigin !== firewall.getOrigin() &&
            destinationOrigin !== 'null';

          const verdict = firewall.inspectRequest(
            requestUrl,
            requestMethod,
            requestBody,
            {
              credentials:
                options.credentials ||
                (input && typeof input === 'object'
                  ? input.credentials
                  : undefined),
              mode:
                options.mode ||
                (input && typeof input === 'object'
                  ? input.mode
                  : undefined),
              external: isExternal
            }
          );

          if (!verdict.allowed) {
            throw new Error(
              `[LocalVault Firewall] ${verdict.reason}`
            );
          }

          return firewall.originalFetch.call(
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

    if (
      typeof targetGlobal.XMLHttpRequest === 'function' &&
      targetGlobal.XMLHttpRequest.prototype
    ) {
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

          return firewall.originalXhrSend.call(this, body);
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

          // Never forward the beacon payload.
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
        : 'Available page-level request interceptors installed.'
    });

    return this;
  }

  /**
   * Restore original browser methods.
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

    this.originalFetch = null;
    this.originalXhrOpen = null;
    this.originalXhrSend = null;
    this.originalSendBeacon = null;
  }

  /**
   * Summarize the retained audit events.
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
