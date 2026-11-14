/*! coi-serviceworker v2.0.0 - LocalVault AI Cross-Origin Isolation Service Worker */
/* Automatically injects COOP/COEP headers on static hosts (GitHub Pages) so SharedArrayBuffer & WebGPU/WASM run at full speed */

if (typeof window === 'undefined') {
  self.addEventListener('install', () => self.skipWaiting());
  self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

  self.addEventListener('fetch', (event) => {
    const request = event.request;
    if (request.cache === 'only-if-cached' && request.mode !== 'same-origin') {
      return;
    }

    const fetchedRequest =
      request.mode === 'no-cors'
        ? new Request(request, { credentials: 'omit' })
        : request;

    event.respondWith(
      fetch(fetchedRequest)
        .then((response) => {
          if (response.status === 0) {
            return response;
          }

          const newHeaders = new Headers(response.headers);
          newHeaders.set('Cross-Origin-Embedder-Policy', 'credentialless');
          newHeaders.set('Cross-Origin-Opener-Policy', 'same-origin');
          newHeaders.set('Cross-Origin-Resource-Policy', 'cross-origin');

          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: newHeaders
          });
        })
        .catch((err) => {
          console.error('[COI-SW] Fetch error:', err);
          throw err;
        })
    );
  });
} else {
  (() => {
    if (window.crossOriginIsolated !== false && typeof SharedArrayBuffer !== 'undefined') {
      return;
    }
    if (!window.isSecureContext || !('serviceWorker' in navigator)) {
      return;
    }
    navigator.serviceWorker
      .register(new URL('./coi-serviceworker.js', window.location.href).href)
      .then((registration) => {
        if (registration.active && !navigator.serviceWorker.controller) {
          if (!sessionStorage.getItem('lv_coi_reloaded')) {
            sessionStorage.setItem('lv_coi_reloaded', '1');
            window.location.reload();
          }
        } else if (registration.installing) {
          registration.installing.addEventListener('statechange', (e) => {
            if (e.target.state === 'activated' && !sessionStorage.getItem('lv_coi_reloaded')) {
              sessionStorage.setItem('lv_coi_reloaded', '1');
              window.location.reload();
            }
          });
        }
      })
      .catch((err) => {
        console.warn('[COI-SW] Registration skipped:', err.message);
      });
  })();
}

