/*!
 * Cross-Origin Isolation Service Worker for Static Hosts (GitHub Pages / Netlify / Vercel)
 * Injects Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: credentialless
 * so SharedArrayBuffer, multi-threaded WASM, and WebGPU run at full speed on static hosts.
 */
if (typeof window === 'undefined') {
  self.addEventListener('install', () => self.skipWaiting());
  self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

  self.addEventListener('fetch', (event) => {
    const req = event.request;
    if (req.cache === 'only-if-cached' && req.mode !== 'same-origin') {
      return;
    }

    event.respondWith(
      fetch(req)
        .then((response) => {
          if (response.status === 0) return response;
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
          throw err;
        })
    );
  });
} else {
  (() => {
    if (window.crossOriginIsolated !== false) return;
    if (!window.isSecureContext || !('serviceWorker' in navigator)) return;

    navigator.serviceWorker
      .register(new URL('./coi-serviceworker.js', window.location.href).href)
      .then((registration) => {
        if (registration.active && !navigator.serviceWorker.controller) {
          if (!sessionStorage.getItem('coiReloaded')) {
            sessionStorage.setItem('coiReloaded', 'true');
            window.location.reload();
          }
        } else if (registration.installing) {
          registration.installing.addEventListener('statechange', (e) => {
            if (e.target.state === 'activated' && !sessionStorage.getItem('coiReloaded')) {
              sessionStorage.setItem('coiReloaded', 'true');
              window.location.reload();
            }
          });
        }
      })
      .catch(() => {
        // Non-fatal in restricted environments
      });
  })();
             }
