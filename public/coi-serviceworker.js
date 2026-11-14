/* LocalVault cross-origin isolation helper for static hosting. */
(function registerIsolationHelper() {
  if (typeof window === 'undefined') {
    self.addEventListener('install', (event) => {
      event.waitUntil(self.skipWaiting());
    });

    self.addEventListener('activate', (event) => {
      event.waitUntil(self.clients.claim());
    });

    self.addEventListener('fetch', (event) => {
      const request = event.request;
      if (request.method !== 'GET' || request.cache === 'only-if-cached' && request.mode !== 'same-origin') {
        return;
      }

      event.respondWith((async () => {
        const response = await fetch(request);
        // Opaque responses cannot be reconstructed with modified headers.
        if (response.type === 'opaque' || response.status === 0 || response.status === 204 || response.status === 304) {
          return response;
        }

        const headers = new Headers(response.headers);
        headers.set('Cross-Origin-Opener-Policy', 'same-origin');
        headers.set('Cross-Origin-Embedder-Policy', 'credentialless');
        headers.set('Cross-Origin-Resource-Policy', 'cross-origin');

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers
        });
      })().catch((error) => {
        console.error('[LocalVault COI] Fetch failed:', error);
        throw error;
      }));
    });
    return;
  }

  if (window.crossOriginIsolated || !window.isSecureContext || !('serviceWorker' in navigator)) {
    return;
  }

  const reloadKey = 'localvault_coi_reload_v1';
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (sessionStorage.getItem(reloadKey) === '1') return;
    sessionStorage.setItem(reloadKey, '1');
    window.location.reload();
  }, { once: true });
  navigator.serviceWorker.register(new URL('./coi-serviceworker.js', document.baseURI), { scope: './' })
    .catch((error) => {
      console.warn('[LocalVault COI] Service worker not available:', error?.message || error);
    });
})();
