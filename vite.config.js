import { defineConfig } from 'vite';

const COOP_COEP_HEADERS = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'credentialless',
  'Cross-Origin-Resource-Policy': 'cross-origin'
};

export default defineConfig({
  base: './',
  server: {
    port: 5173,
    headers: COOP_COEP_HEADERS
  },
  preview: {
    port: 4173,
    headers: COOP_COEP_HEADERS
  },
  worker: {
    format: 'es'
  },
  build: {
    target: 'esnext',
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    rollupOptions: {
      external: []
    }
  },
  optimizeDeps: {
    esbuildOptions: {
      target: 'esnext'
    }
  }
});
