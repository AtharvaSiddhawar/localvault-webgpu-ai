import { defineConfig } from 'vite';

const isolationHeaders = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'credentialless',
  'Cross-Origin-Resource-Policy': 'cross-origin'
};

export default defineConfig({
  // Relative asset paths keep the build compatible with GitHub project Pages.
  base: './',
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    headers: isolationHeaders
  },
  preview: {
    host: '0.0.0.0',
    port: 4173,
    strictPort: true,
    headers: isolationHeaders
  },
  worker: {
    format: 'es'
  },
  build: {
    target: 'es2022',
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    emptyOutDir: true
  },
  optimizeDeps: {
    esbuildOptions: {
      target: 'es2022'
    }
  }
});
