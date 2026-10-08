import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // maplibre-gl is a single ~1 MB vendor module that cannot be split
    // further. It already lives in its own second-level lazy chunk
    // (components/map/maplibre-bridge.js) that raster-only deployments never
    // download, so the warning would be a permanent false positive. App
    // chunks are still reviewed against the baseline in ARCHITECTURE.md.
    chunkSizeWarningLimit: 1100,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:3000',
      '/ws': {
        target: 'ws://localhost:3000',
        ws: true,
      },
    },
  },
});
