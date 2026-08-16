/**
 * Capacitor production build config.
 * Usage: vite build --config vite.config.capacitor.ts
 *
 * Key differences from the dev config:
 *  - base: './'  → relative asset paths required by Android WebView
 *  - No dev-server, no Replit plugins, no port requirements
 *  - Output dir: dist  (Capacitor reads this via `webDir` in capacitor.config.ts)
 */
import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Inline assets ≤ 4 KB so the WebView doesn't need to resolve extra requests
    assetsInlineLimit: 4096,
    rollupOptions: {
      output: {
        // Stable chunk names make Capacitor caching predictable
        manualChunks: {
          react: ['react', 'react-dom'],
          ui: ['framer-motion', 'lucide-react'],
        },
      },
    },
  },
});
