import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: { sourcemap: false }, // no source maps in the production build
  server: {
    port: 5173,
    strictPort: true,
    // Dev only: forward API calls to the HTTPS backend (self-signed cert, hence secure: false).
    proxy: { '/api': { target: 'https://localhost:3443', secure: false } },
  },
});
