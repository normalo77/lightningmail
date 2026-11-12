import { defineConfig } from 'vite';

const proxy = {
  '/relay-a': { target: 'http://127.0.0.1:8443', changeOrigin: true, rewrite: (p: string) => p.replace(/^\/relay-a/, '') },
  '/relay-b': { target: 'http://127.0.0.1:9443', changeOrigin: true, rewrite: (p: string) => p.replace(/^\/relay-b/, '') },
};

export default defineConfig({
  base: './',
  server: { host: '0.0.0.0', port: 5173, proxy },
  preview: { host: '0.0.0.0', port: 5173, proxy },
});
