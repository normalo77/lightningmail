import { defineConfig } from 'vite';
import fs from 'node:fs';
import path from 'node:path';

const proxy = {
  '/relay-a': { target: 'http://127.0.0.1:8443', changeOrigin: true, rewrite: (p: string) => p.replace(/^\/relay-a/, '') },
  '/relay-b': { target: 'http://127.0.0.1:9443', changeOrigin: true, rewrite: (p: string) => p.replace(/^\/relay-b/, '') },
};

// Etappe 6: WebAuthn braucht einen Secure Context → HTTPS, sobald Zertifikate
// in client/app/tls/ liegen (openssl/mkcert). Ohne Zertifikate: HTTP wie bisher.
// shortcut: self-signed for LAN dev; real domain + Let's Encrypt on a production relay.
const tlsDir = path.resolve(process.cwd(), 'tls');
const tls = fs.existsSync(path.join(tlsDir, 'cert.pem'))
  ? { key: fs.readFileSync(path.join(tlsDir, 'key.pem')), cert: fs.readFileSync(path.join(tlsDir, 'cert.pem')) }
  : undefined;

export default defineConfig({
  base: './',
  server: { host: '0.0.0.0', port: 5173, proxy, https: tls },
  preview: { host: '0.0.0.0', port: 5173, proxy, https: tls },
});
