/* sw.js — Painel Valle. Casca do app em cache (abre rápido, funciona sem rede);
   dados/ sempre pela rede primeiro, cache só como reserva. */
const CASCA = 'painel-valle-casca-v1';
const ARQUIVOS = ['./', './index.html', './cripto.js', './manifest.webmanifest'];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CASCA).then((c) => c.addAll(ARQUIVOS)).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CASCA).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.pathname.includes('/dados/')) {
    e.respondWith(fetch(e.request).then((r) => { const cp = r.clone(); caches.open(CASCA).then((c) => c.put(e.request, cp)); return r; }).catch(() => caches.match(e.request)));
  } else {
    e.respondWith(caches.match(e.request).then((r) => r || fetch(e.request)));
  }
});
