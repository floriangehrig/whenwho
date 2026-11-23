// Service worker: only for chat notifications (Web Push). No caching, no offline mode.
// A push carries { kind, title, name, body, url, tag, poll, at }, encrypted by the Worker (pushChat).
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

const pollOf = (u) => { try { return new URL(u).searchParams.get('p'); } catch (e) { return null; } };

self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = { title: 'when-who', body: e.data ? e.data.text() : '' }; }
  e.waitUntil((async () => {
    if (d.kind === 'chat' && d.poll) {
      const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      const here = wins.filter((w) => pollOf(w.url) === d.poll);
      here.forEach((w) => w.postMessage({ type: 'chat', poll: d.poll }));
      // Someone is looking at this poll right now: the page shows the message itself.
      if (here.some((w) => w.focused && w.visibilityState === 'visible')) return;
    }
    await self.registration.showNotification(d.title || 'when-who', {
      body: d.name ? d.name + ': ' + (d.body || '') : d.body || '',
      tag: d.tag || undefined, renotify: !!d.tag, icon: '/apple-touch-icon.png',
      timestamp: d.at ? Date.parse(d.at) : Date.now(), data: { url: d.url || '/', poll: d.poll || null },
    });
  })());
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const { url, poll } = e.notification.data || {};
  const target = new URL(url || '/', self.location.origin).href;
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const w = poll ? wins.find((x) => pollOf(x.url) === poll) : null;
    if (w) { await w.focus(); w.postMessage({ type: 'openchat', poll }); return; }
    await self.clients.openWindow(target);
  })());
});

// The browser replaced the subscription (expired keys): subscribe again and tell the server.
self.addEventListener('pushsubscriptionchange', (e) => {
  e.waitUntil((async () => {
    const old = e.oldSubscription;
    let sub = e.newSubscription;
    if (!sub) {
      const cfg = await fetch('/api/config').then((r) => r.json()).catch(() => ({}));
      if (!cfg.push) return;
      const k = cfg.push.replace(/-/g, '+').replace(/_/g, '/');
      const key = Uint8Array.from(atob(k + '==='.slice((k.length + 3) % 4)), (c) => c.charCodeAt(0));
      sub = await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
    }
    const j = sub.toJSON();
    await fetch('/api/me/push', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ endpoint: j.endpoint, keys: j.keys }) });
    if (old && old.endpoint !== j.endpoint)
      await fetch('/api/me/push', { method: 'DELETE', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ endpoint: old.endpoint }) });
  })());
});
