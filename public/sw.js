// Service worker: only for notifications (Web Push): chat messages and what happens in polls (answers, votes, meetings, questions, rounds). No caching, no offline mode.
// A push carries { kind, title, name, body, url, tag, poll, at, av?, icon?, badge? }, encrypted by the Worker (notifyEvent):
// av = the sender's emoji avatar, icon = signed link to their picture, badge = my unread chat messages (app icon badge).
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

const pollOf = (u) => { try { return new URL(u).searchParams.get('p'); } catch (e) { return null; } };

self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = { title: 'when-who', body: e.data ? e.data.text() : '' }; }
  e.waitUntil((async () => {
    if (typeof d.badge === 'number' && self.navigator.setAppBadge) {
      try { await (d.badge ? self.navigator.setAppBadge(d.badge) : self.navigator.clearAppBadge()); } catch (x) {}
    }
    if (d.poll && d.kind !== 'test') {
      const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      const here = wins.filter((w) => pollOf(w.url) === d.poll);
      here.forEach((w) => w.postMessage(d.kind === 'chat' ? { type: 'chat', poll: d.poll } : { type: 'event', poll: d.poll, kind: d.kind }));
      // Someone is looking at this poll right now: the page shows the message / answer itself.
      if (here.some((w) => w.focused && w.visibilityState === 'visible')) return;
    }
    const who = d.name ? (d.av ? d.av + ' ' : '') + d.name : '';
    await self.registration.showNotification(d.title || 'when-who', {
      body: who ? who + ': ' + (d.body || '') : d.body || '',
      tag: d.tag || undefined, renotify: !!d.tag, icon: d.icon || '/apple-touch-icon.png', badge: '/apple-touch-icon.png',
      timestamp: d.at ? Date.parse(d.at) : Date.now(), data: { url: d.url || '/', poll: d.poll || null, kind: d.kind || '' },
    });
  })());
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const { url, poll, kind } = e.notification.data || {};
  const target = new URL(url || '/', self.location.origin).href;
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const w = poll ? wins.find((x) => pollOf(x.url) === poll) : null;
    const tab = (() => { try { return new URL(target).searchParams.get('tab'); } catch (x) { return null; } })();
    // Already on that poll: open the chat / the tab there.
    if (w) { await w.focus(); w.postMessage(!kind || kind === 'chat' ? { type: 'openchat', poll } : { type: 'opentab', poll, tab }); return; }
    // The app is open elsewhere (an installed iPhone app only gets focused by openWindow): send that window to the page.
    const any = wins.find((x) => x.focused) || wins[0];
    if (any) {
      try { const n = await any.navigate(target); await (n || any).focus(); return; } catch (x) {}
      try { await any.focus(); any.postMessage({ type: 'go', url: target }); return; } catch (x) {}
    }
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
