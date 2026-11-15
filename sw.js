// CFA L1 페이스메이커 알림용 서비스 워커
// 서버는 빈 알림 신호만 보내고, 여기서 /api/push/msg 로 오늘 문구를 받아 보여줍니다.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
async function endpointHash(ep) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('push:' + ep));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}
self.addEventListener('push', e => {
  e.waitUntil((async () => {
    let msg = { title: 'CFA 페이스메이커', body: '5분만 시작해 볼까요? 시작이 제일 어려워요 🙂' };
    try {
      const sub = await self.registration.pushManager.getSubscription();
      if (sub) {
        const r = await fetch('/api/push/msg?h=' + await endpointHash(sub.endpoint), { cache: 'no-store' });
        if (r.ok) msg = await r.json();
      }
    } catch (_) {}
    await self.registration.showNotification(msg.title, { body: msg.body, icon: '/icon-192.png', badge: '/icon-192.png', tag: 'cfa-daily', renotify: true, data: { url: '/#today' } });
  })());
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of wins) { if ('focus' in c) { await c.focus(); c.postMessage({ go: 'today' }); return; } }
    await self.clients.openWindow('/#today');
  })());
});
