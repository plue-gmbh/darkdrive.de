//
// app.offline.js — connectivity and service worker for Darkdrive
//
//   Online/offline:    toggles #offline-notice banner on connectivity change
//   Service worker:    registers /sw for PWA offline caching
//   Reconnect:         auto-reloads the offline page when connection returns
//
(function () {
  var el = document.getElementById('offline-notice');
  if (el) {
    function u() { el.style.display = navigator.onLine ? 'none' : ''; }
    u();
    window.addEventListener('online', u);
    window.addEventListener('offline', u);
  }
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw').catch(function(){});
  }
  if (document.getElementById('offline-retry')) {
    window.addEventListener('online', function () { location.href = '/'; });
  }
})();
