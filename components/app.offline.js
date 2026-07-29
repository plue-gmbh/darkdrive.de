//
// app.offline.js — connectivity and service worker for Darkdrive
//
//   Online/offline:    toggles #offline-notice banner on connectivity change
//   Service worker:    registers /sw for PWA offline caching
//   Reconnect:         auto-reloads the offline page when connection returns
//   Share notices:     share_failed messages and pending shared-file count on
//                      pages without the upload input (login page, detail view).
//                      A share that outgrew device storage reports how many of
//                      the batch survived, since those still upload normally.
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

  function shareNotice(text) {
    var host = document.querySelector('.login-container') || document.querySelector('main');
    if (!host) return;
    var note = document.createElement('p');
    note.className = 'share-notice';
    note.textContent = text;
    host.insertBefore(note, host.firstChild);
  }

  var shareParams = new URLSearchParams(location.search);
  if (shareParams.has('shared') || shareParams.has('share_failed')) {
    history.replaceState(null, '', location.pathname);
  }
  var shareFailed = shareParams.get('share_failed');
  if (shareFailed === 'nosw') {
    shareNotice('Sharing needs the installed app — nothing was uploaded.');
  } else if (shareFailed !== null) {
    var saved = parseInt(shareParams.get('saved'), 10) || 0;
    var total = parseInt(shareParams.get('of'), 10) || 0;
    var why = shareFailed === 'QuotaExceededError'
      ? 'this device ran out of space for them'
      : 'this device could not store them (' + shareFailed + ')';
    if (saved > 0 && total > saved) {
      shareNotice(saved + ' of ' + total + ' shared files were saved — ' + why +
        '. Upload these, then share the rest in smaller batches.');
    } else {
      shareNotice('Shared files could not be saved — ' + why + '. Try sharing fewer at a time.');
    }
  }

  if (!document.getElementById('uploads') && window.caches) {
    caches.has('darkdrive-shared').then(function (exists) {
      return exists ? caches.open('darkdrive-shared') : null;
    }).then(function (cache) {
      if (!cache) return;
      return cache.keys().then(function (keys) {
        if (keys.length === 0) return;
        var loggedOut = !!document.querySelector('.login-container');
        var hint = loggedOut ? 'log in to upload.' : 'open All Files to upload.';
        shareNotice(keys.length + ' shared file' + (keys.length !== 1 ? 's' : '') + ' waiting — ' + hint);
      });
    }).catch(function () {});
  }
})();
