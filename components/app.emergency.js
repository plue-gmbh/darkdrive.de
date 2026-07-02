//
// app.emergency.js — emergency password change controller for Darkdrive
//
//   Key derivation:  derives old + new auth keys via PBKDF2 (Web Crypto)
//   Submission:      POSTs old/new passwords and auth keys as JSON with CSRF token
//   Streaming UI:    reads chunked response via ReadableStream, shows step/progress/counter
//   Steps:           verify → re-encrypt → delete thumbnails → rename → update password
//   Error handling:  server errors displayed in overlay, network errors caught by promise chain
//
(function () {
  var form    = document.getElementById('emergency-form');
  var overlay = document.getElementById('emergency-overlay');
  var title   = document.getElementById('emergency-title');
  var detail  = document.getElementById('emergency-detail');
  var counter = document.getElementById('emergency-counter');
  var okBtn   = document.getElementById('emergency-ok');

  if (!form || !overlay) return;

  var steps = {
    verify:   'Verifying files',
    encrypt:  'Re-encrypting files',
    thumbs:   'Deleting thumbnails',
    rename:   'Renaming files',
    password: 'Updating password'
  };

  okBtn.addEventListener('click', function () { overlay.classList.add('overlay-hidden'); });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (!confirm(form.dataset.confirm)) return;

    var oldPw = form.old_password.value;
    var newPw = form.new_password.value;

    title.textContent = 'Deriving keys...';
    title.style.color = '';
    detail.textContent = '';
    detail.style.color = 'var(--text-dim)';
    counter.textContent = '';
    okBtn.style.display = 'none';
    overlay.classList.remove('overlay-hidden');

    Promise.all([deriveAuthKey(oldPw), deriveAuthKey(newPw)]).then(function(keys) {
      var oldAuthKey = keys[0];
      var newAuthKey = keys[1];

      title.textContent = 'Starting...';

      return fetch(form.dataset.url, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          old_password: oldPw,
          new_password: newPw,
          old_auth_key: oldAuthKey,
          new_auth_key: newAuthKey,
          csrf_token: form.csrf_token.value
        })
      });
    })
    .then(function (response) {
      var reader = response.body.getReader();
      var decoder = new TextDecoder();
      var buf = '';

      function read() {
        return reader.read().then(function (result) {
          buf += decoder.decode(result.value || new Uint8Array(), { stream: !result.done });
          var lines = buf.split('\n');
          buf = lines.pop();
          for (var i = 0; i < lines.length; i++) {
            if (!lines[i]) continue;
            try { var msg = JSON.parse(lines[i]); } catch(e) { continue; }
            if (msg.ok === true) {
              title.textContent = form.dataset.success;
              title.style.color = 'var(--success)';
              detail.textContent = form.dataset.warning;
              detail.style.color = 'var(--danger)';
              counter.textContent = form.dataset.redirect;
              setTimeout(function () { location.href = '/'; }, 4000);
              return;
            }
            if (msg.ok === false) {
              title.textContent = 'Error';
              title.style.color = 'var(--danger)';
              detail.textContent = msg.error;
              detail.style.color = '';
              counter.textContent = '';
              okBtn.style.display = '';
              return;
            }
            title.textContent = steps[msg.step] || msg.step;
            detail.textContent = msg.detail;
            counter.textContent = msg.total ? msg.i + ' / ' + msg.total : '';
          }
          if (!result.done) return read();
        });
      }
      return read();
    })
    .catch(function (err) {
      title.textContent = 'Error';
      title.style.color = 'var(--danger)';
      detail.textContent = err.message;
      detail.style.color = '';
      counter.textContent = '';
      okBtn.style.display = '';
    });
  });
})();
