//
// app.login.js — authentication controller for Darkdrive
//
//   Key derivation:  PBKDF2 (100k iterations, SHA-256) via Web Crypto API
//   Setup form:      derives auth_key from server-generated passphrase, submits with password
//   Login form:      derives auth_key from user input, submits with password for enc_key cookie
//   Split-key:       auth_key for verification, password for encryption — never stored together
//
async function deriveAuthKey(password) {
  if (!crypto.subtle) throw new Error('Secure context required (HTTPS)');
  var enc = new TextEncoder();
  var keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt:enc.encode('darkdrive-auth-v1'), iterations:100000, hash:'SHA-256'}, keyMaterial, 256);
  return Array.from(new Uint8Array(bits)).map(function(b){return b.toString(16).padStart(2,'0')}).join('');
}

(function () {
  var setupForm = document.getElementById('setup-form');
  if (setupForm) {
    var passphrase = setupForm.dataset.passphrase;
    setupForm.addEventListener('submit', function (e) {
      if (setupForm.querySelector('[name=auth_key]').value) return;
      e.preventDefault();
      if (!confirm('Have you saved your password? It cannot be recovered.')) return;
      deriveAuthKey(passphrase).then(function (ak) {
        setupForm.querySelector('[name=auth_key]').value = ak;
        setupForm.querySelector('[name=password]').value = passphrase;
        setupForm.submit();
      }).catch(function (err) {
        alert(err.message || 'Key derivation failed. HTTPS required.');
      });
    });
  }

  var loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', function (e) {
      if (loginForm.querySelector('[name=auth_key]').value) return;
      e.preventDefault();
      var pw = document.getElementById('password-input').value;
      deriveAuthKey(pw).then(function (ak) {
        loginForm.querySelector('[name=auth_key]').value = ak;
        loginForm.querySelector('[name=password]').value = pw;
        loginForm.submit();
      }).catch(function (err) {
        var p = loginForm.querySelector('.login-lockout');
        if (!p) { p = document.createElement('p'); p.className = 'login-lockout'; loginForm.parentNode.insertBefore(p, loginForm); }
        p.textContent = err.message || 'Key derivation failed. HTTPS required.';
      });
    });
  }
})();
