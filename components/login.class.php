<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Login — authentication and brute-force protection for Darkdrive
//
//   Password:  split-key (PBKDF2 auth_key) or legacy bcrypt, auto-migration
//   Lockout:   session-based + IP-based rate limiting (5 attempts / 5 min)
//   Session:   regenerate ID on login, track active sessions, destroy others
//   Setup:     initial password creation via Web Crypto PBKDF2 in browser
//

class Login {

  private string $hash;
  private static int $maxAttempts = 5;
  private static int $lockoutSeconds = 300;

  private static ?self $instance = null;

  public function __construct(string $hash) {
    $this->hash = $hash;
    self::$instance = $this;
  }

  public static function init(string $hash): void {
    new self($hash);
  }

  public static function is_splitkey(): bool {
    return str_starts_with(self::$instance->hash, 'SPLITKEY:');
  }

  public static function handle(): void {
    if (!self::user() && $_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['auth_key'])) {
      if (!Base::csrf_verify()) return;
      if (self::is_locked_out()) return;
      if (strlen($_POST['auth_key']) > 512 || strlen($_POST['password'] ?? '') > 512) return;

      $authKey = $_POST['auth_key'];
      $verified = false;

      if (self::is_splitkey()) {
        $storedHash = substr(self::$instance->hash, 9);
        $verified = password_verify($authKey, $storedHash);
      } else {
        $rawPassword = $_POST['password'] ?? '';
        if ($rawPassword !== '' && password_verify($rawPassword, self::$instance->hash)) {
          $verified = true;
          $passwordFile = Base::data_path('.password');
          $newHash = 'SPLITKEY:' . password_hash($authKey, PASSWORD_DEFAULT);
          file_put_contents($passwordFile, $newHash, LOCK_EX);
          self::$instance->hash = $newHash;
        }
      }

      if ($verified) {
        $password = $_POST['password'] ?? '';
        $_POST['password'] = '';
        $_POST['auth_key'] = '';
        if ($password !== '') Base::set_enc_cookie($password);
        $_SESSION['user'] = true;
        $_SESSION['login_attempts'] = 0;
        unset($_SESSION['csrf_token']);
        session_regenerate_id(true);
        $_SESSION['just_logged_in'] = true;
        session_write_close();
        Base::memzero($authKey);
        Base::memzero($password);
        Base::audit('login_success');
      } else {
        $_POST['password'] = '';
        $_POST['auth_key'] = '';
        $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;
        $_SESSION['last_attempt'] = time();
        $_SESSION['login_failed'] = true;
        self::record_ip_attempt();
        session_write_close();
        Base::memzero($authKey);
        if (isset($rawPassword)) Base::memzero($rawPassword);
        Base::audit('login_failed');
      }
      Base::redirect();
    }
    elseif (self::user() && isset($_GET['logout']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
      if (!Base::csrf_verify()) return;
      Base::audit('logout');
      Base::untrack_session();
      $_SESSION = [];
      session_regenerate_id(true);
      Base::clear_enc_cookie();
      header('Clear-Site-Data: "cache"');
      Base::redirect();
    }
    elseif (self::user() && isset($_GET['destroy_sessions']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
      if (!Base::csrf_verify()) return;
      Base::destroy_other_sessions();
      Base::audit('destroy_other_sessions');
      Base::redirect('/?route=status');
    }
  }

  public static function user(): bool {
    return !empty($_SESSION['user']);
  }

  private static function is_locked_out(): bool {
    $attempts    = $_SESSION['login_attempts'] ?? 0;
    $lastAttempt = $_SESSION['last_attempt']   ?? 0;
    if ($attempts >= self::$maxAttempts && (time() - $lastAttempt) < self::$lockoutSeconds) {
      return true;
    }
    if ($attempts >= self::$maxAttempts && (time() - $lastAttempt) >= self::$lockoutSeconds) {
      $_SESSION['login_attempts'] = 0;
    }
    return self::ip_attempts() >= self::$maxAttempts;
  }

  private static function client_ip(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (defined('DARKDRIVE_TRUSTED_PROXIES') && !empty(DARKDRIVE_TRUSTED_PROXIES)
        && in_array($ip, DARKDRIVE_TRUSTED_PROXIES, true)) {
      $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
      if ($forwarded !== '') {
        $candidate = trim(explode(',', $forwarded)[0]);
        if (filter_var($candidate, FILTER_VALIDATE_IP)) $ip = $candidate;
      }
    }
    return $ip;
  }

  private static function ip_hash(): string {
    return hash_hmac('sha256', self::client_ip(), Base::instance_key());
  }

  private static function ip_attempts(): int {
    $logFile = Base::data_path('.login_rate');
    $ipKey   = self::ip_hash();
    $cutoff  = time() - self::$lockoutSeconds;
    $fh = fopen($logFile, 'c+');
    if (!$fh) return self::$maxAttempts;
    if (!flock($fh, LOCK_SH)) { fclose($fh); return self::$maxAttempts; }
    $count = 0;
    foreach (explode("\n", trim(stream_get_contents($fh) ?: '')) as $line) {
      [$ts, $key] = array_pad(explode(':', $line, 2), 2, '');
      if ((int)$ts >= $cutoff && $key === $ipKey) $count++;
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $count;
  }

  private static function record_ip_attempt(): void {
    $logFile = Base::data_path('.login_rate');
    $fh = fopen($logFile, 'c+');
    if (!$fh) return;
    if (!flock($fh, LOCK_EX)) { fclose($fh); return; }
    $ipKey   = self::ip_hash();
    $cutoff  = time() - self::$lockoutSeconds;
    $entries = [];
    foreach (explode("\n", trim(stream_get_contents($fh) ?: '')) as $line) {
      [$ts, $key] = array_pad(explode(':', $line, 2), 2, '');
      if ((int)$ts >= $cutoff && $key) $entries[] = $line;
    }
    $entries[] = time() . ':' . $ipKey;
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, implode("\n", $entries) . "\n");
    flock($fh, LOCK_UN);
    fclose($fh);
  }

  public static function setup(): void {
    $passphrase = Base::generate_passphrase();
    ?>
<?php App::head() ?>
<body>
  <div class="row">
    <span style="flex:1"></span>
    <label><?= htmlspecialchars(DARKDRIVE_TITLE) ?><?php if (App::$appVersion): ?> <span style="color:var(--text-dim);font-weight:normal">v<?= App::$appVersion ?></span><?php endif ?></label>
    <span style="flex:1"></span>
  </div>
  <div class="login-container">

    <h1 class="login-title">Your Private Cloud</h1>
    <p>
      Your password has been generated. <br>
      Write it down — it cannot be recovered.
    </p>
    <code><?= htmlspecialchars($passphrase) ?></code>
    <div class="login-actions">
      <form method="post" action="/" id="setup-form" data-passphrase="<?= htmlspecialchars($passphrase) ?>">
        <?php Base::csrf_field() ?>
        <input type="hidden" name="auth_key" id="setup-auth-key" value="">
        <input type="hidden" name="password" id="setup-password" value="">
        <button type="submit" class="login-button">I've saved it</button>
      </form>
    </div>
  </div>
  <script src="/components/app.login.js?v=<?= filemtime(__DIR__ . '/app.login.js') ?>"></script>
</body>
</html><?php
    exit;
  }

  public static function view(): void {
    $locked   = self::is_locked_out();
    $failed   = !empty($_SESSION['login_failed']);
    if ($failed) unset($_SESSION['login_failed']);
    ?>
      <div class="login-container">
        <h1 class="login-title">Your Private Cloud</h1>
        <?php if ($locked): ?>
          <p class="login-lockout">Too many attempts. Try again later.</p>
        <?php else: ?>
          <?php if ($failed): ?>
            <p class="login-lockout">Invalid password.</p>
          <?php endif ?>
          <form method="post" action="/" class="login" id="login-form">
            <?php Base::csrf_field() ?>
            <input type="hidden" name="auth_key" id="login-auth-key" value="">
            <input type="hidden" name="password" id="login-password" value="">
            <input type="text" name="username" autocomplete="username" value="<?= htmlspecialchars(DARKDRIVE_TITLE) ?>" style="display:none">
            <input type="password" id="password-input" required="" placeholder="Your Key" autofocus autocomplete="current-password">
            <button type="submit" class="login-button">Decrypt</button>
          </form>
          <script src="/components/app.login.js?v=<?= filemtime(__DIR__ . '/app.login.js') ?>"></script>
        <?php endif ?>
        <?php if (defined('DARKDRIVE_DEMO_PASSWORD')): ?>
          <p style="color:var(--text-dim)">Demo Key <span style="user-select:all;color:var(--text)"><?= htmlspecialchars(DARKDRIVE_DEMO_PASSWORD) ?></span></p>
        <?php endif ?>
      </div>
    <?php
  }

}