<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Emergency — password change with full re-encryption for Darkdrive
//
//   Validates old password, then re-encrypts every file and filename with new key.
//   Purges all thumbnails, re-encrypts tag directory references.
//   Streams progress via NDJSON for real-time UI feedback.
//   Rate-limited, CSRF-protected, zeros all key material on completion.
//

class Emergency {

  private static bool $recoveryNeeded = false;

  private static function cleanup_tmp(string $dir): void {
    if (!is_dir($dir)) return;
    foreach (scandir($dir) as $f) {
      if (str_ends_with($f, '.plain.tmp') || str_ends_with($f, '.enc.tmp') || str_ends_with($f, '.verify')) {
        @unlink($dir . '/' . $f);
      }
    }
  }

  private static function emit(string $step, string $detail, int $i = 0, int $total = 0): void {
    echo json_encode(['step' => $step, 'detail' => $detail, 'i' => $i, 'total' => $total]) . "\n";
    if (ob_get_level() > 0) ob_flush();
    flush();
  }

  private static function fail(string $error): never {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    echo json_encode(['ok' => false, 'error' => $error]) . "\n";
    exit;
  }

  public static function handle(): void {
    if (!defined('DARKDRIVE_EMERGENCY_PASSWORD') || !isset($_GET['emergency'])) return;
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;

    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (stripos($contentType, 'application/json') === false) return;

    header('Content-Type: application/x-ndjson');
    header('X-Accel-Buffering: no');
    @set_time_limit(0);
    while (ob_get_level() > 0) ob_end_flush();

    $input = self::validate_input();

    Base::destroy_other_sessions();

    $filesDir  = Base::data_path('files');
    $thumbsDir = Base::data_path('thumbs');

    register_shutdown_function(function() use ($filesDir) { self::cleanup_tmp($filesDir); });
    self::cleanup_tmp($filesDir);

    $localFiles = is_dir($filesDir)
      ? array_values(array_filter(array_diff(scandir($filesDir), ['.', '..']), fn($f) => !str_ends_with($f, '.s3')))
      : [];
    $s3Files = [];
    if (is_dir($filesDir) && S3::is_configured()) {
      foreach (array_diff(scandir($filesDir), ['.', '..']) as $f) {
        if (str_ends_with($f, '.s3')) $s3Files[] = substr($f, 0, -3);
      }
    }
    $allFiles = array_merge($localFiles, $s3Files);

    self::verify_files($filesDir, $localFiles, $input['old_password']);
    self::verify_s3_files($s3Files, $input['old_password']);

    Base::save_emergency_recovery($input['new_password']);
    register_shutdown_function(function() {
      if (!self::$recoveryNeeded) Base::clear_emergency_recovery();
    });

    self::reencrypt_files($filesDir, $localFiles, $input['old_password'], $input['new_password']);
    self::reencrypt_s3_files($s3Files, $input['old_password'], $input['new_password']);
    self::purge_thumbs($thumbsDir);
    self::reencrypt_filenames($filesDir, $allFiles, $input['old_password'], $input['new_password']);

    self::emit('password', '', 0, 0);

    $passwordFile = Base::data_path('.password');
    $newHash = 'SPLITKEY:' . password_hash($input['new_auth_key'], PASSWORD_DEFAULT);
    if (file_put_contents($passwordFile, $newHash) === false) {
      self::fail('Failed to update password file.');
    }
    Base::audit('emergency_password_change', count($allFiles) . ' files re-encrypted');

    Upload::clear_dedupe();
    Base::clear_emergency_recovery();
    self::cleanup_tmp($filesDir);

    Base::memzero($input['old_password']);
    Base::memzero($input['new_password']);
    Crypto::clear_cache();

    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
      $p = session_get_cookie_params();
      setcookie(session_name(), '', 1, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
    if (isset($_COOKIE['enc_key'])) {
      setcookie('enc_key', '', 1, '/', '', !empty($_SERVER['HTTPS']), true);
    }

    echo json_encode(['ok' => true]) . "\n";
    exit;
  }

  private static function validate_input(): array {
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input) self::fail('Invalid request.');

    $csrfToken   = $input['csrf_token']   ?? '';
    $oldAuthKey  = $input['old_auth_key'] ?? '';
    $oldPassword = $input['old_password'] ?? '';
    $newAuthKey  = $input['new_auth_key'] ?? '';
    $newPassword = $input['new_password'] ?? '';

    if (strlen($oldAuthKey) > 512 || strlen($oldPassword) > 512
        || strlen($newAuthKey) > 512 || strlen($newPassword) > 512) {
      self::fail('Invalid input.');
    }

    if (empty($csrfToken) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $csrfToken)) {
      self::fail('Invalid CSRF token.');
    }

    $attempts = $_SESSION['emergency_attempts'] ?? 0;
    $lastAttempt = $_SESSION['emergency_last_attempt'] ?? 0;
    if ($attempts >= 5 && (time() - $lastAttempt) < 300) {
      self::fail('Too many attempts. Try again later.');
    }
    if ($attempts >= 5) {
      $_SESSION['emergency_attempts'] = 0;
    }

    $passwordFile = Base::data_path('.password');
    if (!file_exists($passwordFile)) self::fail('Password file not found.');
    $storedHash = (string)file_get_contents($passwordFile);

    $verified = false;
    if (str_starts_with($storedHash, 'SPLITKEY:')) {
      $verified = !empty($oldAuthKey) && password_verify($oldAuthKey, substr($storedHash, 9));
    } else {
      $verified = !empty($oldPassword) && password_verify($oldPassword, $storedHash);
    }

    if (!$verified) {
      $_SESSION['emergency_attempts'] = ($attempts + 1);
      $_SESSION['emergency_last_attempt'] = time();
      self::fail('Old password is incorrect.');
    }
    $_SESSION['emergency_attempts'] = 0;

    if (empty($newPassword)) {
      self::fail('New password cannot be empty.');
    }

    if (!Base::auth_key_matches($newAuthKey, $newPassword)) {
      self::fail('New key does not match the new password. Nothing was changed.');
    }

    return ['old_password' => $oldPassword, 'new_password' => $newPassword, 'new_auth_key' => $newAuthKey];
  }

  private static function verify_files(string $filesDir, array $files, string $oldPassword): void {
    $total = count($files);
    foreach ($files as $i => $f) {
      $path = $filesDir . '/' . $f;
      if (!is_file($path)) continue;
      self::emit('verify', $f, $i + 1, $total);
      if (!Crypto::verify_decrypt($path, $oldPassword)) {
        self::fail("Verification failed: {$f}");
      }
    }
  }

  private static function reencrypt_files(string $filesDir, array $files, string $oldPassword, string $newPassword): void {
    $total = count($files);
    foreach ($files as $i => $f) {
      $path = $filesDir . '/' . $f;
      if (!is_file($path)) continue;
      self::emit('encrypt', $f, $i + 1, $total);
      $tmpPlain = $path . '.plain.tmp';
      $tmpEnc   = $path . '.enc.tmp';

      if (!Crypto::decrypt_to_path($path, $oldPassword, $tmpPlain)) {
        @unlink($tmpPlain);
        self::fail("Decryption failed: {$f}");
      }
      if (!Crypto::encrypt_stream($tmpPlain, $tmpEnc, $newPassword)) {
        @unlink($tmpPlain); @unlink($tmpEnc);
        self::fail("Re-encryption failed: {$f}");
      }
      @unlink($tmpPlain);
      if (!rename($tmpEnc, $path)) {
        @unlink($tmpEnc);
        self::fail("Rename failed: {$f}");
      }
      self::$recoveryNeeded = true;
    }
  }

  private static function purge_thumbs(string $thumbsDir): void {
    if (!is_dir($thumbsDir)) return;
    $thumbs = array_values(array_diff(scandir($thumbsDir), ['.', '..']));
    $total = count($thumbs);
    foreach ($thumbs as $i => $t) {
      $tp = $thumbsDir . '/' . $t;
      if (!is_file($tp)) continue;
      self::emit('thumbs', $t, $i + 1, $total);
      @unlink($tp);
    }
  }

  private static function verify_s3_files(array $s3Files, string $oldPassword): void {
    $total = count($s3Files);
    foreach ($s3Files as $i => $f) {
      $marker = S3::read_marker($f);
      if ($marker === false) continue;
      self::emit('verify', $f . ' (S3)', $i + 1, $total);
      $tmp = tempnam(sys_get_temp_dir(), 'dd_emrg_v_');
      if ($tmp === false) self::fail("Cannot create temp file for: {$f}");
      if (!S3::download_to_file((string)($marker['key'] ?? $f), $tmp)) {
        @unlink($tmp);
        self::fail("S3 download failed: {$f}");
      }
      $ok = Crypto::verify_decrypt($tmp, $oldPassword);
      @unlink($tmp);
      if (!$ok) self::fail("S3 verification failed: {$f}");
    }
  }

  private static function reencrypt_s3_files(array $s3Files, string $oldPassword, string $newPassword): void {
    $total = count($s3Files);
    foreach ($s3Files as $i => $f) {
      $marker = S3::read_marker($f);
      if ($marker === false) continue;
      $s3Key   = (string)($marker['key'] ?? $f);
      $oldSize = (int)($marker['size'] ?? 0);
      self::emit('encrypt', $f . ' (S3)', $i + 1, $total);

      $tmpEnc   = tempnam(sys_get_temp_dir(), 'dd_emrg_e_');
      $tmpPlain = tempnam(sys_get_temp_dir(), 'dd_emrg_p_');
      $tmpNew   = tempnam(sys_get_temp_dir(), 'dd_emrg_n_');
      if ($tmpEnc === false || $tmpPlain === false || $tmpNew === false) {
        @unlink($tmpEnc); @unlink($tmpPlain); @unlink($tmpNew);
        self::fail("Cannot create temp files for: {$f}");
      }

      if (!S3::download_to_file($s3Key, $tmpEnc)) {
        @unlink($tmpEnc); @unlink($tmpPlain); @unlink($tmpNew);
        self::fail("S3 download failed: {$f}");
      }
      if (!Crypto::decrypt_to_path($tmpEnc, $oldPassword, $tmpPlain)) {
        @unlink($tmpEnc); @unlink($tmpPlain); @unlink($tmpNew);
        self::fail("S3 decryption failed: {$f}");
      }
      @unlink($tmpEnc);
      if (!Crypto::encrypt_stream($tmpPlain, $tmpNew, $newPassword)) {
        @unlink($tmpPlain); @unlink($tmpNew);
        self::fail("S3 re-encryption failed: {$f}");
      }
      @unlink($tmpPlain);
      if (!S3::put_object($s3Key, $tmpNew)) {
        @unlink($tmpNew);
        self::fail("S3 upload failed: {$f}");
      }
      self::$recoveryNeeded = true;

      $newSize = (int)filesize($tmpNew);
      $hdr = file_get_contents($tmpNew, false, null, 0, 39);
      @unlink($tmpNew);
      $saltHex  = ($hdr && strlen($hdr) >= 27) ? bin2hex(substr($hdr, 11, 16)) : '';
      $plainSz  = ($hdr && strlen($hdr) >= 39) ? unpack('J', substr($hdr, 31, 8))[1] : 0;
      S3::write_marker($f, $s3Key, $newSize, $plainSz, true, $saltHex, Crypto::CHUNK_SIZE);
      if ($newSize !== $oldSize) S3::update_s3_storage_bytes($newSize - $oldSize);
    }
  }

  private static function reencrypt_filenames(string $filesDir, array $files, string $oldPassword, string $newPassword): void {
    $tagsDir = Base::data_path('tags');
    $total = count($files);
    foreach ($files as $i => $f) {
      if (!preg_match('/^(\d{8}-\d{6})-(.+)$/', $f, $m)) continue;
      $prefix  = $m[1];
      $encPart = $m[2];

      $plainName = Crypto::decrypt_filename($encPart, $oldPassword);
      if ($plainName === false) self::fail("Filename decryption failed: {$f}");

      $newEncPart  = Crypto::encrypt_filename($plainName, $newPassword);
      $newFilename = $prefix . '-' . $newEncPart;

      if ($newFilename === $f) continue;

      self::emit('rename', $f, $i + 1, $total);

      $markerPath = S3::marker_path($f);
      if (file_exists($markerPath)) {
        $marker = S3::read_marker($f);
        if (!rename($markerPath, S3::marker_path($newFilename))) {
          self::fail("S3 marker rename failed: {$f}");
        }
        if ($marker !== false) {
          S3::write_marker($newFilename, (string)($marker['key'] ?? $f),
            (int)($marker['size'] ?? 0), (int)($marker['plain_size'] ?? 0),
            !empty($marker['chunked']), (string)($marker['salt'] ?? ''),
            (int)($marker['chunk_size'] ?? Crypto::CHUNK_SIZE));
        }
      } elseif (!rename($filesDir . '/' . $f, $filesDir . '/' . $newFilename)) {
        self::fail("Filename rename failed: {$f}");
      }

      if (is_dir($tagsDir)) {
        foreach (glob($tagsDir . '/*/' . $f . '.txt') ?: [] as $tagFile) {
          $tagDir = dirname($tagFile);
          rename($tagFile, $tagDir . '/' . $newFilename . '.txt');
        }
      }
    }
  }

  public static function view(): void {
    $passphrase = Base::generate_passphrase();
    ?>
    <div class="login-container">
      <h1 class="login-title">Change Password</h1>
      <p>
        Your new password has been generated.<br>
        Write it down — it cannot be recovered.
      </p>
      <code><?= htmlspecialchars($passphrase) ?></code>
      <p>Enter your current password to re-encrypt all files and thumbnails with the new password.</p>
      <form id="emergency-form" class="login" autocomplete="off"
            data-url="/?route=emergency"
            data-confirm="This will re-encrypt all files. Continue?"
            data-success="Password changed successfully."
            data-warning="Now disable DARKDRIVE_EMERGENCY_PASSWORD mode!"
            data-redirect="Redirecting to login...">
        <input type="hidden" name="csrf_token" value="<?= Base::csrf_token() ?>">
        <input type="hidden" name="new_password" value="<?= htmlspecialchars($passphrase) ?>">
        <input type="password" name="old_password" required placeholder="Current Password" autocomplete="off">
        <button type="submit" class="login-button">Re-encrypt</button>
      </form>
    </div>
    <div id="emergency-overlay" class="error-overlay overlay-hidden">
      <div class="error-overlay-box">
        <strong id="emergency-title"></strong>
        <p id="emergency-detail" style="margin-top:0.5rem"></p>
        <p id="emergency-counter" style="margin-top:0.25rem;color:var(--text-dim)"></p>
        <button id="emergency-ok" class="error-ok-btn" style="margin-top:1rem;display:none">OK</button>
      </div>
    </div>
    <?php Base::derive_auth_key_js() ?>
    <script src="/components/app.emergency.js?v=<?= filemtime(__DIR__ . '/app.emergency.js') ?>"></script>
    <?php
  }

}
