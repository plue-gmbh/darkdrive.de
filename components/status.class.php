<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Status — diagnostics and health checks for Darkdrive
//
//   Storage:   disk space, file count, quota usage
//   Security:  HTTPS, encryption state, split-key, cookies, session flags, public shares
//   Server:    PHP version, extensions, RAM, upload limits, directory writability
//   Renders status cards with pass/warn/fail indicators
//

class Status {

  private static function can_write(string $path): bool {
    $created = false;
    if (!is_dir($path)) {
      if (!@mkdir($path, 0755, true)) return false;
      $created = true;
    }
    $f = $path . '/.wchk_' . getmypid();
    $ok = @file_put_contents($f, '') !== false;
    if ($ok) @unlink($f);
    if ($created) @rmdir($path);
    return $ok;
  }

  private static function chk(string $label, bool|string $ok, string $detail = ''): array {
    return ['label' => $label, 'ok' => $ok, 'detail' => $detail];
  }

  private static function title_text(array $checks): string {
    $lines = [];
    foreach ($checks as $c) {
      $icon = $c['ok'] === true ? '✓' : ($c['ok'] === 'warn' ? '~' : '✗');
      $line = $icon . ' ' . $c['label'];
      if ($c['detail'] !== '') $line .= '  ' . $c['detail'];
      $lines[] = $line;
    }
    return implode("\n", $lines);
  }

  private static function check_state(array $checks): string {
    $state = 'ok';
    foreach ($checks as $c) {
      if ($c['ok'] === false) return 'fail';
      if ($c['ok'] === 'warn') $state = 'warn';
    }
    return $state;
  }

  private static function card(string $name, string $summary, string $state, string $title = '', string $extra = ''): void {
    $icon  = $state === 'ok' ? '✓' : ($state === 'warn' ? '~' : '✗');
    $color = $state === 'ok' ? 'var(--success)' : ($state === 'warn' ? 'var(--warning)' : 'var(--danger)');
  ?>
    <div <?php if ($title): ?>title="<?= htmlspecialchars($title) ?>"<?php endif ?> class="status-card<?= $title ? ' status-card-info' : '' ?>">
      <div class="status-card-icon" style="color:<?= $color ?>"><?= $icon ?></div>
      <div class="status-card-body">
        <div class="status-card-name"><?= htmlspecialchars($name) ?></div>
        <div class="status-card-summary"><?= $extra ?: htmlspecialchars($summary) ?></div>
      </div>
    </div>
  <?php }

  private static function storage_checks(): array {
    $filesDir  = Base::data_path('files');
    $freeBytes = @disk_free_space(Base::data_path()) ?: 0;
    $totalBytes = 0; $totalCount = 0; $filesEncrypted = 0;
    $s3Count = 0;
    if (is_dir($filesDir)) {
      foreach (array_diff(scandir($filesDir), ['.', '..']) as $f) {
        $fp = $filesDir . '/' . $f;
        if (!is_file($fp)) continue;
        if (str_ends_with($f, '.s3')) {
          $s3Count++;
        } else {
          $totalCount++;
          $totalBytes += filesize($fp);
          if (Crypto::is_encrypted($fp)) $filesEncrypted++;
        }
      }
    }

    $checks = [];
    $checks[] = self::chk('Disk space free', true, Base::format_bytes((int)$freeBytes));
    $checks[] = self::chk('Files', true, $totalCount . ' files · ' . Base::format_bytes($totalBytes));

    $storageLimitMB = defined('DARKDRIVE_MAX_STORAGE') ? DARKDRIVE_MAX_STORAGE : 1024;
    $pct = 0;
    if ($storageLimitMB > 0) {
      $limitBytes = $storageLimitMB * 1024 * 1024;
      $pct = round($totalBytes / $limitBytes * 100);
      $checks[] = self::chk('Storage limit', $totalBytes < $limitBytes, Base::format_bytes($limitBytes) . ' (' . $pct . '% used)');
    }

    $limit = $storageLimitMB > 0 ? $storageLimitMB * 1024 * 1024 : (int)$freeBytes;
    $sizeInfo = Base::format_bytes($totalBytes) . ' / ' . Base::format_bytes($limit) . ' (' . $pct . '% used)';
    $allCount = $totalCount + $s3Count;
    if ($pct >= 90) {
      $summary = 'Almost full – ' . $sizeInfo;
    } else {
      $summary = $totalCount . ' file' . ($totalCount !== 1 ? 's' : '') . ', ' . $sizeInfo;
    }

    $s3Orphans = !S3::is_configured() ? $s3Count : 0;
    return ['checks' => $checks, 'summary' => $summary, 'totalCount' => $allCount, 'filesEncrypted' => $filesEncrypted + $s3Count, 's3Orphans' => $s3Orphans];
  }

  private static function s3_checks(): array {
    $filesDir = Base::data_path('files');
    $s3Count = 0; $s3Bytes = 0; $orphanCount = 0;
    if (is_dir($filesDir)) {
      foreach (array_diff(scandir($filesDir), ['.', '..']) as $f) {
        if (!str_ends_with($f, '.s3')) continue;
        $fp = $filesDir . '/' . $f;
        if (!is_file($fp)) continue;
        $s3Count++;
        $marker = @json_decode(@file_get_contents($fp), true);
        if (is_array($marker)) $s3Bytes += (int)($marker['size'] ?? 0);
      }
    }
    if (!S3::is_configured() && $s3Count > 0) {
      $orphanCount = $s3Count;
    }

    $checks = [];
    $checks[] = self::chk('Files', true, $s3Count . ' files · ' . Base::format_bytes($s3Bytes));

    $s3LimitMB = defined('DARKDRIVE_S3_MAX_STORAGE') ? (int)DARKDRIVE_S3_MAX_STORAGE : 0;
    $s3Pct = 0;
    if ($s3LimitMB > 0) {
      $s3LimitBytes = $s3LimitMB * 1024 * 1024;
      $s3Pct = $s3LimitBytes > 0 ? round($s3Bytes / $s3LimitBytes * 100) : 0;
      $checks[] = self::chk('Storage limit', $s3Bytes < $s3LimitBytes, Base::format_bytes($s3LimitBytes) . ' (' . $s3Pct . '% used)');
    }

    if (S3::is_configured()) {
      $s3Ok = S3::head_bucket();
      $checks[] = self::chk('Connectivity', $s3Ok, $s3Ok ? 'reachable' : 'unreachable');
    }

    if ($orphanCount > 0) {
      $checks[] = self::chk('S3 not configured', false, $orphanCount . ' file(s) reference S3 but S3 is disabled');
    }

    $sizeInfo = Base::format_bytes($s3Bytes);
    if ($s3LimitMB > 0) {
      $sizeInfo .= ' / ' . Base::format_bytes($s3LimitMB * 1024 * 1024) . ' (' . $s3Pct . '% used)';
    }
    $summary = $s3Count . ' file' . ($s3Count !== 1 ? 's' : '') . ', ' . $sizeInfo;

    return ['checks' => $checks, 'summary' => $summary];
  }

  private static function security_checks(int $totalCount, int $filesEncrypted): array {
    $thumbsDir = Base::data_path('thumbs');
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    $outside = Base::data_outside_webroot();
    $isLink = is_link(rtrim(Base::data_path(), '/'));

    $thumbsTotal = 0; $thumbsEncrypted = 0;
    if (is_dir($thumbsDir)) {
      foreach (array_diff(scandir($thumbsDir), ['.', '..']) as $f) {
        $fp = $thumbsDir . '/' . $f;
        if (!is_file($fp)) continue;
        $thumbsTotal++;
        $first3 = file_get_contents($fp, false, null, 0, 3);
        if ($first3 !== "\xFF\xD8\xFF") $thumbsEncrypted++;
      }
    }

    $checks = [];
    $checks[] = self::chk('HTTPS / SSL', $https, $https ? '' : 'not active');
    $checks[] = self::chk('data/ outside webroot', $outside && !$isLink, $isLink ? 'symlink stays URL-reachable — use DARKDRIVE_STORAGE_DIR' : '');
    $checks[] = self::chk('data/files/ encrypted', $totalCount === 0 || $filesEncrypted === $totalCount, $filesEncrypted . ' / ' . $totalCount);
    $checks[] = self::chk('data/thumbs/ encrypted', $thumbsTotal === 0 || $thumbsEncrypted === $thumbsTotal, $thumbsEncrypted . ' / ' . $thumbsTotal);

    $passwordFile = Base::data_path('.password');
    $isSplitKey = file_exists($passwordFile) && str_starts_with((string)file_get_contents($passwordFile), 'SPLITKEY:');
    $hasEncCookie = Base::enc_key() !== '';
    $checks[] = self::chk('Split-Key auth', $isSplitKey, $isSplitKey ? 'active' : 'legacy format');
    $checks[] = self::chk('Enc-Key via cookie', $hasEncCookie, $hasEncCookie ? 'present' : 'missing');

    $isApache = stripos($_SERVER['SERVER_SOFTWARE'] ?? '', 'apache') !== false;
    $denyFile = Base::data_path('.htaccess');
    $denyCurrent = is_file($denyFile) && file_get_contents($denyFile) === Base::DATA_HTACCESS;
    $dataProtected = ($outside && !$isLink) || ($isApache && $denyCurrent);
    $denyHint = $isApache && !$denyCurrent
      ? 'data/.htaccess is missing or stale and could not be rewritten — check permissions'
      : 'set DARKDRIVE_STORAGE_DIR or add an nginx location block';
    $checks[] = self::chk('data/ web-protected', $dataProtected, $dataProtected ? '' : $denyHint);

    $sessionSecure = (bool)(session_get_cookie_params()['secure'] ?? false);
    $sessionHttpOnly = (bool)(session_get_cookie_params()['httponly'] ?? false);
    $sessionSameSite = strtolower(session_get_cookie_params()['samesite'] ?? '');
    $sessionOk = $sessionHttpOnly && $sessionSameSite === 'strict' && (!$https || $sessionSecure);
    $checks[] = self::chk('Session cookie flags', $sessionOk, 'httponly=' . ($sessionHttpOnly ? 'yes' : 'no') . ', samesite=' . ($sessionSameSite ?: 'none') . ($https ? ', secure=' . ($sessionSecure ? 'yes' : 'no') : ''));

    $emergencyMode = defined('DARKDRIVE_EMERGENCY_PASSWORD');
    if ($emergencyMode) {
      $checks[] = self::chk('Emergency mode OFF', false, 'DARKDRIVE_EMERGENCY_PASSWORD is active!');
    }

    $recoveryLeft = Base::has_emergency_recovery();
    if ($recoveryLeft) {
      $checks[] = self::chk('No recovery key at rest', false, 'an interrupted password change left data/.emergency_recovery — re-run it to completion');
    }

    $pubDir = 'public';
    $pubCount = 0;
    if (is_dir($pubDir)) {
      foreach (array_diff(scandir($pubDir), ['.', '..', '.htaccess']) as $entry) {
        if (is_dir($pubDir . '/' . $entry)) $pubCount++;
      }
    }
    if ($pubCount > 0) {
      $shareLabel = $pubCount . ' file' . ($pubCount > 1 ? 's' : '') . ' shared';
      $checks[] = self::chk('Public shared files', $isApache ? true : 'warn',
        $isApache ? $shareLabel : $shareLabel . ' — public/.htaccess is ignored here, add a CSP sandbox header for /public/');
    }

    $issues = [];
    if (!$https) $issues[] = 'You should enable SSL';
    if (!$outside) $issues[] = 'data/ should be outside webroot';
    if ($isLink) $issues[] = 'data/ symlink should be replaced by DARKDRIVE_STORAGE_DIR';
    if (!$dataProtected) $issues[] = 'data/ may be accessible (nginx)';
    if ($totalCount > 0 && $filesEncrypted < $totalCount) $issues[] = 'Some files are not encrypted';
    if ($thumbsTotal > 0 && $thumbsEncrypted < $thumbsTotal) $issues[] = 'Some thumbnails are not encrypted';
    if (!$isSplitKey) $issues[] = 'Legacy password format';
    if (!$hasEncCookie) $issues[] = 'Enc-Key cookie missing';
    if ($emergencyMode) $issues[] = 'Emergency mode is active!';
    if ($recoveryLeft) $issues[] = 'Interrupted password change left a recovery key';
    if (!$sessionOk) $issues[] = 'Session cookie flags insecure';
    if ($issues) {
      $summary = $issues[0];
    } else {
      $parts = [];
      if ($https) $parts[] = 'SSL';
      $parts[] = 'Encryption';
      $parts[] = 'Split-Key';
      $summary = 'All good – ' . implode(', ', $parts);
    }

    return ['checks' => $checks, 'summary' => $summary];
  }

  private static function server_checks(): array {
    $maxBytes = Base::max_upload_bytes();

    $hasOpenssl  = function_exists('openssl_encrypt');
    $hasGd       = function_exists('imagecreatefromstring');
    $hasZip      = class_exists('ZipArchive');
    $hasFileinfo = class_exists('finfo');
    $hasCurl     = function_exists('curl_init');

    $phpOk = PHP_VERSION_ID >= 80100;

    $checks = [];
    $checks[] = self::chk('PHP ' . PHP_VERSION, $phpOk, $phpOk ? '' : 'PHP 8.1+ required');
    $checks[] = self::chk('OpenSSL', $hasOpenssl, 'AES-256-GCM');
    $checks[] = self::chk('GD', $hasGd);
    $checks[] = self::chk('ZipArchive', $hasZip);
    $checks[] = self::chk('Fileinfo', $hasFileinfo);
    $checks[] = self::chk('cURL', $hasCurl);
    $checks[] = self::chk('ffmpeg', Base::ffmpeg_bin() !== null ? true : 'warn');
    $checks[] = self::chk('pdftoppm', Base::pdftoppm_bin() !== null ? true : 'warn');
    $checks[] = self::chk('LibreOffice', Base::libreoffice_bin() !== null ? true : 'warn');

    if (is_readable('/proc/meminfo')) {
      $meminfo = @file_get_contents('/proc/meminfo');
      if ($meminfo && preg_match('/MemAvailable:\s+(\d+)/i', $meminfo, $ma)) {
        $ramAvailKB = (int)$ma[1];
        $checks[] = self::chk('RAM available', $ramAvailKB >= 256 * 1024, Base::format_bytes($ramAvailKB * 1024));
      }
    }

    $uploadMax   = Base::ini_bytes((string)ini_get('upload_max_filesize'));
    $postMax     = Base::ini_bytes((string)ini_get('post_max_size'));
    $memLimit    = Base::ini_bytes((string)ini_get('memory_limit'));
    $execTime    = (int)ini_get('max_execution_time');
    $minExecTime = max(30, (int)ceil($maxBytes / (10 * 1048576)));

    $checks[] = self::chk('upload_max_filesize', $uploadMax >= 8 * 1048576, ini_get('upload_max_filesize'));
    $checks[] = self::chk('post_max_size', $postMax >= $uploadMax, ini_get('post_max_size'));
    $checks[] = self::chk('memory_limit', $memLimit < 0 || $memLimit >= 128 * 1048576, ini_get('memory_limit'));
    $checks[] = self::chk('max_execution_time', $execTime === 0 || $execTime >= $minExecTime, $execTime . 's');
    $checks[] = self::chk('Max upload per file', $maxBytes >= 8 * 1048576, Base::format_bytes($maxBytes));
    $thumbsDir = Base::data_path('thumbs');
    $checks[] = self::chk('data/ writable', self::can_write(Base::data_path()));
    $checks[] = self::chk('data/files/ writable', self::can_write(Base::data_path('files')));
    $checks[] = self::chk('data/tags/ writable', self::can_write(Base::data_path('tags')));
    $checks[] = self::chk('data/thumbs/ writable', self::can_write($thumbsDir));

    $state = self::check_state($checks);
    if ($state === 'fail') {
      $missing = [];
      if (!$hasOpenssl) $missing[] = 'OpenSSL';
      if (!$hasGd) $missing[] = 'GD';
      if (!$hasZip) $missing[] = 'ZipArchive';
      if (!$hasFileinfo) $missing[] = 'Fileinfo';
      $summary = $missing ? 'Missing: ' . implode(', ', $missing) : 'Some settings need attention';
    } elseif ($state === 'warn') {
      $summary = 'PHP ' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . ', optional tools missing';
    } else {
      $summary = 'PHP ' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . ', all modules ready';
    }

    return ['checks' => $checks, 'summary' => $summary, 'state' => $state];
  }

  public static function view(?array $updateInfo): void {
    $updateAvail = $updateInfo && $updateInfo['remote'] > $updateInfo['local'];
    $storage  = self::storage_checks();
    $security = self::security_checks($storage['totalCount'], $storage['filesEncrypted']);
    $server   = self::server_checks();
    ?>
    <figure>
      <div class="status-wrap">

        <h1>Darkdrive</h1>
        <p class="status-tagline">Your Private Cloud. Securely Encrypted.</p>
        <p class="status-version"><?php
          if ($updateAvail) {
            echo htmlspecialchars('v' . $updateInfo['local'] . ' → ') . '<a href="/?route=update" class="status-update-link">' . htmlspecialchars('v' . $updateInfo['remote']) . '</a>';
          } elseif ($updateInfo) {
            echo htmlspecialchars('v' . $updateInfo['local'] . ' · up to date');
          } else {
            $ver = App::$appVersion ? 'v' . App::$appVersion : 'unknown';
            echo '<span class="text-danger">' . htmlspecialchars($ver . ' · could not check for updates') . '</span>';
          }
        ?></p>
        <a href="https://darkdrive.de" target="_blank" rel="noopener noreferrer" class="status-link-dim">darkdrive.de</a>

        <div class="status-cards">
          <?php self::card('Storage', $storage['summary'], self::check_state($storage['checks']), self::title_text($storage['checks'])) ?>
          <?php if (S3::is_configured() || $storage['s3Orphans'] > 0): ?>
            <?php $s3 = self::s3_checks() ?>
            <?php self::card('Object Storage', $s3['summary'], self::check_state($s3['checks']), self::title_text($s3['checks'])) ?>
          <?php endif ?>
          <?php self::card('Security', $security['summary'], self::check_state($security['checks']), self::title_text($security['checks'])) ?>
          <?php self::card('Server', $server['summary'], $server['state'], self::title_text($server['checks'])) ?>
          <?php
            $sessions = Base::active_sessions();
            $authState = $sessions <= 5 ? 'ok' : 'fail';
            $authSummary = $sessions === 1 ? '1 active session' : $sessions . ' active sessions';
            $authExtra = htmlspecialchars($authSummary);
            if ($sessions > 1) $authExtra .= ' &middot; <form method="post" action="/?route=destroy_sessions" style="display:inline"><input type="hidden" name="csrf_token" value="' . htmlspecialchars(Base::csrf_token()) . '"><button type="submit" class="status-sessions-link">Destroy others</button></form>';
          ?>
          <?php self::card('Authentication', $authSummary, $authState, '', $authExtra) ?>
        </div>

        <form method="post" action="/?route=logout">
          <?php Base::csrf_field() ?>
          <button type="submit" class="status-card status-logout">
            <div class="status-card-icon">&#x2192;</div>
            <div class="status-card-body">
              <div class="status-card-name">Logout</div>
              <div class="status-card-summary">Clears session, cookie &amp; browser</div>
            </div>
          </button>
        </form>
      </div>
    </figure>
    <?php
  }

}