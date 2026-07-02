<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Update — auto-updater for Darkdrive
//
//   Version check:  fetches remote version.json, caches result, enforces maturity delay
//   Download:       fetches ZIP from release URL with SHA-256 integrity verification
//   Apply:          extracts files, skips data/, index.php, and shell scripts
//   UI:             renders update confirmation page with changelog
//

class Update {

  private static string $remoteBase = 'https://core.darkdrive.de';

  private const MINISIGN_PUBLIC_KEY = 'RWSWvUoQBLsdUTLpo8/JS3J34mP39UJKaNbMeduBRa29O0REQqhDzHqe';

  private static function verify_minisign(string $data, string $sigContent): bool {
    $pkRaw = base64_decode(self::MINISIGN_PUBLIC_KEY, true);
    if ($pkRaw === false || strlen($pkRaw) !== 42) return false;
    if (substr($pkRaw, 0, 2) !== 'Ed') return false;
    $pkKeyId = substr($pkRaw, 2, 8);
    $pubKey  = substr($pkRaw, 10, 32);

    $lines = preg_split('/\r?\n/', $sigContent);
    if (!is_array($lines) || count($lines) < 4) return false;

    $sigBin = base64_decode(trim($lines[1]), true);
    if ($sigBin === false || strlen($sigBin) !== 74) return false;
    $alg       = substr($sigBin, 0, 2);
    $keyId     = substr($sigBin, 2, 8);
    $signature = substr($sigBin, 10, 64);

    if (!hash_equals($pkKeyId, $keyId)) return false;

    if (strncmp($lines[2], 'trusted comment: ', 17) !== 0) return false;
    $trustedComment = substr($lines[2], 17);

    $globalSig = base64_decode(trim($lines[3]), true);
    if ($globalSig === false || strlen($globalSig) !== 64) return false;

    if ($alg === 'Ed') {
      $message = $data;
    } elseif ($alg === 'ED') {
      if (!function_exists('sodium_crypto_generichash')) return false;
      $message = sodium_crypto_generichash($data, '', 64);
    } else {
      return false;
    }

    if (!sodium_crypto_sign_verify_detached($signature, $message, $pubKey)) return false;
    if (!sodium_crypto_sign_verify_detached($globalSig, $signature . $trustedComment, $pubKey)) return false;

    return true;
  }

  private static function cleanup_dir(string $dir): void {
    if (!is_dir($dir)) return;
    foreach (new \RecursiveIteratorIterator(
      new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
      \RecursiveIteratorIterator::CHILD_FIRST
    ) as $item) {
      $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    }
    @rmdir($dir);
  }

  public static function check(int $localVersion): ?array {
    $cache = Base::data_path('.version-remote');
    if (!isset($_GET['update']) && !isset($_GET['status']) && empty($_SESSION['just_logged_in']) && file_exists($cache) && (time() - filemtime($cache)) < 3600) {
      $remote = (int)trim((string)file_get_contents($cache));
    } else {
      $remote = self::fetch_remote_version();
      if ($remote === null) return null;
      @file_put_contents($cache, $remote);
    }
    if ($remote <= 0) return null;
    if ($remote > $localVersion && !isset($_GET['update']) && !self::is_release_mature()) {
      return ['local' => $localVersion, 'remote' => $localVersion];
    }
    return ['local' => $localVersion, 'remote' => $remote];
  }

  private static function update_delay(): float {
    $days = defined('DARKDRIVE_UPDATE_DELAY') ? (float)DARKDRIVE_UPDATE_DELAY : 1.0;
    if (is_nan($days) || $days < 0) return INF;
    return $days * 86400;
  }

  private static function is_release_mature(): bool {
    $delay = self::update_delay();
    if ($delay <= 0) return true;
    if (is_infinite($delay)) return false;
    $cache = Base::data_path('.version-time');
    $skipCache = isset($_GET['update']) || isset($_GET['status']);
    if (!$skipCache && file_exists($cache) && (time() - filemtime($cache)) < 3600) {
      $releaseTime = (int)trim((string)file_get_contents($cache));
    } else {
      $url = self::$remoteBase . '/latest.zip.time';
      $ctx = stream_context_create(['http' => ['timeout' => 3, 'ignore_errors' => true]]);
      $data = @file_get_contents($url, false, $ctx);
      if ($data === false && function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3, CURLOPT_FOLLOWLOCATION => true]);
        $data = curl_exec($ch);
        curl_close($ch);
      }
      $releaseTime = $data ? (int)trim($data) : 0;
      if ($releaseTime > 0) @file_put_contents($cache, $releaseTime);
    }
    if ($releaseTime <= 0) return true;
    return (time() - $releaseTime) >= $delay;
  }

  private static function fetch_remote_version(): ?int {
    $url = self::$remoteBase . '/.version';
    $ctx = stream_context_create(['http' => ['timeout' => 3, 'ignore_errors' => true]]);
    $data = @file_get_contents($url, false, $ctx);
    if ($data === false && function_exists('curl_init')) {
      $ch = curl_init($url);
      curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3, CURLOPT_FOLLOWLOCATION => true]);
      $data = curl_exec($ch);
      curl_close($ch);
    }
    if (!$data) return null;
    $v = (int)trim($data);
    return $v > 0 ? $v : null;
  }

  public static function perform(): void {
    if (!isset($_GET['update'])) return;
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !Base::csrf_verify()) return;

    $headers = ['X-Darkdrive-Request: update'];
    $url = self::$remoteBase . '/latest.zip';
    $ctx = stream_context_create(['http' => ['timeout' => 60, 'ignore_errors' => true, 'header' => $headers]]);
    $data = @file_get_contents($url, false, $ctx);
    if ($data === false && function_exists('curl_init')) {
      $ch = curl_init($url);
      curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60, CURLOPT_FOLLOWLOCATION => true, CURLOPT_HTTPHEADER => $headers]);
      $data = curl_exec($ch);
      curl_close($ch);
    }
    if (!$data) exit('Update failed: could not download package.');

    $hashUrl = self::$remoteBase . '/latest.zip.sha256';
    $hashCtx = stream_context_create(['http' => ['timeout' => 10, 'ignore_errors' => true, 'header' => $headers]]);
    $expectedHash = @file_get_contents($hashUrl, false, $hashCtx);
    if ($expectedHash === false && function_exists('curl_init')) {
      $ch = curl_init($hashUrl);
      curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => true, CURLOPT_HTTPHEADER => $headers]);
      $expectedHash = curl_exec($ch);
      curl_close($ch);
    }
    $expectedHash = trim((string)$expectedHash);
    if (!preg_match('/^[a-f0-9]{64}$/', $expectedHash)) exit('Update failed: could not fetch package checksum.');
    if (!hash_equals($expectedHash, hash('sha256', $data))) exit('Update failed: package integrity check failed.');

    $sigUrl = self::$remoteBase . '/latest.zip.minisig';
    $sigCtx = stream_context_create(['http' => ['timeout' => 10, 'ignore_errors' => true, 'header' => $headers]]);
    $sigContent = @file_get_contents($sigUrl, false, $sigCtx);
    if ($sigContent === false && function_exists('curl_init')) {
      $ch = curl_init($sigUrl);
      curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => true, CURLOPT_HTTPHEADER => $headers]);
      $sigContent = curl_exec($ch);
      curl_close($ch);
    }
    if (!$sigContent) exit('Update failed: could not fetch package signature.');
    if (!function_exists('sodium_crypto_sign_verify_detached')) exit('Update failed: libsodium is required for signature verification.');
    if (!self::verify_minisign($data, (string)$sigContent)) exit('Update failed: package signature is invalid. Refusing to install.');

    if (!class_exists('ZipArchive')) exit('Update failed: ZipArchive not available on this server.');

    $tmpFile = tempnam(sys_get_temp_dir(), 'darkdrive_');
    if ($tmpFile === false) exit('Update failed: could not create temp file.');
    if (file_put_contents($tmpFile, $data) === false) { @unlink($tmpFile); exit('Update failed: could not write temp file.'); }

    $zip = new ZipArchive();
    if ($zip->open($tmpFile) !== true) { unlink($tmpFile); exit('Update failed: invalid package.'); }

    $base = rtrim(__DIR__ . '/..', '/') . '/';
    $stagingDir = sys_get_temp_dir() . '/darkdrive_update_' . bin2hex(random_bytes(8));
    mkdir($stagingDir, 0755);

    $extracted = [];
    for ($i = 0; $i < $zip->numFiles; $i++) {
      $name = $zip->getNameIndex($i);
      if (substr($name, -1) === '/') continue;
      if (strncmp($name, 'data/', 5) === 0) continue;
      if (substr($name, -3) === '.sh') continue;
      if ($name === 'index.php') continue;
      $safe = true;
      foreach (explode('/', str_replace('\\', '/', $name)) as $part) {
        if ($part === '..' || $part === '.') { $safe = false; break; }
      }
      if (!$safe) continue;
      $stageDest = $stagingDir . '/' . $name;
      $stageDir  = dirname($stageDest);
      if (!is_dir($stageDir)) mkdir($stageDir, 0755, true);
      if (file_put_contents($stageDest, $zip->getFromIndex($i)) === false) {
        $zip->close();
        unlink($tmpFile);
        self::cleanup_dir($stagingDir);
        exit('Update failed: could not write ' . htmlspecialchars($name) . ' — check disk space.');
      }
      $extracted[] = $name;
    }
    $zip->close();
    unlink($tmpFile);

    if (is_dir($base . 'components')) {
      foreach (scandir($base . 'components') as $component) {
        if ($component === '.' || $component === '..') continue;
        $path = $base . 'components/' . $component;
        if (is_file($path)) unlink($path);
      }
    }
    foreach ($extracted as $name) {
      $dest = $base . $name;
      $dir  = dirname($dest);
      if (!is_dir($dir)) mkdir($dir, 0755, true);
      rename($stagingDir . '/' . $name, $dest);
    }
    self::cleanup_dir($stagingDir);

    $cache = Base::data_path('.version-remote');
    if (file_exists($cache)) unlink($cache);
    $timeCache = Base::data_path('.version-time');
    if (file_exists($timeCache)) unlink($timeCache);

    Base::redirect('/?route=status');
  }

  public static function view(?array $info): void {
    ?>
    <figure>
      <div class="status-wrap">
        <h1>Darkdrive</h1>

        <?php $auto = !empty($_SESSION['auto_update']); unset($_SESSION['auto_update']); ?>
        <?php if ($info && $info['remote'] > $info['local']): ?>
          <?php if (!$auto): ?>
          <p class="status-version">v<?= $info['local'] ?> &rarr; <span class="status-update-link">v<?= $info['remote'] ?></span></p>
          <?php endif ?>
          <form id="<?= $auto ? 'update-auto' : 'update-form' ?>" method="post" action="/?route=update">
            <?php Base::csrf_field() ?>
            <?php if (!$auto): ?>
            <button type="submit" class="status-card status-logout">
              <div class="status-card-icon">&#x2191;</div>
              <div class="status-card-body">
                <div class="status-card-name">Update</div>
                <div class="status-card-summary">Install latest version</div>
              </div>
            </button>
            <?php else: ?>
            <div class="status-card status-logout" style="pointer-events:none">
              <div class="status-card-icon">&#x2191;</div>
              <div class="status-card-body">
                <div class="status-card-name" style="color:var(--success)">Installing v<?= $info['remote'] ?>&hellip;</div>
              </div>
            </div>
            <?php endif ?>
          </form>
        <?php elseif ($info): ?>
          <p class="status-version">v<?= $info['local'] ?> &middot; <span style="font-weight:500">up to date</span></p>
        <?php else: ?>
          <p class="status-version"><span class="text-danger">Could not check for updates</span></p>
        <?php endif ?>
      </div>
    </figure>
    <?php
  }

}