<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Upload — file upload handling and storage management for Darkdrive
//
//   Validation:  file type, size, MIME, safety checks (SVG/XML/CSV sanitization)
//   Encryption:  encrypts directly from PHP tmp via Crypto (no plaintext in data/)
//   Storage:     atomic file-locked byte counter, configurable quota enforcement
//   Rate limit:  per-session upload throttle (max 1000 uploads / hour)
//   Dedupe:      client sends a content fingerprint; index stores it HMAC'd with
//                the encryption key, so re-shared files are skipped without re-upload
//   Thumbnails:  auto-generates image thumbs on upload via GD
//

class Upload {

  const DEDUPE_MAX_HASHES = 200;

  private string $directory;
  private bool $active;

  private static ?self $instance = null;

  public function __construct(string $directory, bool $active) {
    $this->directory = $directory;
    $this->active    = $active;
    self::$instance  = $this;
  }

  public static function init(string $directory, bool $active): void {
    new self($directory, $active);
  }

  private static function fail(string $reason, string &$password = null): never {
    if ($password !== null) { Base::memzero($password); Crypto::clear_cache(); }
    exit(json_encode(['error' => $reason]));
  }

  private static function emit(string $step): void {
    echo json_encode(['step' => $step]) . "\n";
    flush();
  }

  public static function handle(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
    if (empty($_FILES['upload']) && empty($_POST) && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) self::fail('payload_too_large');
    if (empty($_FILES['upload'])) return;
    if (!self::$instance?->active) self::fail('inactive');
    if (($_FILES['upload']['error'] ?? 0) !== UPLOAD_ERR_OK) self::fail('upload_error');
    if (empty($_POST['csrf_token']) || !isset($_SESSION['csrf_token'])
        || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) self::fail('csrf');
    $password = Base::enc_key();
    if ($password === '') self::fail('no_key');
    session_write_close();
    @set_time_limit(300);
    if (!is_dir(self::$instance->directory) && !mkdir(self::$instance->directory, 0755)) self::fail('write_failed', $password);
    $uploadExt = strtolower(pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION));
    if (in_array($uploadExt, Base::EXT_BLOCKED, true)) self::fail('blocked_type', $password);
    if (!Base::is_safe_file($_FILES['upload']['name'])) self::fail('unsupported_type', $password);
    if (!is_uploaded_file($_FILES['upload']['tmp_name'])) self::fail('invalid_upload', $password);
    if (class_exists('finfo')) {
      $fi = new \finfo(FILEINFO_MIME_TYPE);
      $mime = $fi->file($_FILES['upload']['tmp_name']);
      if ($mime !== false && (preg_match('/php|x-httpd/i', $mime))) self::fail('blocked_type', $password);
    }
    if ($_FILES['upload']['size'] > DARKDRIVE_MAX_FILESIZE * 1024 * 1024) self::fail('file_too_large', $password);
    if ($uploadExt === 'svg' && !Base::is_safe_svg($_FILES['upload']['tmp_name'])) self::fail('unsafe_content', $password);
    if ($uploadExt === 'xml' && !Base::is_safe_xml($_FILES['upload']['tmp_name'])) self::fail('unsafe_content', $password);
    if ($uploadExt === 'csv' && !Base::is_safe_csv($_FILES['upload']['tmp_name'])) self::fail('unsafe_content', $password);
    if (!self::check_rate_limit()) self::fail('rate_limited', $password);

    header('X-Accel-Buffering: no');
    while (ob_get_level() > 0) ob_end_flush();

    $clean    = Base::str_clean(basename($_FILES['upload']['name']));
    $ts       = date('Ymd-His');
    $encName  = Crypto::encrypt_filename($clean, $password);
    if ($encName === false) { Base::memzero($password); Crypto::clear_cache(); self::fail('encrypt_failed'); }
    $isS3 = S3::is_configured();
    if ($isS3) {
      if (!S3::check_s3_quota($_FILES['upload']['size'])) self::fail('storage_full', $password);
    } else {
      if (!self::check_storage_quota($_FILES['upload']['size'])) self::fail('storage_full', $password);
    }
    $filename = $ts . '-' . $encName;
    $filepath = self::$instance->directory . "/{$filename}";
    $tmpPath = $_FILES['upload']['tmp_name'];
    if (Base::is_image($clean)) {
      $plainData = file_get_contents($tmpPath);
      if ($plainData !== false) Files::maybe_save_thumb($filename, $plainData);
      if (isset($plainData) && $plainData !== false) Base::memzero($plainData);
    }

    self::emit('encrypting');

    $encpath = $filepath . '.enc';
    if (!Crypto::encrypt_stream($tmpPath, $encpath, $password)) {
      @unlink($encpath);
      if ($isS3) {
        S3::update_s3_storage_bytes(-$_FILES['upload']['size']);
      } else {
        self::update_storage_bytes(-$_FILES['upload']['size']);
      }
      Base::memzero($password);
      Crypto::clear_cache();
      self::fail('encrypt_failed');
    }
    if (!rename($encpath, $filepath)) {
      @unlink($encpath);
      if ($isS3) {
        S3::update_s3_storage_bytes(-$_FILES['upload']['size']);
      } else {
        self::update_storage_bytes(-$_FILES['upload']['size']);
      }
      Base::memzero($password);
      Crypto::clear_cache();
      self::fail('write_failed');
    }
    $actualSize = (int)filesize($filepath);

    if ($isS3) {
      self::emit('uploading');

      $encFh  = fopen($filepath, 'rb');
      if ($encFh === false) {
        @unlink($filepath);
        S3::update_s3_storage_bytes(-$_FILES['upload']['size']);
        Base::memzero($password);
        Crypto::clear_cache();
        self::fail('encrypt_failed');
      }
      $encHdr = fread($encFh, 39);
      fclose($encFh);
      if ($encHdr === false || strlen($encHdr) < 39) {
        @unlink($filepath);
        S3::update_s3_storage_bytes(-$_FILES['upload']['size']);
        Base::memzero($password);
        Crypto::clear_cache();
        self::fail('encrypt_failed');
      }
      $saltHex   = bin2hex(substr($encHdr, 11, 16));
      $plainSz   = unpack('J', substr($encHdr, 31, 8))[1];
      $s3Key     = $filename;
      if (!S3::put_object($s3Key, $filepath)) {
        @unlink($filepath);
        S3::update_s3_storage_bytes(-$_FILES['upload']['size']);
        Base::memzero($password);
        Crypto::clear_cache();
        error_log('Darkdrive S3 upload failed: ' . (S3::last_error() ?? 'unknown'));
        self::fail('s3_failed');
      }
      S3::write_marker($filename, $s3Key, $actualSize, $plainSz, true, $saltHex, Crypto::CHUNK_SIZE);
      S3::update_s3_storage_bytes($actualSize - $_FILES['upload']['size']);
      @unlink($filepath);
    } else {
      $diff = $actualSize - $_FILES['upload']['size'];
      if ($diff !== 0) self::update_storage_bytes($diff);
    }

    if (!empty($_GET['tag'])) Base::set_tag($filename, Base::str_clean($_GET['tag']));
    if (!empty($_POST['fingerprint']) && is_string($_POST['fingerprint']) && preg_match('/^[0-9a-f]{64}$/', $_POST['fingerprint'])) {
      self::dedupe_record($_POST['fingerprint'], $filename, $password);
    }
    Base::memzero($password);
    Crypto::clear_cache();
    exit($filename . '|' . $clean);
  }

  private static function dedupe_path(): string {
    return Base::data_path('.dedupe');
  }

  private static function dedupe_tag(string $fingerprint, string $password): string {
    $key = hash_hmac('sha256', 'darkdrive-dedupe-v1', $password . Base::instance_key(), true);
    $tag = hash_hmac('sha256', $fingerprint, $key);
    Base::memzero($key);
    return $tag;
  }

  private static function dedupe_parse(string $raw): array {
    $map = [];
    foreach (explode("\n", $raw) as $line) {
      $sep = strpos($line, '|');
      if ($sep === false) continue;
      $map[substr($line, 0, $sep)] = substr($line, $sep + 1);
    }
    return $map;
  }

  private static function dedupe_serialize(array $map): string {
    $out = '';
    foreach ($map as $tag => $filename) $out .= $tag . '|' . $filename . "\n";
    return $out;
  }

  private static function stored_names(): array {
    $dir = Base::data_path('files');
    if (!is_dir($dir)) return [];
    $names = @scandir($dir);
    return $names === false ? [] : array_flip($names);
  }

  private static function dedupe_sync(): array {
    $path = self::dedupe_path();
    if (!is_file($path)) return [];
    $fh = @fopen($path, 'c+');
    if (!$fh) return [];
    if (!flock($fh, LOCK_EX)) { fclose($fh); return []; }
    $raw    = (string)stream_get_contents($fh);
    $stored = self::stored_names();
    $keep   = [];
    foreach (self::dedupe_parse($raw) as $tag => $filename) {
      if (isset($stored[$filename]) || isset($stored[$filename . '.s3'])) $keep[$tag] = $filename;
    }
    $out = self::dedupe_serialize($keep);
    if ($out !== $raw) {
      ftruncate($fh, 0);
      rewind($fh);
      fwrite($fh, $out);
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $keep;
  }

  private static function dedupe_record(string $fingerprint, string $filename, string $password): void {
    if ($fingerprint === '') return;
    $fh = @fopen(self::dedupe_path(), 'c+');
    if (!$fh) return;
    if (!flock($fh, LOCK_EX)) { fclose($fh); return; }
    fseek($fh, 0, SEEK_END);
    fwrite($fh, self::dedupe_tag($fingerprint, $password) . '|' . $filename . "\n");
    flock($fh, LOCK_UN);
    fclose($fh);
  }

  public static function handle_dedupe_check(): void {
    if (!isset($_GET['dedupe'])) return;
    header('Content-Type: application/json');
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !Base::csrf_verify()) { http_response_code(403); exit('{}'); }
    $password = Base::enc_key();
    if ($password === '') { http_response_code(403); exit('{}'); }
    $keep   = self::dedupe_sync();
    $seen   = [];
    $hashes = is_array($_POST['hashes'] ?? null) ? array_slice($_POST['hashes'], 0, self::DEDUPE_MAX_HASHES) : [];
    foreach ($hashes as $fingerprint) {
      if (!is_string($fingerprint) || !preg_match('/^[0-9a-f]{64}$/', $fingerprint)) continue;
      if (isset($keep[self::dedupe_tag($fingerprint, $password)])) $seen[] = $fingerprint;
    }
    Base::memzero($password);
    Crypto::clear_cache();
    exit(json_encode(['known' => $seen]));
  }

  public static function clear_dedupe(): void {
    @unlink(self::dedupe_path());
  }

  private static function check_rate_limit(): bool {
    $logFile = Base::data_path('.upload_rate');
    $now     = time();
    $cutoff  = $now - 3600;
    $fh = fopen($logFile, 'c+');
    if (!$fh) return false;
    if (!flock($fh, LOCK_EX)) { fclose($fh); return false; }
    $entries = [];
    foreach (explode("\n", trim(stream_get_contents($fh) ?: '')) as $line) {
      $ts = (int) $line;
      if ($ts >= $cutoff) $entries[] = $ts;
    }
    if (count($entries) >= 1000) {
      flock($fh, LOCK_UN);
      fclose($fh);
      return false;
    }
    $entries[] = $now;
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, implode("\n", $entries) . "\n");
    flock($fh, LOCK_UN);
    fclose($fh);
    return true;
  }

  private static function recalc_storage(): int {
    $total = 0;
    $dir = Base::data_path('files');
    if (is_dir($dir)) {
      foreach (array_diff(scandir($dir), ['.', '..']) as $f) {
        if (str_ends_with($f, '.s3')) continue;
        $fp = $dir . '/' . $f;
        $total += is_file($fp) ? filesize($fp) : 0;
      }
    }
    return $total;
  }

  public static function storage_bytes(): int {
    $counter = Base::data_path('.storage_bytes');
    if (is_file($counter) && (time() - filemtime($counter)) > 3600) {
      $fh = @fopen($counter, 'c+');
      if ($fh && flock($fh, LOCK_EX)) {
        $val = self::recalc_storage();
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, (string)$val);
        flock($fh, LOCK_UN);
        fclose($fh);
        return $val;
      }
      if ($fh) fclose($fh);
      return self::recalc_storage();
    }
    $fh = @fopen($counter, 'c+');
    if (!$fh) return self::recalc_storage();
    if (!flock($fh, LOCK_SH)) { fclose($fh); return self::recalc_storage(); }
    $contents = stream_get_contents($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    $val = max(0, (int)trim($contents ?: '0'));
    if ($val === 0 && $contents !== false && trim($contents) === '0') return 0;
    return $val ?: self::recalc_storage();
  }

  public static function update_storage_bytes(int $delta): void {
    $counter = Base::data_path('.storage_bytes');
    $fh = @fopen($counter, 'c+');
    if (!$fh) return;
    if (!flock($fh, LOCK_EX)) { fclose($fh); return; }
    $contents = stream_get_contents($fh);
    $current = max(0, (int)trim($contents ?: '0'));
    $needs_recalc = ($current === 0 && $delta > 0 && ($contents === false || trim($contents) !== '0'));
    if ($needs_recalc) $current = self::recalc_storage();
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, (string)max(0, $current + $delta));
    flock($fh, LOCK_UN);
    fclose($fh);
  }

  public static function check_storage_quota(int $addBytes): bool {
    $storageLimitMB = defined('DARKDRIVE_MAX_STORAGE') ? DARKDRIVE_MAX_STORAGE : 1024;
    if ($storageLimitMB <= 0) return true;
    $counter = Base::data_path('.storage_bytes');
    $fh = @fopen($counter, 'c+');
    if (!$fh) return false;
    if (!flock($fh, LOCK_EX)) { fclose($fh); return false; }
    $contents = stream_get_contents($fh);
    $current = max(0, (int)trim($contents ?: '0'));
    $needs_recalc = ($current === 0 && ($contents === false || trim($contents) !== '0'));
    if ($needs_recalc) $current = self::recalc_storage();
    $limitBytes = $storageLimitMB * 1024 * 1024;
    if ($current + $addBytes > $limitBytes) {
      flock($fh, LOCK_UN);
      fclose($fh);
      return false;
    }
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, (string)($current + $addBytes));
    flock($fh, LOCK_UN);
    fclose($fh);
    return true;
  }

  public static function view(): void {
    if (!self::$instance?->active) return;
    $hasTag = !empty($_GET['tag']);
    ?>
      <form method="post" action="" enctype="multipart/form-data" class="upload">
        <?php Base::csrf_field() ?>
        <input type="file" name="upload" id="uploads" multiple>
        <label class="button" data-upload-trigger><?php if ($hasTag): ?><svg style="margin-left:1px" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/><path d="M12 10v6"/><path d="m9 13 3-3 3 3"/></svg><?php else: ?><svg style="margin-left:1px" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="m17 8-5-5-5 5"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/></svg><?php endif ?></label>
        <input type="submit" value="Upload" id="upload" class="button">
      </form>
    <?php
  }

}
