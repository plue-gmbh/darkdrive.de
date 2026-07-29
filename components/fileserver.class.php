<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// FileServer — HTTP file serving, downloads, and file mutations for Darkdrive
//
//   Serves encrypted files with decryption on the fly (chunked + legacy).
//   Handles Range requests (HTTP 206) for audio/video streaming.
//   Generates and serves thumbnails (image, video via ffmpeg, PDF via pdftoppm).
//   Streams ZIP exports with per-entry encryption.
//   Processes file mutations: publish/unpublish, delete, edit-save.
//
//   All derived keys and plaintext are zeroed before exit.
//   Redirect targets are validated to prevent open-redirect.
//   Published copies live in public/ and bypass PHP, so every boot (re)writes a
//   public/.htaccess that sandboxes them into an opaque origin — shared HTML and
//   SVG still render and download, but cannot reach the session or the API.
//   Writing it on boot rather than only on publish means instances that shared
//   files before this rule existed are covered without republishing.
//

class FileServer {

  const PUBLIC_HTACCESS = "Options -Indexes\n\n"
    . "<IfModule mod_headers.c>\n"
    . "  Header always set Content-Security-Policy \"sandbox allow-scripts allow-downloads\"\n"
    . "  Header always set X-Content-Type-Options \"nosniff\"\n"
    . "</IfModule>\n";

  public static function protect_public_dir(): void {
    if (!is_dir('public')) return;
    $htaccess = 'public/.htaccess';
    if (!is_file($htaccess) || file_get_contents($htaccess) !== self::PUBLIC_HTACCESS) {
      @file_put_contents($htaccess, self::PUBLIC_HTACCESS, LOCK_EX);
    }
  }

  public static function handle(): void {
    if (!isset($_GET['loadfile'])) return;
    $filename   = Base::str_clean($_GET['loadfile']);
    if (!Files::is_known($filename)) return;
    $filepath   = Base::data_path('files/' . $filename);
    $markerPath = S3::marker_path($filename);
    $isLocal    = file_exists($filepath) && is_file($filepath);
    $isS3       = !$isLocal && file_exists($markerPath);
    if (!$isLocal && !$isS3) return;

    if ($isS3) {
      if (!S3::is_configured()) {
        http_response_code(503);
        exit('This file is stored on S3 which is currently not configured. Re-enable S3 or migrate files back to local storage.');
      }
      self::serve_s3($filename, $markerPath);
      return;
    }

    $fmtime = (int)filemtime($filepath);
    $etag = '"' . md5($filename . (string)filesize($filepath) . $fmtime . session_id()) . '"';
    header('ETag: ' . $etag);
    header('Cache-Control: private, max-age=43200');
    header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 43200) . ' GMT');
    header('Pragma: ');
    header('X-Frame-Options: SAMEORIGIN');
    if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && trim($_SERVER['HTTP_IF_NONE_MATCH']) === $etag) {
      http_response_code(304);
      exit;
    }

    $password = Base::enc_key();
    session_write_close();

    if (!empty($password) && Crypto::is_chunked($filepath)) {
      self::serve_chunked($filepath, $filename, $password);
    } else {
      self::serve_legacy($filepath, $filename, $password);
    }
  }

  private static function serve_s3(string $filename, string $markerPath): never {
    $marker = S3::read_marker($filename);
    if ($marker === false) { http_response_code(500); exit; }

    $fmtime = (int)filemtime($markerPath);
    $etag   = '"' . md5($filename . $marker['size'] . $fmtime . session_id()) . '"';
    header('ETag: ' . $etag);
    header('Cache-Control: private, max-age=43200');
    header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 43200) . ' GMT');
    header('Pragma: ');
    header('X-Frame-Options: SAMEORIGIN');
    if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && trim($_SERVER['HTTP_IF_NONE_MATCH']) === $etag) {
      http_response_code(304);
      exit;
    }

    $password = Base::enc_key();
    if (empty($password)) { http_response_code(403); exit; }
    session_write_close();

    $cleanName = Files::real_name($filename);
    $ext       = strtolower(pathinfo($cleanName, PATHINFO_EXTENSION));
    header('Content-Disposition: ' . self::content_disposition($cleanName, $ext));
    header('Content-Type: ' . Base::ext_to_mime($ext));

    if (!empty($marker['chunked'])) {
      $password = self::test_key_s3_chunked($marker['key'], $password);
      if ($password === false) {
        http_response_code(500); exit;
      }
      self::serve_s3_chunked($filename, $marker, $password);
    } else {
      $stream = S3::get_object_stream($marker['key']);
      if ($stream === false) {
        Base::memzero($password); Crypto::clear_cache(); http_response_code(502); exit;
      }
      $enc = stream_get_contents($stream);
      fclose($stream);
      if ($enc === false) {
        Base::memzero($password); Crypto::clear_cache(); http_response_code(502); exit;
      }
      $data = self::decrypt_with_recovery($enc, $password, $recoveredPw);
      if ($data === false) {
        Base::memzero($password); Crypto::clear_cache(); http_response_code(500); exit;
      }
      if ($recoveredPw !== null) $password = $recoveredPw;
      self::serve_range(strlen($data), $password, data: $data);
    }

    Base::memzero($password); Crypto::clear_cache();
    exit;
  }

  private static function test_key_s3_chunked(string $s3Key, string $password): string|false {
    $testStream = S3::get_object_stream($s3Key);
    if ($testStream === false) return $password;
    $keyOk = Crypto::decrypt_chunked_with_callback_fh($testStream, $password, fn() => true);
    fclose($testStream);
    if ($keyOk) return $password;
    $recovery = Base::emergency_recovery_password();
    if ($recovery !== null) {
      $retryStream = S3::get_object_stream($s3Key);
      if ($retryStream !== false) {
        $retryOk = Crypto::decrypt_chunked_with_callback_fh($retryStream, $recovery, fn() => true);
        fclose($retryStream);
        if ($retryOk) {
          Base::memzero($password); Crypto::clear_cache();
          return $recovery;
        }
      }
    }
    Base::memzero($password); Crypto::clear_cache();
    return false;
  }

  private static function decrypt_with_recovery(string $enc, string $password, ?string &$recoveredPw = null): string|false {
    $recoveredPw = null;
    $data = Crypto::decrypt($enc, $password);
    if ($data !== false) return $data;
    $recovery = Base::emergency_recovery_password();
    if ($recovery === null) return false;
    $data = Crypto::decrypt($enc, $recovery);
    if ($data === false) return false;
    $recoveredPw = $recovery;
    return $data;
  }

  private static function serve_s3_chunked(string $filename, array $marker, string $password): void {
    $plain_size  = (int)($marker['plain_size'] ?? 0);
    $chunk_size  = (int)($marker['chunk_size'] ?? Crypto::CHUNK_SIZE);
    $salt_hex    = (string)($marker['salt']  ?? '');
    $s3_key      = (string)($marker['key']   ?? $filename);

    header('Accept-Ranges: bytes');

    $has_range = isset($_SERVER['HTTP_RANGE'])
      && preg_match('/bytes=(\d*)-(\d*)/i', $_SERVER['HTTP_RANGE'], $rm);

    if ($has_range) {
      if ($rm[1] === '' && $rm[2] !== '') {
        $rs = max(0, $plain_size - (int)$rm[2]);
        $re = $plain_size - 1;
      } else {
        $rs = (int)$rm[1];
        $re = $rm[2] !== '' ? min((int)$rm[2], $plain_size - 1) : $plain_size - 1;
      }
      if ($rs > $re || $rs >= $plain_size) {
        http_response_code(416);
        header('Content-Range: bytes */' . $plain_size);
        return;
      }
      http_response_code(206);
      header('Content-Range: bytes ' . $rs . '-' . $re . '/' . $plain_size);
      header('Content-Length: ' . ($re - $rs + 1));

      if ($salt_hex !== '') {
        $enc_chunk_stride = 4 + 12 + 16 + $chunk_size;
        $first_chunk      = (int)floor($rs / $chunk_size);
        $enc_start        = 39 + $first_chunk * $enc_chunk_stride;
        $enc_end          = (int)$marker['size'] - 1;
        $stream = S3::get_range_stream($s3_key, $enc_start, $enc_end);
        if ($stream === false) { http_response_code(502); return; }
        Crypto::decrypt_s3_range_output($stream, $salt_hex, $password, $first_chunk, $rs, $re, $chunk_size, $plain_size);
        fclose($stream);
      } else {
        $stream = S3::get_object_stream($s3_key);
        if ($stream === false) { http_response_code(502); return; }
        Crypto::decrypt_chunked_output_range_fh($stream, $password, $rs, $re);
        fclose($stream);
      }
    } else {
      header('Content-Length: ' . $plain_size);
      $stream = S3::get_object_stream($s3_key);
      if ($stream === false) { http_response_code(502); return; }
      Crypto::decrypt_chunked_output_fh($stream, $password);
      fclose($stream);
    }
  }

  private static function content_disposition(string $cleanName, string $ext): string {
    $inline = Base::is_image($cleanName) || Base::is_video($cleanName) || Base::is_audio($cleanName)
              || Base::is_text($cleanName) || Base::is_contact($cleanName) || $ext === 'pdf';
    $mime = Base::ext_to_mime($ext);
    $mimeIsHtml = (bool) preg_match('#^(text/html|application/xhtml)#i', $mime);
    if ($mimeIsHtml && !in_array($ext, ['html', 'htm'])) $inline = false;
    if ($ext === 'svg') $inline = false;
    if ($mimeIsHtml) {
      header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:;");
    }
    $ascii = str_replace(['"', "\r", "\n", '\\'], '', preg_replace('/[^\x20-\x7E]/', '?', $cleanName));
    $disposition = $inline ? 'inline' : 'attachment';
    return "{$disposition}; filename=\"{$ascii}\"; filename*=UTF-8''" . rawurlencode($cleanName);
  }

  private static function serve_range(int $size, string $password, ?string $filepath = null, ?string $data = null): void {
    header('Accept-Ranges: bytes');
    if (!isset($_SERVER['HTTP_RANGE']) || !preg_match('/bytes=(\d*)-(\d*)/i', $_SERVER['HTTP_RANGE'], $rm)) {
      header('Content-Length: ' . $size);
      if ($filepath !== null) {
        Crypto::decrypt_chunked_output($filepath, $password);
      } else {
        echo $data;
      }
      return;
    }
    if ($rm[1] === '' && $rm[2] !== '') {
      $rs = max(0, $size - (int)$rm[2]);
      $re = $size - 1;
    } else {
      $rs = (int)$rm[1];
      $re = $rm[2] !== '' ? min((int)$rm[2], $size - 1) : $size - 1;
    }
    if ($rs > $re || $rs >= $size) {
      http_response_code(416);
      header('Content-Range: bytes */' . $size);
      Base::memzero($password); Crypto::clear_cache();
      exit;
    }
    http_response_code(206);
    header('Content-Range: bytes ' . $rs . '-' . $re . '/' . $size);
    header('Content-Length: ' . ($re - $rs + 1));
    if ($filepath !== null) {
      Crypto::decrypt_chunked_output_range($filepath, $password, $rs, $re);
    } else {
      echo substr($data, $rs, $re - $rs + 1);
    }
  }

  private static function serve_chunked(string $filepath, string $filename, string $password): never {
    if (!Crypto::test_chunked_key($filepath, $password)) {
      $recovery = Base::emergency_recovery_password();
      if ($recovery !== null && Crypto::test_chunked_key($filepath, $recovery)) {
        $password = $recovery;
      } else {
        Base::memzero($password); Crypto::clear_cache();
        http_response_code(500);
        exit;
      }
    }
    $plainSize = Crypto::chunked_plain_size($filepath);
    if ($plainSize === false) {
      Base::memzero($password); Crypto::clear_cache();
      http_response_code(500);
      exit;
    }
    $cleanName = Files::real_name($filename);
    $ext = strtolower(pathinfo($cleanName, PATHINFO_EXTENSION));

    header('Content-Disposition: ' . self::content_disposition($cleanName, $ext));
    header('Content-Type: ' . Base::ext_to_mime($ext));

    $thumbPath = Base::data_path('thumbs/' . $filename);
    if (Base::is_image($cleanName) && !file_exists($thumbPath) && $plainSize < 50 * 1024 * 1024) {
      $decStr = Crypto::decrypt_chunked_to_string($filepath, $password);
      if ($decStr !== false) {
        Files::maybe_save_thumb($filename, $decStr);
        self::serve_range($plainSize, $password, data: $decStr);
        Base::memzero($password); Crypto::clear_cache();
        exit;
      }
    }

    self::serve_range($plainSize, $password, filepath: $filepath);
    Base::memzero($password); Crypto::clear_cache();
    exit;
  }

  private static function serve_legacy(string $filepath, string $filename, string $password): never {
    $data = file_get_contents($filepath);
    if ($data === false) {
      Base::memzero($password); Crypto::clear_cache();
      http_response_code(500);
      exit;
    }
    if (!empty($password)) {
      $decrypted = self::decrypt_with_recovery($data, $password, $recoveredPw);
      if ($decrypted === false) {
        Base::memzero($password); Crypto::clear_cache();
        http_response_code(500);
        exit;
      }
      if ($recoveredPw !== null) $password = $recoveredPw;
      $data = $decrypted;
    }
    $cleanName = Files::real_name($filename);
    if (Base::is_image($cleanName)) Files::maybe_save_thumb($filename, $data);
    $ext = strtolower(pathinfo($cleanName, PATHINFO_EXTENSION));
    header('Content-Type: ' . Base::ext_to_mime($ext));
    header('Content-Disposition: ' . self::content_disposition($cleanName, $ext));

    self::serve_range(strlen($data), $password, data: $data);
    Base::memzero($password); Crypto::clear_cache();
    exit;
  }

  public static function handle_thumb(): void {
    if (!isset($_GET['loadthumb'])) return;
    $filename  = Base::str_clean($_GET['loadthumb']);
    if (!Files::is_known($filename)) { http_response_code(404); exit; }
    $thumbpath = Base::data_path('thumbs/' . $filename);

    if (!file_exists($thumbpath)) {
      $rn = Files::real_name($filename);
      if (Base::is_video($rn)) {
        Files::maybe_save_video_thumb($filename);
      } elseif (strtolower(pathinfo($rn, PATHINFO_EXTENSION)) === 'pdf') {
        Files::maybe_save_pdf_thumb($filename);
      } elseif (Base::is_office($rn)) {
        Files::maybe_save_office_thumb($filename);
      } elseif (Base::is_image($rn)) {
        $filepath = Base::data_path('files/' . $filename);
        $tmpS3 = null;
        if (!file_exists($filepath)) {
          if (!S3::is_configured()) { http_response_code(404); exit; }
          $marker = S3::read_marker($filename);
          if ($marker === false) { http_response_code(404); exit; }
          $tmpS3 = tempnam(sys_get_temp_dir(), 'dd_s3th_');
          if (!S3::download_to_file((string)($marker['key'] ?? $filename), $tmpS3)) {
            @unlink($tmpS3); http_response_code(502); exit;
          }
          $filepath = $tmpS3;
        }
        $password = Base::enc_key();
        if ($password !== '') {
          $dec = Crypto::decrypt_any_to_string($filepath, $password);
          if ($tmpS3) @unlink($tmpS3);
          if ($dec !== false) {
            Files::maybe_save_thumb($filename, $dec);
            if (!file_exists($thumbpath)) {
              header('Content-Type: ' . Base::ext_to_mime(pathinfo($rn, PATHINFO_EXTENSION)));
              header('Content-Length: ' . strlen($dec));
              header('Cache-Control: private, max-age=43200');
              header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 43200) . ' GMT');
              header('Pragma: ');
              session_write_close();
              echo $dec;
              Base::memzero($password); Crypto::clear_cache();
              exit;
            }
          }
        } else {
          if ($tmpS3) @unlink($tmpS3);
        }
      }
    }

    if (!file_exists($thumbpath) || !is_file($thumbpath)) { http_response_code(404); exit; }

    $thMtime = (int)filemtime($thumbpath);
    $etag = '"th-' . md5($filename . (string)filesize($thumbpath) . $thMtime . session_id()) . '"';
    header('ETag: ' . $etag);
    header('Cache-Control: private, max-age=43200');
    header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 43200) . ' GMT');
    header('Pragma: ');
    header('X-Frame-Options: SAMEORIGIN');
    if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && trim($_SERVER['HTTP_IF_NONE_MATCH']) === $etag) {
      http_response_code(304);
      exit;
    }
    $password = Base::enc_key();
    session_write_close();
    $data = file_get_contents($thumbpath);
    if ($data === false) { http_response_code(404); exit; }
    if (!empty($password)) {
      $dec = Crypto::decrypt($data, $password);
      if ($dec === false) {
        @unlink($thumbpath);
        Base::memzero($password); Crypto::clear_cache();
        http_response_code(404); exit;
      }
      $data = $dec;
    }
    header('Content-Type: image/jpeg');
    header('Content-Length: ' . strlen($data));
    echo $data;
    Base::memzero($password); Crypto::clear_cache();
    exit;
  }

  public static function handle_publish(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['publish'])) return;
    if (!Base::csrf_verify()) return;
    $filename   = Base::str_clean($_POST['publish']);
    if (!Files::is_known($filename)) return;
    $filepath   = Base::data_path('files/' . $filename);
    $markerPath = S3::marker_path($filename);
    $isS3       = !file_exists($filepath) && file_exists($markerPath);
    if (!$isS3 && !file_exists($filepath)) return;

    $password = Base::enc_key();
    if ($password === '') return;

    $pubPath = Files::public_path($filename);
    $pubDir  = dirname($pubPath);
    if (!is_dir($pubDir)) mkdir($pubDir, 0755, true);
    self::protect_public_dir();

    if ($isS3) {
      if (!S3::is_configured()) { Base::memzero($password); return; }
      $marker  = S3::read_marker($filename);
      $s3Key   = is_array($marker) ? (string)($marker['key'] ?? $filename) : $filename;
      $tmpPath = tempnam(sys_get_temp_dir(), 'dd_s3pub_');
      if (!S3::download_to_file($s3Key, $tmpPath)) { @unlink($tmpPath); Base::memzero($password); return; }
      $ok = Crypto::decrypt_to_path($tmpPath, $password, $pubPath);
      @unlink($tmpPath);
    } else {
      $ok = Crypto::decrypt_to_path($filepath, $password, $pubPath);
    }

    Base::memzero($password);
    if (!$ok) return;
    Base::audit('file_publish', hash('sha256', $filename));

    $back = $_POST['_redirect'] ?? ('/?file=' . urlencode($filename));
    if (!str_starts_with($back, '/') || str_starts_with($back, '//')) $back = '/';
    Base::redirect($back);
  }

  public static function handle_unpublish(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['unpublish'])) return;
    if (!Base::csrf_verify()) return;
    $filename = Base::str_clean($_POST['unpublish']);
    if (!Files::is_known($filename)) return;

    $pubPath = Files::public_path($filename);
    $pubDir  = dirname($pubPath);
    if (file_exists($pubPath)) {
      Base::audit('file_unpublish', hash('sha256', $filename));
      unlink($pubPath);
    }
    if (is_dir($pubDir)) @rmdir($pubDir);

    $back = $_POST['_redirect'] ?? ('/?file=' . urlencode($filename));
    if (!str_starts_with($back, '/') || str_starts_with($back, '//')) $back = '/';
    Base::redirect($back);
  }

  public static function handle_delete(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['delete'])) return;
    if (!Base::csrf_verify()) return;
    $filename = Base::str_clean($_POST['delete']);
    if (!Files::is_known($filename)) return;
    $filepath   = Base::data_path('files/' . $filename);
    $thumbpath  = Base::data_path('thumbs/' . $filename);
    $markerPath = S3::marker_path($filename);

    if (file_exists($markerPath)) {
      $marker = S3::read_marker($filename);
      Base::audit('file_delete', hash('sha256', $filename));
      if ($marker !== false && S3::is_configured()) {
        S3::delete_object((string)($marker['key'] ?? $filename));
        S3::update_s3_storage_bytes(-((int)($marker['size'] ?? 0)));
      }
      S3::delete_marker($filename);
    } elseif (file_exists($filepath)) {
      $filesize = (int)filesize($filepath);
      Base::audit('file_delete', hash('sha256', $filename));
      unlink($filepath);
      if ($filesize > 0) Upload::update_storage_bytes(-$filesize);
    }
    if (file_exists($thumbpath)) unlink($thumbpath);
    $markerpath = $thumbpath . '.webmaudio';
    if (file_exists($markerpath)) unlink($markerpath);
    $tagsDir = Base::data_path('tags');
    if (is_dir($tagsDir)) {
      $escaped = addcslashes($filename, '*?[\\');
      foreach (glob("{$tagsDir}/*/{$escaped}.txt") as $tagFile) {
        unlink($tagFile);
      }
    }
    $pubPath = Files::public_path($filename);
    $pubDir  = dirname($pubPath);
    if (file_exists($pubPath)) unlink($pubPath);
    if (is_dir($pubDir)) @rmdir($pubDir);
    $back = $_POST['_redirect'] ?? '/';
    if (!str_starts_with($back, '/') || str_starts_with($back, '//')) $back = '/';
    Base::redirect($back);
  }

  public static function handle_bulk_delete(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['bulk_delete'])) return;
    if (!Base::csrf_verify()) return;
    $files = is_array($_POST['bulk_delete']) ? $_POST['bulk_delete'] : [];
    if (empty($files) || count($files) > 500) return;
    foreach ($files as $raw) {
      if (!is_string($raw) || strlen($raw) > 512) continue;
      $filename = Base::str_clean($raw);
      if (!Files::is_known($filename)) continue;
      $filepath   = Base::data_path('files/' . $filename);
      $thumbpath  = Base::data_path('thumbs/' . $filename);
      $markerPath = S3::marker_path($filename);
      if (file_exists($markerPath)) {
        $marker = S3::read_marker($filename);
        Base::audit('file_delete', hash('sha256', $filename));
        if ($marker !== false && S3::is_configured()) {
          S3::delete_object((string)($marker['key'] ?? $filename));
          S3::update_s3_storage_bytes(-((int)($marker['size'] ?? 0)));
        }
        S3::delete_marker($filename);
      } elseif (file_exists($filepath)) {
        $filesize = (int)filesize($filepath);
        Base::audit('file_delete', hash('sha256', $filename));
        unlink($filepath);
        if ($filesize > 0) Upload::update_storage_bytes(-$filesize);
      }
      if (file_exists($thumbpath)) unlink($thumbpath);
      $markerpath = $thumbpath . '.webmaudio';
      if (file_exists($markerpath)) unlink($markerpath);
      $tagsDir = Base::data_path('tags');
      if (is_dir($tagsDir)) {
        $escaped = addcslashes($filename, '*?[\\');
        foreach (glob("{$tagsDir}/*/{$escaped}.txt") as $tagFile) {
          unlink($tagFile);
        }
      }
      $pubPath = Files::public_path($filename);
      $pubDir  = dirname($pubPath);
      if (file_exists($pubPath)) unlink($pubPath);
      if (is_dir($pubDir)) @rmdir($pubDir);
    }
    $back = $_POST['_redirect'] ?? '/';
    if (!str_starts_with($back, '/') || str_starts_with($back, '//')) $back = '/';
    Base::redirect($back);
  }

  public static function handle_edit_save(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['edit_save'])) return;
    if (!Base::csrf_verify()) return;
    $filename = Base::str_clean($_POST['edit_save']);
    if (!Files::is_known($filename)) return;
    $realName = Files::real_name($filename);
    if (!Base::is_editable($realName)) return;
    $filePath   = Base::data_path('files/' . $filename);
    $markerPath = S3::marker_path($filename);
    $isLocal    = is_file($filePath);
    $isS3       = !$isLocal && file_exists($markerPath);
    if (!$isLocal && !$isS3) return;

    if ($isLocal && filesize($filePath) > Base::INLINE_SIZE_LIMIT) return;
    if ($isS3) {
      $marker = S3::read_marker($filename);
      if ($marker === false) return;
      if ((int)($marker['plain_size'] ?? 0) > Base::INLINE_SIZE_LIMIT) return;
    }

    $contentLen = strlen($_POST['content'] ?? '');
    $content = $_POST['content'] ?? '';
    $encKey  = Base::enc_key();
    if ($encKey === '') return;
    $encrypted = Crypto::encrypt($content, $encKey);
    Base::memzero($encKey);
    Base::memzero($content);
    if ($encrypted === false) return;

    if ($isS3 && S3::is_configured()) {
      $marker  = $marker ?? S3::read_marker($filename);
      $s3Key   = is_array($marker) ? (string)($marker['key'] ?? $filename) : $filename;
      $oldSize = is_array($marker) ? (int)($marker['size'] ?? 0) : 0;
      $tmpNew  = tempnam(sys_get_temp_dir(), 'dd_s3ed_');
      file_put_contents($tmpNew, $encrypted);
      if (!S3::put_object($s3Key, $tmpNew)) { @unlink($tmpNew); return; }
      $newSize = (int)filesize($tmpNew);
      @unlink($tmpNew);
      S3::write_marker($filename, $s3Key, $newSize, $contentLen, false, '', 0);
      if ($newSize !== $oldSize) S3::update_s3_storage_bytes($newSize - $oldSize);
    } else {
      $oldSize = (int)filesize($filePath);
      file_put_contents($filePath, $encrypted);
      $newSize = (int)filesize($filePath);
      if ($newSize !== $oldSize) Upload::update_storage_bytes($newSize - $oldSize);
    }

    $thumbPath = Base::data_path('thumbs/' . $filename);
    if (is_file($thumbPath)) @unlink($thumbPath);
    $ctx = array_filter([
      'file' => $filename,
      'tag'  => isset($_POST['_tag'])  ? Base::str_clean($_POST['_tag'])  : null,
      'type' => isset($_POST['_type']) ? Base::str_clean($_POST['_type']) : null,
    ], fn($v) => $v !== null && $v !== '');
    Base::redirect(Base::url($ctx));
  }

  public static function handle_create_file(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['create_file'])) return;
    if (!Base::csrf_verify()) return;
    $raw = (string)$_POST['create_file'];
    if (str_contains($raw, "\0")) return;
    $cleanName = Base::str_clean(basename($raw));
    if (empty($cleanName)) return;
    $ext = strtolower(pathinfo($cleanName, PATHINFO_EXTENSION));
    if ($ext === '') { $cleanName .= '.txt'; $ext = 'txt'; }
    if (!in_array($ext, Base::EXT_EDITABLE, true)) return;
    $encKey = Base::enc_key();
    if ($encKey === '') return;
    $encName = Crypto::encrypt_filename($cleanName, $encKey);
    if ($encName === false) { Base::memzero($encKey); return; }
    $filename = date('Ymd-His') . '-' . $encName;
    $filePath = Base::data_path('files/' . $filename);
    $encrypted = Crypto::encrypt('', $encKey);
    Base::memzero($encKey);
    Crypto::clear_cache();
    if ($encrypted === false) return;
    if (!Upload::check_storage_quota(strlen($encrypted))) return;
    file_put_contents($filePath, $encrypted, LOCK_EX);
    Upload::update_storage_bytes((int)filesize($filePath));
    Base::audit('file_create', hash('sha256', $filename));
    $tag  = isset($_POST['_tag'])  ? Base::str_clean($_POST['_tag'])  : null;
    $type = isset($_POST['_type']) ? Base::str_clean($_POST['_type']) : null;
    if ($tag !== null && $tag !== '') Base::set_tag($filename, $tag);
    $ctx = array_filter(['file' => $filename, 'tag' => $tag, 'type' => $type], fn($v) => $v !== null && $v !== '');
    Base::redirect(Base::url($ctx) . '&edit=1');
  }

  public static function handle_zip(): void {
    if (!isset($_GET['zip'])) return;
    $password = Base::enc_key();
    if (empty($password)) { http_response_code(403); Base::memzero($password); Crypto::clear_cache(); exit; }
    session_write_close();

    $files = Files::filtered_files();
    $selectedFiles = !empty($_POST['files']) && is_array($_POST['files']) ? $_POST['files']
                   : (!empty($_GET['files']) && is_array($_GET['files']) ? $_GET['files'] : []);
    if (!empty($selectedFiles)) {
      $allowed = array_flip($files);
      $subset = [];
      foreach ($selectedFiles as $f) {
        if (!is_string($f) || $f === '') continue;
        if (isset($allowed[$f])) $subset[] = $f;
      }
      $files = $subset;
    }
    if (empty($files)) { http_response_code(204); Base::memzero($password); Crypto::clear_cache(); exit; }

    $tag  = isset($_GET['tag'])  ? Base::str_clean($_GET['tag'])  : '';
    $type = isset($_GET['type']) ? Base::str_clean($_GET['type']) : '';
    $selCount = !empty($selectedFiles) ? count($files) : 0;
    $parts   = array_filter([
      $selCount ? $selCount . '-files' : '',
      $type ? preg_replace('/[^\w-]/', '', $type) : '',
      $tag  ? preg_replace('/[^\w-]/', '', $tag)  : '',
    ]);
    $zipName = 'darkdrive-' . (empty($parts) ? 'all-files' : implode('-', $parts)) . '.zip';

    set_time_limit(max(300, min(count($files) * 30, 3600)));
    if (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $zipName . '"');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');

    $centralDir = '';
    $offset     = 0;
    $count      = 0;
    $useZip64   = false;

    foreach ($files as $filename) {
      $filepath   = Base::data_path('files/' . $filename);
      $markerPath = S3::marker_path($filename);
      $isS3       = !file_exists($filepath) && file_exists($markerPath);
      if (!$isS3 && (!file_exists($filepath) || !is_file($filepath))) continue;

      $realName    = Files::real_name($filename);
      $mtime       = (int)filemtime($isS3 ? $markerPath : $filepath);
      [$dosTime, $dosDate] = self::zip_dos_datetime($mtime);
      $localOffset = $offset;

      $localHdr = self::zip_local_header($realName, $dosTime, $dosDate);
      echo $localHdr;
      $offset += strlen($localHdr);

      $crcCtx   = hash_init('crc32b');
      $fileSize = 0;

      if ($isS3 && S3::is_configured()) {
        $marker = S3::read_marker($filename);
        $s3Key  = is_array($marker) ? (string)($marker['key'] ?? $filename) : $filename;
        $stream = S3::get_object_stream($s3Key);
        if ($stream !== false) {
          if (!empty($marker['chunked'])) {
            $ok = Crypto::decrypt_chunked_with_callback_fh($stream, $password, function (string $plain) use (&$crcCtx, &$fileSize): void {
              hash_update($crcCtx, $plain);
              $fileSize += strlen($plain);
              echo $plain;
              if (ob_get_level() > 0) ob_flush();
              flush();
            });
            if (!$ok) {
              $recovery = Base::emergency_recovery_password();
              if ($recovery !== null) {
                fclose($stream);
                $stream = S3::get_object_stream($s3Key);
                if ($stream !== false) {
                  $crcCtx = hash_init('crc32b');
                  $fileSize = 0;
                  Crypto::decrypt_chunked_with_callback_fh($stream, $recovery, function (string $plain) use (&$crcCtx, &$fileSize): void {
                    hash_update($crcCtx, $plain);
                    $fileSize += strlen($plain);
                    echo $plain;
                    if (ob_get_level() > 0) ob_flush();
                    flush();
                  });
                }
              }
            }
          } else {
            $enc = stream_get_contents($stream);
            if ($enc !== false) {
              $plain = Crypto::decrypt($enc, $password);
              if ($plain === false) {
                $recovery = Base::emergency_recovery_password();
                if ($recovery !== null) $plain = Crypto::decrypt($enc, $recovery);
              }
              if ($plain !== false) {
                hash_update($crcCtx, $plain);
                $fileSize = strlen($plain);
                echo $plain;
                flush();
              }
            }
          }
          fclose($stream);
        }
      } elseif (!$isS3) {
        if (Crypto::is_chunked($filepath)) {
          $ok = Crypto::decrypt_chunked_with_callback($filepath, $password, function (string $plain) use (&$crcCtx, &$fileSize): void {
            hash_update($crcCtx, $plain);
            $fileSize += strlen($plain);
            echo $plain;
            if (ob_get_level() > 0) ob_flush();
            flush();
          });
          if (!$ok) {
            $recovery = Base::emergency_recovery_password();
            if ($recovery !== null) {
              $crcCtx = hash_init('crc32b');
              $fileSize = 0;
              Crypto::decrypt_chunked_with_callback($filepath, $recovery, function (string $plain) use (&$crcCtx, &$fileSize): void {
                hash_update($crcCtx, $plain);
                $fileSize += strlen($plain);
                echo $plain;
                if (ob_get_level() > 0) ob_flush();
                flush();
              });
            }
          }
        } else {
          $raw = file_get_contents($filepath);
          if ($raw !== false) {
            $plain = Crypto::decrypt($raw, $password);
            if ($plain === false) {
              $recovery = Base::emergency_recovery_password();
              if ($recovery !== null) $plain = Crypto::decrypt($raw, $recovery);
            }
            if ($plain !== false) {
              hash_update($crcCtx, $plain);
              $fileSize = strlen($plain);
              echo $plain;
              flush();
            }
          }
        }
      }

      if ($fileSize > 0xFFFFFFFF || $offset > 0xFFFFFFFF) $useZip64 = true;

      $offset += $fileSize;
      $crc32   = hexdec(hash_final($crcCtx));

      $dataDesc = self::zip_data_descriptor($crc32, $fileSize);
      echo $dataDesc;
      $offset += strlen($dataDesc);

      $centralDir .= self::zip_central_entry($realName, $dosTime, $dosDate, $crc32, $fileSize, $localOffset);
      $count++;
    }

    $cdOffset = $offset;
    echo $centralDir;

    if ($useZip64) {
      $cdSize = strlen($centralDir);
      echo self::zip64_eocd($count, $cdSize, $cdOffset);
      echo self::zip64_eocd_locator($cdOffset + $cdSize);
    }

    echo self::zip_eocd(
      $useZip64 ? 0xFFFF : $count,
      $useZip64 ? 0xFFFFFFFF : strlen($centralDir),
      $useZip64 ? 0xFFFFFFFF : $cdOffset
    );

    Base::memzero($password);
    Crypto::clear_cache();
    exit;
  }

  private static function zip_dos_datetime(int $mtime): array {
    $dt   = getdate($mtime);
    $year = max(1980, $dt['year']);
    return [
      ($dt['hours'] << 11) | ($dt['minutes'] << 5) | (int)($dt['seconds'] / 2),
      (($year - 1980) << 9) | ($dt['mon'] << 5) | $dt['mday'],
    ];
  }

  private static function zip_local_header(string $name, int $dosTime, int $dosDate): string {
    return pack('VvvvvvVVVvv',
      0x04034b50, 20, 0x0808, 0,
      $dosTime, $dosDate,
      0, 0, 0,
      strlen($name), 0
    ) . $name;
  }

  private static function zip_data_descriptor(int $crc32, int $size): string {
    if ($size > 0xFFFFFFFF) {
      return pack('VV', 0x08074b50, $crc32 & 0xFFFFFFFF)
        . pack('P', $size) . pack('P', $size);
    }
    return pack('VVVV', 0x08074b50, $crc32 & 0xFFFFFFFF, $size, $size);
  }

  private static function zip_central_entry(string $name, int $dosTime, int $dosDate, int $crc32, int $size, int $offset): string {
    if ($size > 0xFFFFFFFF || $offset > 0xFFFFFFFF) {
      $extra = pack('vv', 0x0001, 24) . pack('P', $size) . pack('P', $size) . pack('P', $offset);
      return pack('VvvvvvvVVVvvvvvVV',
        0x02014b50, 0x032D, 45, 0x0808, 0,
        $dosTime, $dosDate,
        $crc32 & 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        strlen($name), strlen($extra), 0, 0, 0, 0, 0xFFFFFFFF
      ) . $name . $extra;
    }
    return pack('VvvvvvvVVVvvvvvVV',
      0x02014b50, 0x0314, 20, 0x0808, 0,
      $dosTime, $dosDate,
      $crc32 & 0xFFFFFFFF, $size, $size,
      strlen($name), 0, 0, 0, 0, 0, $offset
    ) . $name;
  }

  private static function zip64_eocd(int $count, int $cdSize, int $cdOffset): string {
    return pack('V', 0x06064b50)
      . pack('P', 44)
      . pack('vv', 0x032D, 45)
      . pack('VV', 0, 0)
      . pack('P', $count) . pack('P', $count)
      . pack('P', $cdSize)
      . pack('P', $cdOffset);
  }

  private static function zip64_eocd_locator(int $zip64EocdOffset): string {
    return pack('V', 0x07064b50)
      . pack('V', 0)
      . pack('P', $zip64EocdOffset)
      . pack('V', 1);
  }

  private static function zip_eocd(int $count, int $cdSize, int $cdOffset): string {
    return pack('VvvvvVVv', 0x06054b50, 0, 0,
      min($count, 0xFFFF), min($count, 0xFFFF),
      min($cdSize, 0xFFFFFFFF), min($cdOffset, 0xFFFFFFFF), 0);
  }

}
