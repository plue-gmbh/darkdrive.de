<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// S3 — AWS S3-compatible object storage client for Darkdrive
//
//   Uses AWS Signature V4 with raw HTTP (no SDK dependency).
//   Hetzner Object Storage compatible (path-style URLs).
//   Marker files (.s3) track which files live on S3.
//   All encrypted blobs pass through unchanged — zero knowledge.
//
//   Constants (in index.php):
//     DARKDRIVE_S3_ENDPOINT   — e.g. 'https://fsn1.your-objectstorage.com'
//     DARKDRIVE_S3_BUCKET     — e.g. 'darkdrive-files'
//     DARKDRIVE_S3_ACCESS_KEY — S3 access key
//     DARKDRIVE_S3_SECRET_KEY — S3 secret key
//     DARKDRIVE_S3_REGION     — e.g. 'fsn1' (default: 'us-east-1')
//     DARKDRIVE_S3_MAX_STORAGE — quota in MB (0 = unlimited)
//

class S3 {

  public static function is_configured(): bool {
    return defined('DARKDRIVE_S3_BUCKET') && DARKDRIVE_S3_BUCKET !== '';
  }

  private static function endpoint(): string {
    return rtrim(DARKDRIVE_S3_ENDPOINT, '/');
  }

  private static function bucket(): string {
    return DARKDRIVE_S3_BUCKET;
  }

  private static function access_key(): string {
    return DARKDRIVE_S3_ACCESS_KEY;
  }

  private static function secret_key(): string {
    return DARKDRIVE_S3_SECRET_KEY;
  }

  private static function region(): string {
    return defined('DARKDRIVE_S3_REGION') ? DARKDRIVE_S3_REGION : 'us-east-1';
  }

  private static function encode_s3_path(string $key): string {
    if ($key === '') return '';
    $segments = explode('/', $key);
    $encoded = [];
    foreach ($segments as $seg) {
      $encoded[] = rawurlencode($seg);
    }
    return implode('/', $encoded);
  }

  private static function sign(
    string $method,
    string $key,
    array  $extra_headers = [],
    string $payload_hash  = 'UNSIGNED-PAYLOAD'
  ): array {
    $datetime = gmdate('Ymd\THis\Z');
    $date     = substr($datetime, 0, 8);
    $region   = self::region();
    $parsed   = parse_url(self::endpoint());
    $host     = $parsed['host'];
    $bucket   = self::bucket();
    $encoded_key = self::encode_s3_path($key);
    $path     = '/' . $bucket . ($encoded_key !== '' ? '/' . ltrim($encoded_key, '/') : '');

    $headers = [
      'host'                 => $host,
      'x-amz-content-sha256' => $payload_hash,
      'x-amz-date'           => $datetime,
    ];
    foreach ($extra_headers as $k => $v) {
      $headers[strtolower($k)] = trim((string)$v);
    }
    ksort($headers);

    $canonical_headers = '';
    foreach ($headers as $k => $v) {
      $canonical_headers .= $k . ':' . $v . "\n";
    }
    $signed_headers = implode(';', array_keys($headers));

    $canonical_request = implode("\n", [
      $method,
      $path,
      '',
      $canonical_headers,
      $signed_headers,
      $payload_hash,
    ]);

    $scope          = "$date/$region/s3/aws4_request";
    $string_to_sign = implode("\n", [
      'AWS4-HMAC-SHA256',
      $datetime,
      $scope,
      hash('sha256', $canonical_request),
    ]);

    $secret = self::secret_key();
    $signing_key = hash_hmac('sha256', 'aws4_request',
      hash_hmac('sha256', 's3',
        hash_hmac('sha256', $region,
          hash_hmac('sha256', $date, 'AWS4' . $secret, true),
        true),
      true),
    true);
    Base::memzero($secret);

    $signature     = hash_hmac('sha256', $string_to_sign, $signing_key);
    Base::memzero($signing_key);
    $authorization = "AWS4-HMAC-SHA256 Credential=" . self::access_key() . "/$scope, SignedHeaders=$signed_headers, Signature=$signature";

    $all_headers                  = $headers;
    $all_headers['authorization'] = $authorization;

    return ['url' => self::endpoint() . $path, 'headers' => $all_headers];
  }

  private static function do_curl(
    string  $method,
    string  $key,
    array   $extra_headers = [],
    ?string $put_path      = null,
    ?string $put_body      = null
  ): array {
    $payload_hash = 'UNSIGNED-PAYLOAD';
    if ($method === 'PUT' && $put_path !== null) {
      if (!is_file($put_path) || !is_readable($put_path)) {
        return ['code' => 0, 'error' => 'Local file not accessible: ' . basename($put_path), 'body' => '', 'raw_headers' => ''];
      }
      $payload_hash = hash_file('sha256', $put_path);
      if ($payload_hash === false) {
        return ['code' => 0, 'error' => 'Failed to hash file: ' . basename($put_path), 'body' => '', 'raw_headers' => ''];
      }
    } elseif ($method === 'PUT' && $put_body !== null) {
      $payload_hash = hash('sha256', $put_body);
    }

    $signed = self::sign($method, $key, $extra_headers, $payload_hash);

    $ch = curl_init($signed['url']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 300);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

    $header_lines = [];
    foreach ($signed['headers'] as $k => $v) {
      $header_lines[] = "$k: $v";
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $header_lines);

    $put_fh = null;
    if ($method === 'PUT') {
      if ($put_path !== null) {
        $put_fh = fopen($put_path, 'rb');
        if ($put_fh === false) {
          curl_close($ch);
          return ['code' => 0, 'error' => 'Cannot open file: ' . basename($put_path), 'body' => '', 'raw_headers' => ''];
        }
        curl_setopt($ch, CURLOPT_PUT, true);
        curl_setopt($ch, CURLOPT_INFILE, $put_fh);
        curl_setopt($ch, CURLOPT_INFILESIZE, (int)filesize($put_path));
      } elseif ($put_body !== null) {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($ch, CURLOPT_POSTFIELDS, $put_body);
      } else {
        curl_setopt($ch, CURLOPT_PUT, true);
        curl_setopt($ch, CURLOPT_INFILESIZE, 0);
      }
    } elseif ($method === 'DELETE') {
      curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
    } elseif ($method === 'HEAD') {
      curl_setopt($ch, CURLOPT_NOBODY, true);
    }

    $response    = curl_exec($ch);
    $http_code   = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $header_size = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $curl_error  = curl_error($ch);
    curl_close($ch);
    if ($put_fh !== null) fclose($put_fh);

    if ($response === false) {
      return ['code' => 0, 'error' => $curl_error, 'body' => '', 'raw_headers' => ''];
    }
    return [
      'code'        => $http_code,
      'body'        => substr($response, $header_size),
      'raw_headers' => substr($response, 0, $header_size),
      'error'       => '',
    ];
  }

  private static function open_stream(string $method, string $key, array $extra_headers = []): mixed {
    $signed = self::sign($method, $key, $extra_headers, 'UNSIGNED-PAYLOAD');

    $header_lines = [];
    foreach ($signed['headers'] as $k => $v) {
      $header_lines[] = "$k: $v";
    }

    $ctx = stream_context_create([
      'http' => [
        'method'        => $method,
        'header'        => implode("\r\n", $header_lines),
        'ignore_errors' => true,
        'timeout'       => 300,
      ],
      'ssl' => [
        'verify_peer'      => true,
        'verify_peer_name' => true,
      ],
    ]);

    $stream = @fopen($signed['url'], 'rb', false, $ctx);
    if ($stream === false) return false;

    if (isset($http_response_header) && is_array($http_response_header)) {
      $status_line = $http_response_header[0] ?? '';
      if (!preg_match('/^HTTP\/\S+\s+(2\d\d)/', $status_line)) {
        fclose($stream);
        return false;
      }
    }

    return $stream;
  }

  private static ?string $lastError = null;

  public static function last_error(): ?string { return self::$lastError; }

  public static function put_object(string $key, string $local_path): bool {
    self::$lastError = null;
    if (!is_file($local_path) || !is_readable($local_path)) {
      self::$lastError = 'Local file not accessible';
      return false;
    }
    $size = filesize($local_path);
    if ($size === false) {
      self::$lastError = 'Cannot determine file size';
      return false;
    }
    $r = self::do_curl('PUT', $key, ['content-length' => (string)$size], $local_path);
    if ($r['code'] >= 200 && $r['code'] < 300) return true;
    self::$lastError = $r['error'] ?: ('HTTP ' . $r['code']);
    error_log('Darkdrive S3 PUT failed for key (' . $size . ' bytes): ' . self::$lastError);
    return false;
  }

  public static function get_object_stream(string $key): mixed {
    return self::open_stream('GET', $key);
  }

  public static function get_range_stream(string $key, int $start, int $end): mixed {
    return self::open_stream('GET', $key, ['range' => "bytes=$start-$end"]);
  }

  public static function delete_object(string $key): bool {
    $r = self::do_curl('DELETE', $key);
    return $r['code'] >= 200 && $r['code'] < 300;
  }

  public static function head_object(string $key): int|false {
    $r = self::do_curl('HEAD', $key);
    if ($r['code'] !== 200) return false;
    if (preg_match('/content-length:\s*(\d+)/i', $r['raw_headers'], $m)) {
      return (int)$m[1];
    }
    return false;
  }

  public static function head_bucket(): bool {
    $r = self::do_curl('HEAD', '');
    return $r['code'] >= 200 && $r['code'] < 300;
  }

  public static function download_to_file(string $key, string $localPath): bool {
    $stream = self::get_object_stream($key);
    if ($stream === false) return false;
    $fh = fopen($localPath, 'wb');
    if (!$fh) { fclose($stream); return false; }
    $copied = stream_copy_to_stream($stream, $fh);
    fclose($fh);
    fclose($stream);
    if ($copied === false || $copied === 0) {
      @unlink($localPath);
      return false;
    }
    return true;
  }

  public static function marker_path(string $filename): string {
    return Base::data_path('files/' . $filename . '.s3');
  }

  private static array $marker_required = ['key', 'size', 'plain_size', 'chunked', 'salt', 'chunk_size'];

  public static function read_marker(string $filename): array|false {
    $path = self::marker_path($filename);
    if (!is_file($path)) return false;
    $json = file_get_contents($path);
    if ($json === false) return false;
    $data = json_decode($json, true);
    if (!is_array($data)) return false;
    foreach (self::$marker_required as $field) {
      if (!array_key_exists($field, $data)) return false;
    }
    return $data;
  }

  public static function write_marker(
    string $filename,
    string $s3_key,
    int    $enc_size,
    int    $plain_size,
    bool   $chunked,
    string $salt_hex,
    int    $chunk_size
  ): void {
    file_put_contents(self::marker_path($filename), json_encode([
      'key'        => $s3_key,
      'size'       => $enc_size,
      'plain_size' => $plain_size,
      'chunked'    => $chunked,
      'salt'       => $salt_hex,
      'chunk_size' => $chunk_size,
    ]), LOCK_EX);
  }

  public static function delete_marker(string $filename): void {
    $path = self::marker_path($filename);
    if (file_exists($path)) unlink($path);
  }

  public static function s3_storage_bytes(): int {
    $counter = Base::data_path('.storage_bytes_s3');
    if (is_file($counter) && (time() - filemtime($counter)) > 3600) {
      $fh = @fopen($counter, 'c+');
      if ($fh && flock($fh, LOCK_EX)) {
        $val = self::recalc_s3_storage();
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, (string)$val);
        flock($fh, LOCK_UN);
        fclose($fh);
        return $val;
      }
      if ($fh) fclose($fh);
      return self::recalc_s3_storage();
    }
    $fh = @fopen($counter, 'c+');
    if (!$fh) return self::recalc_s3_storage();
    if (!flock($fh, LOCK_SH)) { fclose($fh); return self::recalc_s3_storage(); }
    $contents = stream_get_contents($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    $val = max(0, (int)trim($contents ?: '0'));
    if ($val === 0 && $contents !== false && trim($contents) === '0') return 0;
    return $val ?: self::recalc_s3_storage();
  }

  public static function update_s3_storage_bytes(int $delta): void {
    $counter = Base::data_path('.storage_bytes_s3');
    $fh = @fopen($counter, 'c+');
    if (!$fh) return;
    if (!flock($fh, LOCK_EX)) { fclose($fh); return; }
    $contents = stream_get_contents($fh);
    $current = max(0, (int)trim($contents ?: '0'));
    $needs_recalc = ($current === 0 && $delta > 0 && ($contents === false || trim($contents) !== '0'));
    if ($needs_recalc) $current = self::recalc_s3_storage();
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, (string)max(0, $current + $delta));
    flock($fh, LOCK_UN);
    fclose($fh);
  }

  public static function check_s3_quota(int $add_bytes): bool {
    $limit_mb = defined('DARKDRIVE_S3_MAX_STORAGE') ? (int)DARKDRIVE_S3_MAX_STORAGE : 0;
    $unlimited = $limit_mb <= 0;
    $counter = Base::data_path('.storage_bytes_s3');
    $fh = @fopen($counter, 'c+');
    if (!$fh) return $unlimited;
    if (!flock($fh, LOCK_EX)) { fclose($fh); return $unlimited; }
    $contents = stream_get_contents($fh);
    $current = max(0, (int)trim($contents ?: '0'));
    $needs_recalc = ($current === 0 && ($contents === false || trim($contents) !== '0'));
    if ($needs_recalc) $current = self::recalc_s3_storage();
    $limit = $limit_mb * 1024 * 1024;
    if (!$unlimited && $current + $add_bytes > $limit) {
      flock($fh, LOCK_UN);
      fclose($fh);
      return false;
    }
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, (string)($current + $add_bytes));
    flock($fh, LOCK_UN);
    fclose($fh);
    return true;
  }

  private static function recalc_s3_storage(): int {
    $total = 0;
    $dir   = Base::data_path('files');
    if (!is_dir($dir)) return 0;
    foreach (array_diff(scandir($dir), ['.', '..']) as $f) {
      if (!str_ends_with($f, '.s3')) continue;
      $marker = @json_decode(@file_get_contents($dir . '/' . $f), true);
      if (is_array($marker) && isset($marker['size'])) {
        $total += (int)$marker['size'];
      }
    }
    return $total;
  }

}
