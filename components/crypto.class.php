<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Crypto — AES-256-GCM encryption for Darkdrive
//
//   File format (DARKDRIVEV3):
//     Header:  MAGIC (11 B) | salt (16 B) | chunk_size (4 B) | plain_size (8 B)
//     Chunks:  cipher_len (4 B) | nonce (12 B) | tag (16 B) | ciphertext
//     AAD binds chunk index (V2+) plus plain_size and chunk_size (V3), so a
//     truncated or size-swapped blob fails to authenticate instead of decrypting
//     silently. V3 also verifies the decrypted total against the header.
//     V1 (no AAD) and V2 (index only) still decrypt unchanged.
//     The V3 header is byte-identical to V2 — only the magic differs.
//
//   Filenames:  PBKDF2-derived key (100k rounds, domain salt) + random nonce per name
//   Key split:  password encrypted into cookie, random share in session — neither alone decrypts
//   Zeroing:    all derived keys zeroed via sodium_memzero before return
//

class Crypto {

  const CHUNK_SIZE = 16 * 1024 * 1024;
  const MAGIC_V1   = "DARKDRIVEV1";
  const MAGIC_V2   = "DARKDRIVEV2";
  const MAGIC_V3   = "DARKDRIVEV3";

  private static function derive_key(string $password, string $salt): string {
    return hash_pbkdf2('sha256', $password, $salt, 100_000, 32, true);
  }

  private static function is_magic(string $magic): bool {
    return $magic === self::MAGIC_V1 || $magic === self::MAGIC_V2 || $magic === self::MAGIC_V3;
  }

  private static function chunk_aad(int $version, int $chunkIdx, int $plainSize, int $chunkSize): string {
    if ($version <= 1) return '';
    if ($version === 2) return pack('J', $chunkIdx);
    return pack('J', $chunkIdx) . pack('J', $plainSize) . pack('N', $chunkSize);
  }

  public static function encrypt(string $data, string $password): string|false {
    $salt = random_bytes(16);
    $key = self::derive_key($password, $salt);
    $nonce = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
    Base::memzero($key);
    if ($ciphertext === false) return false;
    return $salt . $nonce . $tag . $ciphertext;
  }

  public static function decrypt(string $data, string $password): string|false {
    if (strlen($data) < 44) return false;
    $salt       = substr($data, 0, 16);
    $nonce      = substr($data, 16, 12);
    $tag        = substr($data, 28, 16);
    $ciphertext = substr($data, 44);
    $key = self::derive_key($password, $salt);
    $result = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    Base::memzero($key);
    return $result;
  }

  public static function encrypt_stream(string $inPath, string $outPath, string $password): bool {
    $plainSize = filesize($inPath);
    if ($plainSize === false) return false;
    $in = fopen($inPath, 'rb');
    if (!$in) return false;
    $out = fopen($outPath, 'wb');
    if (!$out) { fclose($in); return false; }

    $salt = random_bytes(16);
    $key  = self::derive_key($password, $salt);

    $header = self::MAGIC_V3 . $salt . pack('N', self::CHUNK_SIZE) . pack('J', $plainSize);
    if (fwrite($out, $header) !== strlen($header)) {
      fclose($in); fclose($out); @unlink($outPath); Base::memzero($key); return false;
    }

    $chunkIdx = 0;
    while (!feof($in)) {
      $plain = fread($in, self::CHUNK_SIZE);
      if ($plain === false || $plain === '') break;
      $nonce = random_bytes(12);
      $tag   = '';
      $aad   = self::chunk_aad(3, $chunkIdx, $plainSize, self::CHUNK_SIZE);
      $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
      if ($cipher === false) { fclose($in); fclose($out); @unlink($outPath); Base::memzero($key); return false; }
      $chunk = pack('N', strlen($cipher)) . $nonce . $tag . $cipher;
      if (fwrite($out, $chunk) !== strlen($chunk)) { fclose($in); fclose($out); @unlink($outPath); Base::memzero($key); return false; }
      $chunkIdx++;
    }

    fclose($in);
    fclose($out);
    Base::memzero($key);
    return true;
  }

  public static function is_chunked(string $filepath): bool {
    $fh = fopen($filepath, 'rb');
    if (!$fh) return false;
    $magic = fread($fh, strlen(self::MAGIC_V1));
    fclose($fh);
    return $magic !== false && self::is_magic($magic);
  }

  public static function is_encrypted(string $filepath): bool {
    $fh = fopen($filepath, 'rb');
    if (!$fh) return false;
    $head = fread($fh, max(strlen(self::MAGIC_V1), 44));
    fclose($fh);
    if ($head === false || $head === '') return false;
    if (self::is_magic(substr($head, 0, strlen(self::MAGIC_V1)))) return true;
    if (strlen($head) < 44) return false;
    if (ctype_print(substr($head, 0, 44))) return false;
    return true;
  }

  public static function chunked_plain_size(string $filepath): int|false {
    $fh = fopen($filepath, 'rb');
    if (!$fh) return false;
    $hdr = fread($fh, 39);
    $mlen = strlen(self::MAGIC_V1);
    if (strlen($hdr) < 39 || !self::is_magic(substr($hdr, 0, $mlen))) { fclose($fh); return false; }
    $stored = unpack('J', substr($hdr, 31, 8))[1];
    if ($stored > 0) { fclose($fh); return $stored; }
    $total = 0;
    while (!feof($fh)) {
      $lenRaw = fread($fh, 4);
      if (!$lenRaw || strlen($lenRaw) < 4) break;
      $cipherLen = unpack('N', $lenRaw)[1];
      if ($cipherLen === 0) break;
      $total += $cipherLen;
      fseek($fh, 12 + 16 + $cipherLen, SEEK_CUR);
    }
    fclose($fh);
    return $total;
  }

  private static function fread_exact(mixed $fh, int $n): string|false {
    $buf = '';
    while (strlen($buf) < $n) {
      $chunk = fread($fh, $n - strlen($buf));
      if ($chunk === false || $chunk === '') return false;
      $buf .= $chunk;
    }
    return $buf;
  }

  private static function decrypt_chunked_core_fh(mixed $fh, string $password, callable $onChunk): bool {
    $mlen  = strlen(self::MAGIC_V1);
    $magic = self::fread_exact($fh, $mlen);
    if ($magic === false || !self::is_magic($magic)) return false;
    $version = $magic === self::MAGIC_V3 ? 3 : ($magic === self::MAGIC_V2 ? 2 : 1);

    $salt      = self::fread_exact($fh, 16);
    $chunkMeta = self::fread_exact($fh, 12);
    if ($salt === false || strlen($salt) < 16 || $chunkMeta === false || strlen($chunkMeta) < 12) return false;

    $chunkSize = unpack('N', substr($chunkMeta, 0, 4))[1];
    $plainSize = unpack('J', substr($chunkMeta, 4, 8))[1];
    if ($chunkSize === 0 || $chunkSize > self::CHUNK_SIZE * 2) return false;
    $key = self::derive_key($password, $salt);

    $chunkIdx = 0;
    $seen     = 0;
    while (true) {
      $lenRaw = self::fread_exact($fh, 4);
      if ($lenRaw === false) break;
      $cipherLen = unpack('N', $lenRaw)[1];
      if ($cipherLen === 0 || $cipherLen > $chunkSize + 32) { Base::memzero($key); return false; }
      $nonce  = self::fread_exact($fh, 12);
      $tag    = self::fread_exact($fh, 16);
      $cipher = self::fread_exact($fh, $cipherLen);
      if ($nonce === false || $tag === false || $cipher === false) { Base::memzero($key); return false; }
      $aad   = self::chunk_aad($version, $chunkIdx, $plainSize, $chunkSize);
      $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
      if ($plain === false) { Base::memzero($key); return false; }
      $seen += strlen($plain);
      $cbResult = $onChunk($plain);
      if ($cbResult === false) { Base::memzero($key); return false; }
      if ($cbResult === true) { Base::memzero($key); return true; }
      $chunkIdx++;
    }

    Base::memzero($key);
    if ($version >= 3 && $seen !== $plainSize) return false;
    return true;
  }

  private static function decrypt_chunked_core(string $filepath, string $password, callable $onChunk): bool {
    $fh = fopen($filepath, 'rb');
    if (!$fh) return false;
    $result = self::decrypt_chunked_core_fh($fh, $password, $onChunk);
    fclose($fh);
    return $result;
  }

  public static function decrypt_chunked_output(string $filepath, string $password): bool {
    return self::decrypt_chunked_core($filepath, $password, function (string $plain): void {
      echo $plain;
      if (ob_get_level() > 0) ob_flush();
      flush();
    });
  }

  public static function decrypt_chunked_with_callback(string $filepath, string $password, callable $onChunk): bool {
    return self::decrypt_chunked_core($filepath, $password, $onChunk);
  }

  public static function decrypt_chunked_output_range(string $filepath, string $password, int $rangeStart, int $rangeEnd): void {
    $plainOffset = 0;
    self::decrypt_chunked_core($filepath, $password, function (string $plain) use (&$plainOffset, $rangeStart, $rangeEnd): ?bool {
      $chunkSize = strlen($plain);
      $chunkEnd  = $plainOffset + $chunkSize - 1;
      if ($chunkEnd < $rangeStart) { $plainOffset += $chunkSize; return null; }
      if ($plainOffset > $rangeEnd) { return true; }
      $outStart = max($plainOffset, $rangeStart) - $plainOffset;
      $outEnd   = min($chunkEnd, $rangeEnd) - $plainOffset;
      echo substr($plain, $outStart, $outEnd - $outStart + 1);
      if (ob_get_level() > 0) ob_flush();
      flush();
      $plainOffset += $chunkSize;
      return $plainOffset > $rangeEnd ? true : null;
    });
  }

  public static function decrypt_chunked_to_string(string $filepath, string $password): string|false {
    $result = '';
    $ok = self::decrypt_chunked_core($filepath, $password, function (string $plain) use (&$result): void {
      $result .= $plain;
    });
    return $ok ? $result : false;
  }

  private ?string $fnKey     = null;
  private string  $fnKeyHash = '';

  private static ?self $instance = null;
  private static function inst(): self { return self::$instance ??= new self(); }

  public static function clear_cache(): void {
    if (self::$instance === null) return;
    if (self::$instance->fnKeyHash !== '') {
      Base::memzero(self::$instance->fnKeyHash);
    }
    if (self::$instance->fnKey !== null) {
      Base::memzero(self::$instance->fnKey);
      self::$instance->fnKey = null;
    }
  }

  private static function filename_key(string $password): string {
    $i = self::inst();
    $pwHash = hash('sha256', $password, true);
    if ($i->fnKey === null || !hash_equals($i->fnKeyHash, $pwHash)) {
      $i->fnKey     = hash_pbkdf2('sha256', $password, 'darkdrive-filename-v1', 100_000, 32, true);
      $i->fnKeyHash = $pwHash;
    }
    Base::memzero($pwHash);
    return $i->fnKey;
  }

  public static function encrypt_filename(string $name, string $password): string|false {
    $key   = self::filename_key($password);
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt($name, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
    if ($ct === false) return false;
    return rtrim(strtr(base64_encode($nonce . $tag . $ct), '+/', '-_'), '=');
  }

  public static function decrypt_filename(string $encoded, string $password, bool &$was_legacy = false): string|false {
    $pad = (4 - strlen($encoded) % 4) % 4;
    $raw = base64_decode(strtr($encoded . str_repeat('=', $pad), '-_', '+/'));
    if ($raw === false || strlen($raw) < 28) return false;
    $nonce  = substr($raw, 0, 12);
    $tag    = substr($raw, 12, 16);
    $ct     = substr($raw, 28);
    $key    = self::filename_key($password);
    $result = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($result !== false) { $was_legacy = false; return $result; }
    $legacyKey = hash_pbkdf2('sha256', $password, 'darkdrive-filename-v1', 10_000, 32, true);
    $result = openssl_decrypt($ct, 'aes-256-gcm', $legacyKey, OPENSSL_RAW_DATA, $nonce, $tag);
    Base::memzero($legacyKey);
    if ($result !== false) { $was_legacy = true; }
    return $result;
  }

  public static function decrypt_to_path(string $filepath, string $password, string $outPath): bool {
    if (self::is_chunked($filepath)) {
      $out = fopen($outPath, 'wb');
      if (!$out) return false;
      $ok = self::decrypt_chunked_core($filepath, $password, function (string $plain) use ($out): bool|null {
        return fwrite($out, $plain) === strlen($plain) ? null : false;
      });
      fclose($out);
      if (!$ok) { @unlink($outPath); }
      return $ok;
    }
    $data = file_get_contents($filepath);
    if ($data === false) return false;
    $dec = self::decrypt($data, $password);
    if ($dec === false) return false;
    return file_put_contents($outPath, $dec) !== false;
  }

  public static function verify_decrypt(string $filepath, string $password): bool {
    if (self::is_chunked($filepath)) {
      return self::decrypt_chunked_core($filepath, $password, function (string $plain): void {});
    }
    $data = file_get_contents($filepath);
    if ($data === false) return false;
    return self::decrypt($data, $password) !== false;
  }

  public static function test_chunked_key(string $filepath, string $password): bool {
    if (!self::is_chunked($filepath)) return false;
    return self::decrypt_chunked_core($filepath, $password, fn() => true);
  }

  public static function decrypt_filename_unwrap(string $encoded, string $password): string|false {
    $dec = self::decrypt_filename($encoded, $password);
    if ($dec === false) return false;
    $inner = self::decrypt_filename($dec, $password);
    return $inner !== false ? $inner : $dec;
  }

  public static function decrypt_any_to_string(string $filepath, string $password): string|false {
    if (self::is_chunked($filepath)) {
      return self::decrypt_chunked_to_string($filepath, $password);
    }
    $data = file_get_contents($filepath);
    if ($data === false) return false;
    return self::decrypt($data, $password);
  }

  public static function decrypt_chunked_with_callback_fh(mixed $fh, string $password, callable $onChunk): bool {
    return self::decrypt_chunked_core_fh($fh, $password, $onChunk);
  }

  public static function chunked_plain_size_fh(mixed $fh): int|false {
    $mlen = strlen(self::MAGIC_V1);
    $magic = self::fread_exact($fh, $mlen);
    if ($magic === false || !self::is_magic($magic)) return false;
    $salt = self::fread_exact($fh, 16);
    $meta = self::fread_exact($fh, 12);
    if ($salt === false || $meta === false || strlen($meta) < 12) return false;
    $stored = unpack('J', substr($meta, 4, 8))[1];
    return $stored > 0 ? $stored : false;
  }

  public static function is_chunked_fh(mixed $fh): bool {
    $magic = self::fread_exact($fh, strlen(self::MAGIC_V1));
    return $magic !== false && self::is_magic($magic);
  }

  public static function decrypt_chunked_output_fh(mixed $fh, string $password): bool {
    return self::decrypt_chunked_core_fh($fh, $password, function (string $plain): void {
      echo $plain;
      if (ob_get_level() > 0) ob_flush();
      flush();
    });
  }

  public static function decrypt_chunked_output_range_fh(mixed $fh, string $password, int $rangeStart, int $rangeEnd): void {
    $plainOffset = 0;
    self::decrypt_chunked_core_fh($fh, $password, function (string $plain) use (&$plainOffset, $rangeStart, $rangeEnd): ?bool {
      $chunkSize = strlen($plain);
      $chunkEnd  = $plainOffset + $chunkSize - 1;
      if ($chunkEnd < $rangeStart) { $plainOffset += $chunkSize; return null; }
      if ($plainOffset > $rangeEnd) { return true; }
      $outStart = max($plainOffset, $rangeStart) - $plainOffset;
      $outEnd   = min($chunkEnd, $rangeEnd) - $plainOffset;
      echo substr($plain, $outStart, $outEnd - $outStart + 1);
      if (ob_get_level() > 0) ob_flush();
      flush();
      $plainOffset += $chunkSize;
      return $plainOffset > $rangeEnd ? true : null;
    });
  }

  public static function decrypt_s3_range_output(
    mixed  $fh,
    string $salt_hex,
    string $password,
    int    $first_chunk_idx,
    int    $rs,
    int    $re,
    int    $chunk_size,
    int    $plain_size
  ): void {
    if (strlen($salt_hex) !== 32 || !ctype_xdigit($salt_hex)) return;
    $salt  = (string)hex2bin($salt_hex);
    $key   = self::derive_key($password, $salt);
    $chunk_idx   = $first_chunk_idx;
    $plain_offset = $first_chunk_idx * $chunk_size;
    $version     = null;

    while (true) {
      $len_raw = self::fread_exact($fh, 4);
      if ($len_raw === false) break;
      $cipher_len = unpack('N', $len_raw)[1];
      if ($cipher_len === 0 || $cipher_len > $chunk_size + 32) break;
      $nonce  = self::fread_exact($fh, 12);
      $tag    = self::fread_exact($fh, 16);
      $cipher = self::fread_exact($fh, $cipher_len);
      if ($nonce === false || $tag === false || $cipher === false) break;
      $plain = false;
      foreach ($version !== null ? [$version] : [3, 2, 1] as $v) {
        $aad = self::chunk_aad($v, $chunk_idx, $plain_size, $chunk_size);
        $try = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        if ($try !== false) { $version = $v; $plain = $try; break; }
      }
      if ($plain === false) break;
      $chunk_end = $plain_offset + strlen($plain) - 1;
      if ($plain_offset <= $re && $chunk_end >= $rs) {
        $out_start = max($plain_offset, $rs) - $plain_offset;
        $out_end   = min($chunk_end, $re) - $plain_offset;
        echo substr($plain, $out_start, $out_end - $out_start + 1);
        if (ob_get_level() > 0) ob_flush();
        flush();
      }
      $plain_offset += strlen($plain);
      if ($plain_offset > $re) break;
      $chunk_idx++;
    }

    Base::memzero($key);
  }

}
