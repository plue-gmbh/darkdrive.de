<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Base — shared utilities and security primitives for Darkdrive
//
//   Sessions:   start, track, destroy, multi-session management
//   Security:   CSRF tokens, Content-Security-Policy, X-Content-Type-Options
//   File types: extension-based detection (image/audio/video/text/…), MIME mapping
//   Enc cookie: split-key v2 — password encrypted with session share (AES-256-GCM)
//   Tags:       encrypted tag directory names, auto-migration from plaintext
//   Utilities:  string sanitization, URL building, redirects, audit logging
//

class Base {

  const EXT_IMAGES    = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico', 'bmp', 'tif', 'tiff', 'avif', 'heic', 'heif', 'jxl'];
  const EXT_AUDIO     = ['mp3', 'ogg', 'wav', 'flac', 'aac', 'm4a', 'opus', 'wma'];
  const EXT_VIDEO     = ['mp4', 'm4v', 'webm', 'mov', 'avi', 'mkv', 'ogv', '3gp', 'flv', 'wmv'];
  const EXT_DOCUMENTS = ['pdf', 'doc', 'docx', 'odt', 'xls', 'xlsx', 'ods', 'ppt', 'pptx', 'odp', 'rtf', 'eml', 'epub', 'pages', 'numbers', 'key', 'pfx'];
  const EXT_ARCHIVES  = ['zip', 'rar', 'gz', 'bz2', 'xz', 'tar', '7z', 'dmg', 'iso'];
  const EXT_TEXT      = ['txt', 'md', 'csv', 'html', 'htm', 'css', 'js', 'json', 'xml',
    'py', 'ts', 'tsx', 'jsx', 'sh', 'yaml', 'yml', 'toml', 'sql', 'rb', 'go', 'rs',
    'c', 'h', 'cpp', 'java', 'swift', 'kt', 'lua', 'r', 'ini', 'cfg', 'env', 'log',
    'db', 'sqlite',
  ];
  const EXT_FONTS     = ['woff', 'woff2', 'eot', 'ttf', 'otf'];
  const EXT_CONTACTS  = ['vcf'];
  const EXT_EDITABLE  = ['txt', 'md', 'csv', 'html', 'htm', 'css', 'js', 'json', 'xml',
    'py', 'ts', 'tsx', 'jsx', 'sh', 'yaml', 'yml', 'toml', 'sql', 'rb', 'go', 'rs',
    'c', 'h', 'cpp', 'java', 'swift', 'kt', 'lua', 'r', 'ini', 'cfg', 'env', 'log',
    'vcf',
  ];
  const EXT_DESIGN    = ['psd', 'ai', 'eps', 'indd', 'sketch', 'xd', 'fig', 'afdesign', 'afphoto', 'afpub'];

  const EXT_BLOCKED   = ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'phps', 'cgi', 'pl', 'asp', 'aspx', 'jsp', 'shtml'];

  const SESSION_LIFETIME = 43200;
  const INLINE_SIZE_LIMIT = 2 * 1024 * 1024;
  const SAFETY_READ_LIMIT = 2 * 1024 * 1024;

  public static function str_clean(string $string): string {
    $string = str_replace(' ', '-', trim($string));
    $string = str_replace(['ä','ö','ü','ß'], ['ae','oe','ue','ss'], $string);
    $string = preg_replace("/[^A-Za-z0-9\-\+_.@–~]+/", '', $string);
    return $string;
  }

  public static function url(array $params = []): string {
    $segments = [];
    if (!empty($params['tag']))  $segments[] = 'tag/'  . rawurlencode((string)$params['tag']);
    if (!empty($params['type'])) $segments[] = 'type/' . rawurlencode((string)$params['type']);
    if (!empty($params['file'])) $segments[] = 'file/' . rawurlencode((string)$params['file']);
    if (empty($segments)) return '/';
    return '/?route=' . implode('/', $segments);
  }

  public static function redirect(string $target='/'): void {
    $target = str_replace(["\r", "\n", "\0", "\\"], '', $target);
    if (!str_starts_with($target, '/') || str_starts_with($target, '//')) $target = '/';
    header('Location: ' . $target);
    exit;
  }

  public static function session_works(): bool {
    if (headers_sent()) return false;

    $lifetime = self::SESSION_LIFETIME;

    session_set_cookie_params([
      'lifetime' => $lifetime,
      'path' => '/',
      'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
      'httponly' => true,
      'samesite' => 'Strict',
    ]);

    ini_set('session.gc_maxlifetime', (string)$lifetime);
    session_cache_limiter('');
    if (!session_id()) session_start();
    if (empty($_SERVER['SERVER_NAME'])) return false;
    if (empty($_SERVER['HTTP_USER_AGENT']) || preg_match('/(bot|partner|slurp)/i', $_SERVER['HTTP_USER_AGENT'])) return false;
    if (empty($_SERVER['REMOTE_ADDR'])) return false;

    if (isset($_SESSION['last_active']) && (time() - $_SESSION['last_active']) > $lifetime) {
      self::untrack_session();
      $_SESSION = [];
      session_destroy();
      session_start();
    }
    $_SESSION['last_active'] = time();

    if (!empty($_SESSION['user'])) self::track_session($lifetime);

    return true;
  }

  private static function session_hash(string $sid): string {
    return hash('sha256', $sid);
  }

  public static function track_session(int $lifetime): void {
    $file = self::data_path('.sessions');
    $hash = self::session_hash(session_id());
    $now  = time();
    $cutoff = $now - $lifetime;
    $fh = @fopen($file, 'c+');
    if (!$fh) return;
    if (!flock($fh, LOCK_EX)) { fclose($fh); return; }
    $lines = [];
    foreach (explode("\n", trim(stream_get_contents($fh) ?: '')) as $line) {
      if ($line === '') continue;
      [$id, $ts] = array_pad(explode(':', $line, 2), 2, '0');
      if ((int)$ts >= $cutoff && $id !== $hash) $lines[] = $line;
    }
    $lines[] = $hash . ':' . $now;
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, implode("\n", $lines) . "\n");
    flock($fh, LOCK_UN);
    fclose($fh);
  }

  public static function untrack_session(): void {
    $file = self::data_path('.sessions');
    if (!is_file($file)) return;
    $hash = self::session_hash(session_id());
    $fh = fopen($file, 'c+');
    if (!$fh) return;
    if (!flock($fh, LOCK_EX)) { fclose($fh); return; }
    $lines = [];
    foreach (explode("\n", trim(stream_get_contents($fh) ?: '')) as $line) {
      if ($line === '') continue;
      [$id] = explode(':', $line, 2);
      if ($id !== $hash) $lines[] = $line;
    }
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, $lines ? implode("\n", $lines) . "\n" : '');
    flock($fh, LOCK_UN);
    fclose($fh);
  }

  public static function destroy_other_sessions(): void {
    $file = self::data_path('.sessions');
    $sid  = session_id();
    $hash = self::session_hash($sid);
    $dir  = session_save_path() ?: sys_get_temp_dir();
    if (is_file($file)) {
      $tracked = [];
      foreach (explode("\n", trim(file_get_contents($file) ?: '')) as $line) {
        if ($line === '') continue;
        [$id] = explode(':', $line, 2);
        if ($id !== $hash) $tracked[$id] = true;
      }
      if (!empty($tracked)) {
        foreach (glob($dir . '/sess_*') as $path) {
          $pathHash = self::session_hash(substr(basename($path), 5));
          if (isset($tracked[$pathHash])) @unlink($path);
        }
      }
    }
    @file_put_contents($file, $hash . ':' . time() . "\n", LOCK_EX);
  }

  public static function active_sessions(): int {
    $file = self::data_path('.sessions');
    if (!is_file($file)) return 1;
    $cutoff = time() - self::SESSION_LIFETIME;
    $count = 0;
    foreach (explode("\n", trim(file_get_contents($file) ?: '')) as $line) {
      if ($line === '') continue;
      [$id, $ts] = array_pad(explode(':', $line, 2), 2, '0');
      if ((int)$ts >= $cutoff) $count++;
    }
    return max(1, $count);
  }

  public static function security_headers(): void {
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self'; frame-src 'self'; object-src 'none'; form-action 'self'");
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
      header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
  }

  public static function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
  }

  public static function csrf_field(): void {
    echo '<input type="hidden" name="csrf_token" value="' . self::csrf_token() . '">';
  }

  public static function csrf_verify(): bool {
    if (!isset($_POST['csrf_token']) || !hash_equals(self::csrf_token(), $_POST['csrf_token'])) {
      return false;
    }
    return true;
  }

  public static function is_safe_svg(string $file): bool {
    $size = filesize($file);
    if ($size === false || $size === 0) return false;
    if ($size > self::SAFETY_READ_LIMIT) return false;
    $svg = file_get_contents($file);
    if (!$svg) return false;
    if (stripos($svg, '<!DOCTYPE') !== false || stripos($svg, '<!ENTITY') !== false) return false;
    $prev = libxml_use_internal_errors(true);
    $dom = new \DOMDocument();
    $ok = $dom->loadXML($svg, LIBXML_NONET);
    libxml_clear_errors();
    libxml_use_internal_errors($prev);
    if (!$ok) return false;
    $dangerous = ['script', 'foreignobject', 'iframe', 'embed', 'object', 'animate', 'set', 'handler', 'listener'];
    $xpath = new \DOMXPath($dom);
    foreach ($xpath->query('//*') as $el) {
      if (in_array(strtolower($el->localName), $dangerous, true)) return false;
      foreach ($el->attributes as $attr) {
        $name = strtolower($attr->localName);
        if (str_starts_with($name, 'on')) return false;
        if (in_array($name, ['href', 'src', 'action', 'formaction'], true)) {
          $val = trim($attr->value);
          if (preg_match('/^(javascript|data|vbscript)\s*:/i', $val)) return false;
        }
      }
    }
    return true;
  }

  public static function is_safe_xml(string $file): bool {
    $size = filesize($file);
    if ($size === false || $size === 0) return false;
    if ($size > self::SAFETY_READ_LIMIT) return false;
    $xml = file_get_contents($file);
    if (!$xml) return false;
    if (preg_match('/
      <script
      |\bon\w+\s*=
      |javascript\s*:
      |<!DOCTYPE
      |<!ENTITY
      /ix', $xml)
    ) return false;
    return true;
  }

  public static function is_safe_csv(string $file): bool {
    $size = filesize($file);
    if ($size === false) return false;
    if ($size > self::SAFETY_READ_LIMIT) return false;
    $fh = fopen($file, 'r');
    if ($fh === false) return false;
    $bom = fread($fh, 2);
    if ($bom === "\xFF\xFE" || $bom === "\xFE\xFF") { fclose($fh); return false; }
    foreach ([',', ';', "\t", '|'] as $delim) {
      rewind($fh);
      while (($row = fgetcsv($fh, 0, $delim, '"', '')) !== false) {
        foreach ($row as $field) {
          $field = ltrim((string)$field, " \r\n\xEF\xBB\xBF");
          if ($field === '') continue;
          $first = $field[0];
          if ($first === '=' || $first === '@' || $first === "\t") { fclose($fh); return false; }
          if (($first === '-' || $first === '+') && preg_match('/[=(|!]/', $field)) { fclose($fh); return false; }
        }
      }
    }
    fclose($fh);
    return true;
  }

  public static function is_safe_file(string $file): bool {
    static $all = null;
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    if (in_array($ext, self::EXT_BLOCKED, true)) return false;
    if ($all === null) {
      $all = array_merge(self::EXT_IMAGES, self::EXT_AUDIO, self::EXT_VIDEO,
        self::EXT_DOCUMENTS, self::EXT_ARCHIVES, self::EXT_TEXT, self::EXT_FONTS, self::EXT_CONTACTS, self::EXT_DESIGN);
    }
    return in_array($ext, $all, true);
  }

  public static function is_image(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_IMAGES, true);
  }

  public static function is_audio(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_AUDIO, true);
  }

  public static function is_video(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_VIDEO, true);
  }

  public static function is_document(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_DOCUMENTS, true);
  }

  public static function is_archive(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_ARCHIVES, true);
  }

  public static function is_text(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_TEXT, true);
  }

  public static function is_editable(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_EDITABLE, true);
  }

  public static function is_font(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_FONTS, true);
  }

  public static function is_contact(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_CONTACTS, true);
  }

  public static function is_design(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_DESIGN, true);
  }

  public static function data_path(string $to=''): string {
    $dir = defined('DARKDRIVE_STORAGE_DIR') ? rtrim(DARKDRIVE_STORAGE_DIR, '/') : 'data';
    return $dir . '/' . $to;
  }

  public static function data_outside_webroot(): bool {
    $data = realpath(rtrim(self::data_path(), '/'));
    $root = realpath(getcwd());
    if ($data === false || $root === false) return false;
    return !str_starts_with($data . '/', $root . '/');
  }

  public static function format_bytes(int $bytes): string {
    if ($bytes >= 1099511627776) return number_format($bytes / 1099511627776, 2) . ' TB';
    if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576)    return number_format($bytes / 1048576, 1) . ' MB';
    if ($bytes >= 1024)       return round($bytes / 1024) . ' KB';
    return $bytes . ' B';
  }

  public static function resolve_tag_dir(string $tag): ?string {
    $tagsDir = self::data_path('tags');
    $clean = strtolower(self::str_clean($tag));
    $encKey = self::enc_key();
    $plain = $tagsDir . '/' . $clean;
    if (is_dir($plain)) {
      if ($encKey !== '') {
        $encName = Crypto::encrypt_filename($clean, $encKey);
        if ($encName !== false) {
          $encPath = $tagsDir . '/' . $encName;
          if (@rename($plain, $encPath)) { self::memzero($encKey); return $encPath; }
        }
      }
      self::memzero($encKey);
      return $plain;
    }
    if ($encKey !== '' && is_dir($tagsDir)) {
      foreach (array_diff(scandir($tagsDir), ['.', '..']) as $dir) {
        if (!is_dir($tagsDir . '/' . $dir)) continue;
        $dec = Crypto::decrypt_filename_unwrap($dir, $encKey);
        if ($dec !== false) {
          if (strtolower($dec) === $clean) {
            self::memzero($encKey);
            return $tagsDir . '/' . $dir;
          }
        }
      }
    }
    self::memzero($encKey);
    return null;
  }

  private static ?array $allTagsCache = null;

  public static function get_all_tags(): array {
    if (self::$allTagsCache !== null) return self::$allTagsCache;
    $tagsDir = self::data_path('tags');
    if (!is_dir($tagsDir)) return self::$allTagsCache = [];
    $encKey = self::enc_key();
    $dirs = [];
    foreach (array_diff(scandir($tagsDir), ['.', '..']) as $dir) {
      if (is_dir($tagsDir . '/' . $dir)) $dirs[] = $dir;
    }
    $decrypted = [];
    $undecrypted = [];
    foreach ($dirs as $dir) {
      if ($encKey !== '') {
        $raw = Crypto::decrypt_filename($dir, $encKey);
        if ($raw !== false) {
          $inner = Crypto::decrypt_filename($raw, $encKey);
          if ($inner !== false) {
            $dec = $inner;
            $fixedEnc = Crypto::encrypt_filename($dec, $encKey);
            if ($fixedEnc !== false) {
              $fixedPath = $tagsDir . '/' . $fixedEnc;
              if (@rename($tagsDir . '/' . $dir, $fixedPath)) { $dir = $fixedEnc; }
            }
          } else {
            $dec = $raw;
          }
          $decrypted[$dir] = $dec;
          continue;
        }
      }
      $undecrypted[] = $dir;
    }
    $keyVerified = $encKey !== '' && count($decrypted) > 0;
    $result = [];
    foreach ($decrypted as $dir => $name) {
      $result[$name] = $tagsDir . '/' . $dir;
    }
    foreach ($undecrypted as $dir) {
      if ($keyVerified) {
        $encName = Crypto::encrypt_filename($dir, $encKey);
        if ($encName !== false) {
          $encPath = $tagsDir . '/' . $encName;
          if (@rename($tagsDir . '/' . $dir, $encPath)) {
            $result[$dir] = $encPath;
            continue;
          }
        }
      }
      $result[$dir] = $tagsDir . '/' . $dir;
    }
    self::memzero($encKey);
    return self::$allTagsCache = $result;
  }

  public static function tag_dir_name(string $tag): string {
    $clean = strtolower(self::str_clean($tag));
    $encKey = self::enc_key();
    if ($encKey !== '') {
      $result = Crypto::encrypt_filename($clean, $encKey);
      self::memzero($encKey);
      if ($result === false) return $clean;
      return $result;
    }
    return $clean;
  }

  public static function decrypt_tag_name(string $dirName): string {
    $encKey = self::enc_key();
    if ($encKey !== '') {
      $dec = Crypto::decrypt_filename_unwrap($dirName, $encKey);
      self::memzero($encKey);
      if ($dec !== false) return $dec;
    }
    return $dirName;
  }

  public static function set_tag(string $filename, string $tag): bool {
    $existing = self::resolve_tag_dir($tag);
    if ($existing) {
      $path = $existing;
    } else {
      $path = self::data_path('tags') . '/' . self::tag_dir_name($tag);
    }
    if (!is_dir($path) && !mkdir($path, 0755, true)) return false;
    return touch($path . '/' . self::str_clean($filename) . '.txt');
  }

  public static function rm_tag(string $filename, string $tag): bool {
    $dir = self::resolve_tag_dir($tag);
    if (!$dir) return false;
    $file = $dir . '/' . self::str_clean($filename) . '.txt';
    return file_exists($file) && unlink($file);
  }

  private static ?string $ffmpegBin     = null;
  private static bool    $ffmpegChecked = false;

  public static function ffmpeg_bin(): ?string {
    if (!self::$ffmpegChecked) {
      self::$ffmpegChecked = true;
      foreach (['/usr/bin/ffmpeg', '/usr/local/bin/ffmpeg', '/opt/homebrew/bin/ffmpeg', '/opt/local/bin/ffmpeg'] as $path) {
        if (is_executable($path)) { self::$ffmpegBin = $path; break; }
      }
    }
    return self::$ffmpegBin;
  }

  private static ?string $pdftoppmBin     = null;
  private static bool    $pdftoppmChecked = false;

  public static function pdftoppm_bin(): ?string {
    if (!self::$pdftoppmChecked) {
      self::$pdftoppmChecked = true;
      foreach (['/usr/bin/pdftoppm', '/usr/local/bin/pdftoppm', '/opt/homebrew/bin/pdftoppm', '/opt/local/bin/pdftoppm'] as $path) {
        if (is_executable($path)) { self::$pdftoppmBin = $path; break; }
      }
    }
    return self::$pdftoppmBin;
  }

  private static ?string $libreofficeBin     = null;
  private static bool    $libreofficeChecked = false;

  public static function libreoffice_bin(): ?string {
    if (!self::$libreofficeChecked) {
      self::$libreofficeChecked = true;
      foreach (['/usr/bin/libreoffice', '/usr/local/bin/libreoffice', '/opt/homebrew/bin/libreoffice', '/opt/local/bin/libreoffice', '/usr/bin/soffice', '/usr/local/bin/soffice'] as $path) {
        if (is_executable($path)) { self::$libreofficeBin = $path; break; }
      }
    }
    return self::$libreofficeBin;
  }

  private const EXT_OFFICE = ['doc', 'docx', 'odt', 'xls', 'xlsx', 'ods', 'ppt', 'pptx', 'odp', 'rtf'];

  public static function is_office(string $file): bool {
    return in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), self::EXT_OFFICE, true);
  }

  public static function ext_to_mime(string $ext): string {
    return match($ext) {
      'jpg', 'jpeg' => 'image/jpeg',
      'png'         => 'image/png',
      'gif'         => 'image/gif',
      'webp'        => 'image/webp',
      'svg'         => 'image/svg+xml',
      'ico'         => 'image/x-icon',
      'bmp'         => 'image/bmp',
      'tif', 'tiff' => 'image/tiff',
      'avif'        => 'image/avif',
      'mp4', 'm4v'  => 'video/mp4',
      'webm'        => 'video/webm',
      'mov'         => 'video/quicktime',
      'avi'         => 'video/x-msvideo',
      'mkv'         => 'video/x-matroska',
      'ogv'         => 'video/ogg',
      '3gp'         => 'video/3gpp',
      'mp3'         => 'audio/mpeg',
      'ogg'         => 'audio/ogg',
      'wav'         => 'audio/wav',
      'flac'        => 'audio/flac',
      'aac'         => 'audio/aac',
      'm4a'         => 'audio/mp4',
      'opus'        => 'audio/opus',
      'wma'         => 'audio/x-ms-wma',
      'pdf'         => 'application/pdf',
      'doc'         => 'application/msword',
      'docx'        => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'odt'         => 'application/vnd.oasis.opendocument.text',
      'xls'         => 'application/vnd.ms-excel',
      'xlsx'        => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'ods'         => 'application/vnd.oasis.opendocument.spreadsheet',
      'ppt'         => 'application/vnd.ms-powerpoint',
      'pptx'        => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'odp'         => 'application/vnd.oasis.opendocument.presentation',
      'rtf'         => 'application/rtf',
      'eml'         => 'message/rfc822',
      'zip'         => 'application/zip',
      'rar'         => 'application/x-rar-compressed',
      'gz'          => 'application/gzip',
      'bz2'         => 'application/x-bzip2',
      'xz'          => 'application/x-xz',
      'tar'         => 'application/x-tar',
      '7z'          => 'application/x-7z-compressed',
      'txt', 'md'   => 'text/plain',
      'csv'         => 'text/csv',
      'html', 'htm' => 'text/html',
      'css'         => 'text/css',
      'js'          => 'text/javascript',
      'json'        => 'application/json',
      'xml'         => 'application/xml',
      'vcf'         => 'text/vcard',
      default       => 'application/octet-stream',
    };
  }

  public static function ini_bytes(string $val): int {
    $val  = trim($val);
    $last = strtolower(substr($val, -1));
    $num  = (int) $val;
    if ($last === 'g') return $num * 1073741824;
    if ($last === 'm') return $num * 1048576;
    if ($last === 'k') return $num * 1024;
    return $num;
  }

  public static function max_upload_bytes(): int {
    return min(self::ini_bytes((string)ini_get('upload_max_filesize')), self::ini_bytes((string)ini_get('post_max_size')), DARKDRIVE_MAX_FILESIZE * 1024 * 1024);
  }

  private static string $instanceKeyCache = '';

  public static function instance_key(): string {
    if (self::$instanceKeyCache !== '') return self::$instanceKeyCache;
    if (defined('DARKDRIVE_INSTANCE_KEY')) { self::$instanceKeyCache = hex2bin(DARKDRIVE_INSTANCE_KEY); return self::$instanceKeyCache; }
    $path = self::data_path('.instance_key');
    if (is_file($path)) {
      $hex = trim((string)file_get_contents($path));
      if (strlen($hex) === 64) { self::$instanceKeyCache = hex2bin($hex); return self::$instanceKeyCache; }
    }
    $key = random_bytes(32);
    @file_put_contents($path, bin2hex($key), LOCK_EX);
    @chmod($path, 0600);
    self::$instanceKeyCache = $key;
    return $key;
  }

  public static function set_enc_cookie(string $password): void {
    $share = random_bytes(32);
    $_SESSION['enc_share'] = $share;
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt($password, 'aes-256-gcm', $share, OPENSSL_RAW_DATA, $nonce, $tag);
    $value = base64_encode("\x02" . $nonce . $tag . $ct);
    setcookie('enc_key', $value, [
      'expires'  => time() + self::SESSION_LIFETIME,
      'path'     => '/',
      'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
      'httponly'  => true,
      'samesite' => 'Strict',
    ]);
  }

  public static function enc_key(): string {
    if (!isset($_COOKIE['enc_key'])) return '';
    $raw = base64_decode($_COOKIE['enc_key'], true);
    if ($raw === false || strlen($raw) < 2) return '';

    if ($raw[0] === "\x02" && strlen($raw) >= 30 && isset($_SESSION['enc_share'])) {
      $nonce = substr($raw, 1, 12);
      $tag   = substr($raw, 13, 16);
      $ct    = substr($raw, 29);
      $plain = openssl_decrypt($ct, 'aes-256-gcm', $_SESSION['enc_share'], OPENSSL_RAW_DATA, $nonce, $tag);
      if ($plain !== false) return $plain;
    }

    if (strlen($raw) >= 29) {
      $key   = self::instance_key();
      $nonce = substr($raw, 0, 12);
      $tag   = substr($raw, 12, 16);
      $ct    = substr($raw, 28);
      $plain = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
      if ($plain !== false) {
        if (session_status() === PHP_SESSION_ACTIVE) self::set_enc_cookie($plain);
        return $plain;
      }
    }

    return '';
  }

  public static function memzero(string &$var): void {
    if (function_exists('sodium_memzero')) {
      try { sodium_memzero($var); } catch (\SodiumException $e) {}
    } else {
      $len = strlen($var);
      $var = str_repeat("\0", $len);
    }
    $var = '';
  }

  public static function audit(string $action, string $detail = ''): void {
    $log = self::data_path('.audit_log');
    $entry = date('Y-m-d H:i:s') . "\t" . $action;
    if ($detail !== '') $entry .= "\t" . substr($detail, 0, 128);
    @file_put_contents($log, $entry . "\n", FILE_APPEND | LOCK_EX);
  }

  public static function derive_auth_key_js(): void {
    ?>
    <script src="/components/app.login.js?v=<?= filemtime(__DIR__ . '/app.login.js') ?>"></script>
    <?php
  }

  public static function generate_passphrase(): string {
    $chars = '23456789abcdefghjkmnpqrstuvwxyz';
    $parts = [];
    for ($i = 0; $i < 5; $i++) {
      $part = '';
      for ($j = 0; $j < 5; $j++) {
        $part .= $chars[random_int(0, strlen($chars) - 1)];
      }
      $parts[] = $part;
    }
    return implode('-', $parts);
  }

  public static function clear_enc_cookie(): void {
    setcookie('enc_key', '', [
      'expires'  => 1,
      'path'     => '/',
      'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
      'httponly'  => true,
      'samesite' => 'Strict',
    ]);
  }

  public static function save_emergency_recovery(string $password): void {
    $path = self::data_path('.emergency_recovery');
    $key = self::instance_key();
    $nonce = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($password, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($ct !== false) {
      @file_put_contents($path, $nonce . $tag . $ct, LOCK_EX);
      @chmod($path, 0600);
    }
  }

  public static function emergency_recovery_password(): ?string {
    $path = self::data_path('.emergency_recovery');
    if (!is_file($path)) return null;
    $raw = file_get_contents($path);
    if ($raw === false || strlen($raw) < 29) return null;
    $key = self::instance_key();
    $nonce = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $ct = substr($raw, 28);
    $plain = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    return $plain !== false ? $plain : null;
  }

  public static function clear_emergency_recovery(): void {
    $path = self::data_path('.emergency_recovery');
    if (!is_file($path)) return;
    $size = filesize($path);
    if ($size > 0) @file_put_contents($path, str_repeat("\0", $size), LOCK_EX);
    @unlink($path);
  }

  public static function handle_tags(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['tag'])) return;
    if (!isset($_POST['file']) && !isset($_POST['bulk_tag_files'])) return;
    if (!self::csrf_verify()) return;
    if (strlen($_POST['tag']) > 64) return;
    $tag = strtolower(self::str_clean($_POST['tag']));
    if (empty($tag)) return;
    $dir = self::data_path('tags');
    if (!is_dir($dir) && !mkdir($dir, 0755)) return;

    if (!empty($_POST['bulk_tag_files']) && is_array($_POST['bulk_tag_files'])) {
      if (count($_POST['bulk_tag_files']) > 500) return;
      $tagDir = self::resolve_tag_dir($tag);
      $allHaveTag = true;
      $cleaned = [];
      foreach ($_POST['bulk_tag_files'] as $raw) {
        if (!is_string($raw) || strlen($raw) > 512) continue;
        $f = self::str_clean($raw);
        if (empty($f)) continue;
        $cleaned[] = $f;
        if (!$tagDir || !file_exists("{$tagDir}/{$f}.txt")) $allHaveTag = false;
      }
      foreach ($cleaned as $f) {
        $allHaveTag ? self::rm_tag($f, $tag) : self::set_tag($f, $tag);
      }
    } else {
      if (strlen($_POST['file'] ?? '') > 512) return;
      $file = self::str_clean($_POST['file']);
      if (empty($file)) return;
      $tagDir = self::resolve_tag_dir($tag);
      $exists = $tagDir && file_exists("{$tagDir}/{$file}.txt");
      $exists ? self::rm_tag($file, $tag) : self::set_tag($file, $tag);
    }
    $validTypes = ['images', 'videos', 'audio', 'documents', 'archives', 'texts', 'fonts', 'contacts', 'design'];
    $ctx = array_filter([
      'tag'  => isset($_GET['tag'])  ? self::str_clean($_GET['tag'])  : null,
      'type' => isset($_GET['type']) && in_array($_GET['type'], $validTypes, true) ? $_GET['type'] : null,
      'file' => isset($_GET['file']) ? self::str_clean($_GET['file']) : null,
    ], fn($v) => $v !== null && $v !== '');
    self::redirect(self::url($ctx));
  }

}
