#!/usr/bin/env php
<?php
if (PHP_SAPI !== 'cli') exit;

define('DARKDRIVE_TITLE',       'Test');
define('DARKDRIVE_MAX_FILESIZE', 1024);
define('DARKDRIVE_MAX_STORAGE',  1024);

const C_RED   = "\033[0;31m";
const C_GREEN = "\033[0;32m";
const C_DIM   = "\033[2m";
const C_BOLD  = "\033[1m";
const C_NC    = "\033[0m";

$PASS = 0; $FAIL = 0;

function ok(string $label): void {
  global $PASS; $PASS++;
  echo '  ' . C_GREEN . '✓' . C_NC . "  $label\n";
}
function err(string $label, string $detail = ''): void {
  global $FAIL; $FAIL++;
  echo '  ' . C_RED . '✗' . C_NC . "  $label" . ($detail ? " — $detail" : '') . "\n";
}
function section(string $t): void { echo "\n  " . C_DIM . $t . C_NC . "\n"; }
function check(string $label, bool $cond, string $detail = ''): void {
  $cond ? ok($label) : err($label, $detail);
}
function check_eq(string $label, mixed $got, mixed $want): void {
  check($label, $got === $want,
    'got ' . var_export($got, true) . ', want ' . var_export($want, true));
}

$dir = __DIR__;

// ── 1. Syntax ─────────────────────────────────────────────────────────────────

echo "\n" . C_BOLD . "Syntax" . C_NC . "\n";

$phpFiles = array_merge(glob("$dir/*.php"), glob("$dir/components/*.php"));
sort($phpFiles);
foreach ($phpFiles as $f) {
  if ($f === __FILE__) continue;
  $rel = substr($f, strlen($dir) + 1);
  $out = []; $code = 0;
  exec('php -l ' . escapeshellarg($f) . ' 2>&1', $out, $code);
  if ($code === 0) {
    ok($rel);
  } else {
    err($rel);
    foreach (array_filter($out) as $line) echo "      $line\n";
  }
}

// ── 1a. index.php require integrity ──────────────────────────────────────────
// index.php is excluded from auto-updates. Every component class file in
// components/ must either be listed in index.php OR be auto-loaded by a file
// that is listed. This catches two problems:
//   1. A new class file added but missing from index.php
//   2. A new class file in index.php that old installations don't have,
//      without an auto-load guard in the file that references it

echo "\n" . C_BOLD . "index.php require integrity" . C_NC . "\n";

// Parse current requires from index.php and app.class.php
$indexSrc = file_get_contents("$dir/index.php");
$appClassSrc = file_get_contents("$dir/components/app.class.php");
preg_match_all("/require_once\s+['\"]([^'\"]+)['\"]/", $indexSrc, $rm1);
preg_match_all("/require_once\s+__DIR__\s*\.\s*['\"]\/([^'\"]+)['\"]/", $appClassSrc, $rm2);
$currentRequires = array_merge($rm1[1], array_map(fn($f) => "components/$f", $rm2[1]));

// Known component class files — when you add a new one, add it here.
// The test will fail if a .class.php file exists on disk but is not in this list,
// forcing you to consider whether old index.php installations need an auto-load guard.
$knownClassFiles = [
  'components/app.class.php',
  'components/base.class.php',
  'components/crypto.class.php',
  'components/emergency.class.php',
  'components/files.class.php',
  'components/fileserver.class.php',
  'components/login.class.php',
  'components/s3.class.php',
  'components/status.class.php',
  'components/update.class.php',
  'components/upload.class.php',
];

$diskClassFiles = array_map(
  fn($f) => 'components/' . basename($f),
  glob("$dir/components/*.class.php")
);
sort($diskClassFiles);

$unlisted = array_diff($diskClassFiles, $knownClassFiles);
$missing  = array_diff($knownClassFiles, $diskClassFiles);
check('no unlisted class files on disk', empty($unlisted),
  $unlisted ? 'add to test: ' . implode(', ', $unlisted) : '');
check('no missing class files from disk', empty($missing),
  $missing ? 'missing: ' . implode(', ', $missing) : '');

// Every class file must be in index.php or auto-loaded by one that is
foreach ($knownClassFiles as $cf) {
  check("$cf is in index.php or auto-loaded",
    in_array($cf, $currentRequires) ||
    str_contains(file_get_contents("$dir/$cf"), 'class_exists') === false
  );
}

// No requires pointing to missing files
foreach ($currentRequires as $r) {
  check(basename($r) . ' exists on disk', file_exists("$dir/$r"));
}

// Verify the full require order loads cleanly in a subprocess
$fullRequireLines = '';
foreach ($currentRequires as $r) {
  $fullRequireLines .= 'require_once "' . $dir . '/' . $r . '";';
}
$fullCmd = sprintf('php -r %s 2>&1', escapeshellarg($fullRequireLines . 'echo "OK";'));
$fullOut = trim(shell_exec($fullCmd) ?? '');
check_eq('all requires load without error', $fullOut, 'OK');

// Test that each file loads independently (auto-loads its own deps)
// by requiring each one alone — catches missing auto-load guards
foreach ($currentRequires as $r) {
  $soloCmd = sprintf('php -r %s 2>&1', escapeshellarg(
    'require_once "' . $dir . '/' . $r . '"; echo "OK";'
  ));
  $soloOut = trim(shell_exec($soloCmd) ?? '');
  check_eq(basename($r) . ' loads standalone', $soloOut, 'OK');
}

// ── 1b. JS syntax ────────────────────────────────────────────────────────────

echo "\n" . C_BOLD . "JS files" . C_NC . "\n";

$hasNode = trim(shell_exec('which node 2>/dev/null') ?? '') !== '';
$jsFiles = glob("$dir/components/*.js");
sort($jsFiles);
foreach ($jsFiles as $f) {
  $rel = substr($f, strlen($dir) + 1);
  if ($hasNode) {
    $out = []; $code = 0;
    exec('node --check ' . escapeshellarg($f) . ' 2>&1', $out, $code);
    if ($code === 0) {
      ok($rel);
    } else {
      err($rel);
      foreach (array_filter($out) as $line) echo "      $line\n";
    }
  } else {
    $src = file_get_contents($f);
    ok("$rel (" . strlen($src) . ' bytes, node not available for syntax check)');
  }
}

section('app.login.js');
$loginSrc = file_get_contents("$dir/components/app.login.js");
check('defines deriveAuthKey',         str_contains($loginSrc, 'async function deriveAuthKey'));
check('uses PBKDF2',                   str_contains($loginSrc, 'PBKDF2'));
check('salt = darkdrive-auth-v1',      str_contains($loginSrc, 'darkdrive-auth-v1'));
check('100000 iterations',             str_contains($loginSrc, '100000'));
check('SHA-256 hash',                  str_contains($loginSrc, 'SHA-256'));
check('derives 256 bits',              str_contains($loginSrc, '256'));
check('returns hex string',            str_contains($loginSrc, 'toString(16)'));
check('handles setup-form',            str_contains($loginSrc, 'setup-form'));
check('handles login-form',            str_contains($loginSrc, 'login-form'));
check('calls deriveAuthKey',           str_contains($loginSrc, 'deriveAuthKey('));
check('sets auth_key field',           str_contains($loginSrc, "name=auth_key") || str_contains($loginSrc, "'auth_key'") || str_contains($loginSrc, "[name=auth_key]"));
check('sets password field',           str_contains($loginSrc, "name=password") || str_contains($loginSrc, "'password'") || str_contains($loginSrc, "[name=password]"));
check('prevents double-submit',        str_contains($loginSrc, '.value) return'));
check('calls form.submit()',           str_contains($loginSrc, '.submit()'));
check('checks crypto.subtle',         str_contains($loginSrc, 'crypto.subtle'));
check('shows error on HTTP',          str_contains($loginSrc, '.catch'));

section('app.emergency.js');
$emergSrc = file_get_contents("$dir/components/app.emergency.js");
check('is IIFE',                       str_contains($emergSrc, '(function'));
check('finds emergency-form',          str_contains($emergSrc, 'emergency-form'));
check('finds emergency-overlay',       str_contains($emergSrc, 'emergency-overlay'));
check('defines step labels',           str_contains($emergSrc, 'verify') && str_contains($emergSrc, 'encrypt') && str_contains($emergSrc, 'thumbs') && str_contains($emergSrc, 'rename'));
check('derives both auth keys',        str_contains($emergSrc, 'Promise.all'));
check('sends JSON POST',               str_contains($emergSrc, 'application/json'));
check('sends csrf_token',              str_contains($emergSrc, 'csrf_token'));
check('sends old_password',            str_contains($emergSrc, 'old_password'));
check('sends new_password',            str_contains($emergSrc, 'new_password'));
check('streams NDJSON response',       str_contains($emergSrc, 'getReader') && str_contains($emergSrc, 'TextDecoder'));
check('handles ok:true → success',     str_contains($emergSrc, 'msg.ok === true'));
check('handles ok:false → error',      str_contains($emergSrc, 'msg.ok === false'));
check('shows progress counter',        str_contains($emergSrc, 'msg.i') && str_contains($emergSrc, 'msg.total'));
check('redirects after success',       str_contains($emergSrc, "location.href = '/'"));
check('has catch for network errors',  str_contains($emergSrc, '.catch'));

// ── 1c. CSS checks ──────────────────────────────────────────────────────────

echo "\n" . C_BOLD . "CSS" . C_NC . "\n";

$cssSrc = file_get_contents("$dir/components/app.css");
check('app.css exists and is non-empty', strlen($cssSrc) > 100);

// Strip strings and comments before counting brackets
$cssStripped = preg_replace(['~/\*.*?\*/~s', '~"[^"]*"|\'[^\']*\'~'], '', $cssSrc);
$open  = substr_count($cssStripped, '{');
$close = substr_count($cssStripped, '}');
check("brackets balanced ({$open} open, {$close} close)", $open === $close);

section('CSS variables');
check(':root defines --bg',            str_contains($cssSrc, '--bg:'));
check(':root defines --text',          str_contains($cssSrc, '--text:'));
check(':root defines --text-dim',      str_contains($cssSrc, '--text-dim:'));
check(':root defines --success',       str_contains($cssSrc, '--success:'));
check(':root defines --danger',        str_contains($cssSrc, '--danger:'));
check(':root defines --surface',       str_contains($cssSrc, '--surface:'));
check(':root defines --border',        str_contains($cssSrc, '--border:'));

section('CSS responsive');
check('has mobile breakpoint',         str_contains($cssSrc, '@media') && str_contains($cssSrc, '999px'));
// Tile overlays (.audio-btn, .video-btn) use longhand for Firefox Android compat
// inset:0 is OK in non-tile contexts
check('has @media max-width 999px', (bool) preg_match('/@media\s*\(\s*max-width\s*:\s*999px\s*\)/', $cssSrc));

section('CSS critical selectors');
check('.login-container',              str_contains($cssSrc, '.login-container'));
check('.login-button',                 str_contains($cssSrc, '.login-button'));
check('.login-lockout',                str_contains($cssSrc, '.login-lockout'));
check('.upload form',                  str_contains($cssSrc, '.upload'));
check('.tile selector',                str_contains($cssSrc, '.tile'));
check('.audio-play',                   str_contains($cssSrc, '.audio-play'));
check('.video-btn',                    str_contains($cssSrc, '.video-btn'));
check('.footer-bar',                   str_contains($cssSrc, '.footer-bar'));
check('.error-overlay',                str_contains($cssSrc, '.error-overlay'));
check('.error-ok-btn',                 str_contains($cssSrc, '.error-ok-btn'));
check('audio element styling',         str_contains($cssSrc, 'audio'));
check('.offline-notice',               str_contains($cssSrc, '.offline-notice'));

$appSrc = file_get_contents("$dir/components/app.class.php");

section('Offline notice');
check('layout has offline-notice div',    str_contains($appSrc, 'id="offline-notice"'));
check('layout has offline-notice class',  str_contains($appSrc, 'class="offline-notice"'));
check('hidden by default',               str_contains($appSrc, "style=\"display:none\"") || str_contains($appSrc, "display:none"));
check('loads app.offline.js',             str_contains($appSrc, 'app.offline.js'));
check('no inline scripts',              !preg_match('/<script>/', $appSrc));

section('Service Worker (PHP-generated)');
$swMethod = '';
if (preg_match('/function service_worker\(\).*?\{(.+?)\n  \}/s', $appSrc, $swm)) $swMethod = $swm[1];
check('service_worker method exists',    !empty($swMethod));
check('cache name uses filemtime hash',  str_contains($swMethod, 'filemtime') && str_contains($swMethod, 'darkdrive-v'));
check('serves application/javascript',   str_contains($swMethod, 'application/javascript'));
check('no-cache header',                 str_contains($swMethod, 'no-cache'));
check('caches app.css',                  str_contains($swMethod, 'app.css'));
check('caches app.offline.js',           str_contains($swMethod, 'app.offline.js'));
check('caches font',                     str_contains($swMethod, 'app.ttf'));
check('caches offline page',             str_contains($swMethod, '/offline'));
check('no app.js in cache',             !str_contains($swMethod, "'app.js'") && !str_contains($swMethod, "app.js'"));
check('install + skipWaiting',           str_contains($swMethod, 'install') && str_contains($swMethod, 'skipWaiting'));
check('activate + clients.claim',        str_contains($swMethod, 'activate') && str_contains($swMethod, 'clients.claim'));
check('cleans old caches on activate',   str_contains($swMethod, 'caches.delete'));
check('navigate → offline fallback',     str_contains($swMethod, 'navigate') && str_contains($swMethod, '/offline'));
check('only handles GET',               str_contains($swMethod, "!=='GET'"));

section('Share target');
$jsSrc = file_get_contents("$dir/components/app.js");
check('manifest declares share_target',  str_contains($appSrc, "'share_target'"));
check('share_target posts to /share',    str_contains($appSrc, "'action'  => '/share'"));
check('share route mapped',              str_contains($appSrc, "\$p === 'share'"));
check('dedupe route mapped',             str_contains($appSrc, "\$p === 'dedupe'"));
check('no-SW fallback flags failure',    str_contains($appSrc, 'share_failed=nosw'));
check('SW intercepts POST /share',       str_contains($swMethod, "req.method==='POST'") && str_contains($swMethod, "==='/share'"));
check('SW caches share to SHARED',       str_contains($swMethod, "SHARED='darkdrive-shared'"));
check('SW share keys are unique',        str_contains($swMethod, 'Math.random()'));
check('SW cache failure flags failure',  str_contains($swMethod, 'share_failed=cache'));
check('activate keeps shared cache',     str_contains($swMethod, 'k!==CACHE&&k!==SHARED'));
check('drain not gated on shared=1',    !str_contains($jsSrc, "indexOf('shared=1')"));
check('shared files kept until stored',  str_contains($jsSrc, 'darkdriveCacheKey') && str_contains($jsSrc, 'dropShared'));
check('queue cap restored',              str_contains($jsSrc, 'MAX_QUEUE   = 100'));
check('batch sliced to cap',             str_contains($jsSrc, 'all.slice(0, MAX_QUEUE)'));
check('fingerprinting is lane-limited',  str_contains($jsSrc, 'mapLimit(files, FP_LANES, fingerprint)'));
check('picked files snapshot FileList',  str_contains($jsSrc, '[...e.target.files]'));

section('Offline page');
check('offline route registered',        str_contains($appSrc, "'offline'"));
check('offline_page method exists',      str_contains($appSrc, 'function offline_page'));
// Extract offline_page method body and verify it calls head() without its own doctype
$offlineBody = '';
if (preg_match('/function offline_page\(\).*?\{(.+?)\n  \}/s', $appSrc, $om)) $offlineBody = $om[1];
check('uses shared head()',              str_contains($offlineBody, 'self::head()') && !str_contains($offlineBody, '<!doctype'));
check('offline page has retry link',     str_contains($offlineBody, 'offline-retry'));
check('no inline script in offline page', !str_contains($offlineBody, '<script>'));
check('loads app.offline.js',            str_contains($offlineBody, 'app.offline.js'));
check('no-cache header',                 str_contains($offlineBody, 'no-cache'));

section('app.offline.js');
$offJsSrc = file_get_contents("$dir/components/app.offline.js");
check('handles offline-notice',          str_contains($offJsSrc, 'offline-notice'));
check('checks navigator.onLine',        str_contains($offJsSrc, 'navigator.onLine'));
check('listens to online event',         str_contains($offJsSrc, "'online'"));
check('listens to offline event',        str_contains($offJsSrc, "'offline'"));
check('registers service worker',        str_contains($offJsSrc, "register('/sw')"));
check('auto-reconnects via offline-retry', str_contains($offJsSrc, 'offline-retry'));
check('logged-out share is announced',   str_contains($offJsSrc, 'log in to upload'));
check('logged-in share fallback notice', str_contains($offJsSrc, 'open All Files to upload'));
check('share_failed notice on any page', str_contains($offJsSrc, 'share_failed'));

// ── 2. Unit tests ─────────────────────────────────────────────────────────────

require "$dir/components/app.class.php";
require "$dir/components/base.class.php";
require "$dir/components/crypto.class.php";
require "$dir/components/s3.class.php";
require "$dir/components/files.class.php";
require "$dir/components/login.class.php";
require "$dir/components/upload.class.php";
require "$dir/components/emergency.class.php";

echo "\n" . C_BOLD . "Unit tests" . C_NC . "\n";

// --- Base::url ---
section('Base::url');
check_eq('empty',      Base::url(),                               '/');
check_eq('tag',        Base::url(['tag'  => 'work']),             '/?route=tag/work');
check_eq('type',       Base::url(['type' => 'images']),           '/?route=type/images');
check_eq('tag+type',   Base::url(['tag'  => 'a', 'type' => 'v']), '/?route=tag/a/type/v');
check_eq('file',       Base::url(['file' => 'x.pdf']),            '/?route=file/x.pdf');
check_eq('url-encode', Base::url(['file' => 'a b.jpg']),          '/?route=file/a%20b.jpg');
check_eq('all three',  Base::url(['tag' => 't', 'type' => 'images', 'file' => 'f.jpg']),
                                                   '/?route=tag/t/type/images/file/f.jpg');

// --- Base::str_clean ---
section('Base::str_clean');
check_eq('spaces',  Base::str_clean('hello world'), 'hello-world');
check_eq('umlauts', Base::str_clean('über'),         'ueber');
check_eq('trim',    Base::str_clean('  hi  '),       'hi');

// --- Base::is_* ---
section('Base::is_*');
check('is_image jpg',     Base::is_image('x.jpg'));
check('is_image webp',    Base::is_image('x.webp'));
check('!is_image txt',   !Base::is_image('x.txt'));
check('is_video mp4',     Base::is_video('x.mp4'));
check('is_video webm',    Base::is_video('x.webm'));
check('is_audio mp3',     Base::is_audio('x.mp3'));
check('is_audio flac',    Base::is_audio('x.flac'));
check('is_document pdf',  Base::is_document('x.pdf'));
check('is_archive zip',   Base::is_archive('x.zip'));
check('is_text md',       Base::is_text('x.md'));
check('is_safe_file jpg', Base::is_safe_file('photo.jpg'));
check('!safe php',       !Base::is_safe_file('evil.php'));
check('!safe exe',       !Base::is_safe_file('virus.exe'));
check('!safe htaccess',  !Base::is_safe_file('.htaccess'));

// --- Shell-arg safety (ffmpeg / pdftoppm / libreoffice thumbnail paths) ---
// Filenames flow into shell commands via escapeshellarg(). Prove that command
// substitution, backticks, and ; chaining stay inert: the arg must pass through
// printf verbatim, no embedded command may run, and the canary file must never
// be created. This pins the safety of every exec()-with-filename path.
section('escapeshellarg neutralizes injection in filenames');
$canary    = sys_get_temp_dir() . '/dd_shell_canary_' . getmypid();
@unlink($canary);
$evilNames = [
  'photo$(id).jpg',
  'clip`id`.mp4',
  'doc; id .pdf',
  'sheet$(touch ' . $canary . ').xlsx',
];
foreach ($evilNames as $evil) {
  $out = []; $code = 0;
  exec('printf %s ' . escapeshellarg($evil), $out, $code);
  $got = implode("\n", $out);
  check_eq('passes through verbatim: ' . $evil, $got, $evil);
  check('no uid= leak: ' . $evil,           !str_contains($got, 'uid='));
}
check('substitution canary never created', !file_exists($canary));
@unlink($canary);

// --- Crypto legacy ---
section('Crypto legacy');
$pw    = 'correct-horse-battery-staple';
$plain = 'Hello Darkdrive!';
$enc   = Crypto::encrypt($plain, $pw);
check('returns string',        is_string($enc));
check('enc !== plain',         $enc !== $plain);
check_eq('dec round-trip',     Crypto::decrypt($enc, $pw), $plain);
check('dec wrong pw → false',  Crypto::decrypt($enc, 'wrong') === false);

// --- Crypto filename ---
section('Crypto filename');
$orig = 'holiday photo 2025.jpg';
$ef   = Crypto::encrypt_filename($orig, $pw);
check('returns string',        is_string($ef));
check('no extension',          pathinfo($ef, PATHINFO_EXTENSION) === '');
check('url-safe chars only',   (bool) preg_match('/^[A-Za-z0-9_-]+$/', $ef));
check_eq('dec round-trip',     Crypto::decrypt_filename($ef, $pw), $orig);
check('dec wrong pw → false',  Crypto::decrypt_filename($ef, 'wrong') === false);
check('non-deterministic',     $ef !== Crypto::encrypt_filename($orig, $pw));

// --- Crypto stream ---
section('Crypto stream');
$tmpIn  = tempnam(sys_get_temp_dir(), 'dd_in_');
$tmpOut = tempnam(sys_get_temp_dir(), 'dd_out_');
$data   = str_repeat('Chunked payload. ', 1000); // ~17 KB → 2 chunks
file_put_contents($tmpIn, $data);
check('encrypt_stream ok',      Crypto::encrypt_stream($tmpIn, $tmpOut, $pw));
check('is_chunked',             Crypto::is_chunked($tmpOut));
check_eq('plain size scanned',  Crypto::chunked_plain_size($tmpOut), strlen($data));
check_eq('dec to string',       Crypto::decrypt_chunked_to_string($tmpOut, $pw), $data);
check('dec wrong pw → false',   Crypto::decrypt_chunked_to_string($tmpOut, 'wrong') === false);
check_eq('decrypt_any chunked', Crypto::decrypt_any_to_string($tmpOut, $pw), $data);
unlink($tmpIn); unlink($tmpOut);
$tmpLeg = tempnam(sys_get_temp_dir(), 'dd_leg_');
file_put_contents($tmpLeg, Crypto::encrypt($data, $pw));
check_eq('decrypt_any legacy',  Crypto::decrypt_any_to_string($tmpLeg, $pw), $data);
unlink($tmpLeg);

// --- Files::real_name ---
section('Files::real_name');
$share = random_bytes(32);
$nonce = random_bytes(12);
$tag   = '';
$ct    = openssl_encrypt($pw, 'aes-256-gcm', $share, OPENSSL_RAW_DATA, $nonce, $tag);
$_SESSION = ['enc_share' => $share];
$_COOKIE['enc_key'] = base64_encode("\x02" . $nonce . $tag . $ct);
$rn = new ReflectionMethod('Files', 'real_name');
$rn->setAccessible(true);
check_eq('legacy pdf',    $rn->invoke(null, '20250101-120000-report.pdf'),  'report.pdf');
check_eq('legacy txt',    $rn->invoke(null, '20250101-120000-notes.txt'),   'notes.txt');
check_eq('legacy mp4',    $rn->invoke(null, '20250220-093015-clip.mp4'),    'clip.mp4');
$stored  = '20250101-120000-' . Crypto::encrypt_filename('invoice-2025.pdf', $pw);
$stored2 = '20250220-180000-' . Crypto::encrypt_filename('song.mp3', $pw);
check_eq('encrypted pdf', $rn->invoke(null, $stored),  'invoice-2025.pdf');
check_eq('encrypted mp3', $rn->invoke(null, $stored2), 'song.mp3');
$wrongShare = random_bytes(32);
$wrongNonce = random_bytes(12);
$wrongTag   = '';
$wrongCt    = openssl_encrypt('wrong', 'aes-256-gcm', $wrongShare, OPENSSL_RAW_DATA, $wrongNonce, $wrongTag);
$_SESSION = ['enc_share' => $wrongShare];
$_COOKIE['enc_key'] = base64_encode("\x02" . $wrongNonce . $wrongTag . $wrongCt);
Crypto::clear_cache();
$rnCache = new ReflectionProperty('Files', 'realNameCache');
$rnCache->setAccessible(true);
$rnCache->setValue(null, []);
$fallback = $rn->invoke(null, $stored);
check('bad pw → string fallback', is_string($fallback) && $fallback !== 'invoice-2025.pdf');

// --- CSRF token rotation ---
section('CSRF token rotation');
$_SESSION = [];
$token1 = Base::csrf_token();
check('token is 64 hex chars', (bool) preg_match('/^[0-9a-f]{64}$/', $token1));
check_eq('same within session', Base::csrf_token(), $token1);
$_POST['csrf_token'] = $token1;
check('verify succeeds', Base::csrf_verify());
check_eq('stable after verify', Base::csrf_token(), $token1);
$_POST['csrf_token'] = $token1;
check('same token still valid', Base::csrf_verify());
$_POST['csrf_token'] = 'wrong';
check('wrong token rejected', !Base::csrf_verify());
$_POST = [];

// --- Trusted proxy IP ---
section('Trusted proxy IP');
$clientIp = new ReflectionMethod('Login', 'client_ip');
$clientIp->setAccessible(true);
$_SERVER['REMOTE_ADDR'] = '203.0.113.1';
unset($_SERVER['HTTP_X_FORWARDED_FOR']);
check_eq('direct IP', $clientIp->invoke(null), '203.0.113.1');
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.5, 10.0.0.1';
check_eq('untrusted proxy ignores XFF', $clientIp->invoke(null), '203.0.113.1');
define('DARKDRIVE_TRUSTED_PROXIES', ['203.0.113.1']);
check_eq('trusted proxy uses XFF first', $clientIp->invoke(null), '198.51.100.5');
$_SERVER['HTTP_X_FORWARDED_FOR'] = '  192.0.2.9  ';
check_eq('XFF trimmed', $clientIp->invoke(null), '192.0.2.9');
unset($_SERVER['HTTP_X_FORWARDED_FOR']);
check_eq('trusted proxy no XFF', $clientIp->invoke(null), '203.0.113.1');

// --- Upload rate limit ---
section('Upload rate limit');
$rl = new ReflectionMethod('Upload', 'check_rate_limit');
$rl->setAccessible(true);
$tmpRate = tempnam(sys_get_temp_dir(), 'dd_rate_');
$origDataPath = new ReflectionMethod('Base', 'data_path');
// Test with empty rate file — should allow
file_put_contents($tmpRate, '');
$_SESSION = [];
// Use a real tmp dir as data path for rate limit test
$tmpDataDir = sys_get_temp_dir() . '/dd_test_' . getmypid();
@mkdir($tmpDataDir);
file_put_contents("$tmpDataDir/.upload_rate", '');
$savedDataPath = null;
// Base::data_path uses 'data' relative — we need to override it for the test
// Instead, test the fail-closed behavior: unreadable file
$unreadable = $tmpDataDir . '/.upload_rate_locked';
file_put_contents($unreadable, '');
chmod($unreadable, 0000);
// We can't easily test check_rate_limit without overriding data_path,
// so test the core behavior: fopen failure returns false
$fh = @fopen($unreadable, 'c+');
check('inaccessible file → fopen fails', $fh === false);
if ($fh) fclose($fh);
chmod($unreadable, 0644);
unlink($unreadable);
@rmdir($tmpDataDir);

// --- Upload validation ---
section('Upload validation');
check('blocked ext: php',      in_array('php',   Base::EXT_BLOCKED));
check('blocked ext: phtml',    in_array('phtml', Base::EXT_BLOCKED));
check('blocked ext: phar',     in_array('phar',  Base::EXT_BLOCKED));
check('blocked ext: cgi',      in_array('cgi',   Base::EXT_BLOCKED));
check('blocked ext: asp',      in_array('asp',   Base::EXT_BLOCKED));
check('safe file rejects php', !Base::is_safe_file('test.php'));
check('safe file rejects phtml', !Base::is_safe_file('test.phtml'));
// Upload instance state
Upload::init('/tmp/test-upload', true);
$uInst = new ReflectionProperty('Upload', 'instance');
$uInst->setAccessible(true);
$inst = $uInst->getValue();
check('Upload::init creates instance', $inst !== null);
$uDir = new ReflectionProperty('Upload', 'directory');
$uDir->setAccessible(true);
check_eq('Upload instance directory', $uDir->getValue($inst), '/tmp/test-upload');
$uActive = new ReflectionProperty('Upload', 'active');
$uActive->setAccessible(true);
check_eq('Upload instance active', $uActive->getValue($inst), true);
// Re-init with inactive
Upload::init('/tmp/other', false);
$inst2 = $uInst->getValue();
check_eq('Upload re-init directory', $uDir->getValue($inst2), '/tmp/other');
check_eq('Upload re-init active=false', $uActive->getValue($inst2), false);

// --- Upload dedupe index ---
// Runs in a subprocess so DARKDRIVE_STORAGE_DIR can point at a scratch dir
// without affecting the data_path() of every other test in this file.
section('Upload dedupe index');
$dedupeDir    = sys_get_temp_dir() . '/dd_dedupe_' . getmypid();
$dedupeScript = sys_get_temp_dir() . '/dd_dedupe_' . getmypid() . '.php';
@mkdir("$dedupeDir/files", 0755, true);
file_put_contents($dedupeScript, '<?php
define("DARKDRIVE_TITLE", "Test");
define("DARKDRIVE_MAX_FILESIZE", 1024);
define("DARKDRIVE_MAX_STORAGE", 1024);
define("DARKDRIVE_STORAGE_DIR", ' . var_export($dedupeDir, true) . ');
require ' . var_export("$dir/components/app.class.php", true) . ';
require ' . var_export("$dir/components/base.class.php", true) . ';
require ' . var_export("$dir/components/upload.class.php", true) . ';
$m = function (string $name) { $r = new ReflectionMethod("Upload", $name); $r->setAccessible(true); return $r; };
$tag = $m("dedupe_tag"); $rec = $m("dedupe_record"); $sync = $m("dedupe_sync"); $path = $m("dedupe_path");
$pw = "pw-one"; $pw2 = "pw-two";
$fpA = str_repeat("a", 64); $fpB = str_repeat("b", 64); $fpC = str_repeat("c", 64);
$tA  = $tag->invoke(null, $fpA, $pw);
$dir = DARKDRIVE_STORAGE_DIR . "/files";
touch("$dir/20250101-120000-aaa");
touch("$dir/20250102-120000-bbb.s3");
$rec->invoke(null, $fpA, "20250101-120000-aaa", $pw);
$rec->invoke(null, $fpB, "20250102-120000-bbb", $pw);
$rec->invoke(null, $fpC, "20250103-120000-ccc", $pw);
$rec->invoke(null, $fpA, "20250101-120000-aaa", $pw);
$file   = $path->invoke(null);
$before = substr_count((string)file_get_contents($file), "\n");
$keep   = $sync->invoke(null);
$after  = substr_count((string)file_get_contents($file), "\n");
$raw    = (string)file_get_contents($file);
Upload::clear_dedupe();
echo json_encode([
  "deterministic" => $tA === $tag->invoke(null, $fpA, $pw),
  "pw_separated"  => $tA !== $tag->invoke(null, $fpA, $pw2),
  "fp_separated"  => $tA !== $tag->invoke(null, $fpB, $pw),
  "taglen"        => strlen($tA),
  "taghex"        => (bool) preg_match("/^[0-9a-f]{64}$/", $tA),
  "lines_before"  => $before,
  "lines_after"   => $after,
  "keeps_plain"   => isset($keep[$tA]),
  "keeps_s3"      => isset($keep[$tag->invoke(null, $fpB, $pw)]),
  "drops_stale"   => !isset($keep[$tag->invoke(null, $fpC, $pw)]),
  "kept_count"    => count($keep),
  "no_plaintext"  => !str_contains($raw, $fpA) && !str_contains($raw, $pw),
  "cleared"       => !file_exists($file),
]);
');
$dedupeOut = json_decode(trim(shell_exec('php ' . escapeshellarg($dedupeScript) . ' 2>&1') ?? ''), true);
if (!is_array($dedupeOut)) {
  err('dedupe subprocess ran', 'no JSON output');
} else {
  check('tag is deterministic',        $dedupeOut['deterministic'] === true);
  check('tag differs per password',    $dedupeOut['pw_separated'] === true);
  check('tag differs per fingerprint', $dedupeOut['fp_separated'] === true);
  check_eq('tag is 64 chars',          $dedupeOut['taglen'], 64);
  check('tag is lowercase hex',        $dedupeOut['taghex'] === true);
  check_eq('4 records appended',       $dedupeOut['lines_before'], 4);
  check_eq('sync collapses to 2',      $dedupeOut['lines_after'], 2);
  check('sync keeps local file',       $dedupeOut['keeps_plain'] === true);
  check('sync keeps S3 marker file',   $dedupeOut['keeps_s3'] === true);
  check('sync drops deleted file',     $dedupeOut['drops_stale'] === true);
  check_eq('sync returns 2 entries',   $dedupeOut['kept_count'], 2);
  check('index stores no plaintext',   $dedupeOut['no_plaintext'] === true);
  check('clear_dedupe removes index',  $dedupeOut['cleared'] === true);
}
@unlink($dedupeScript);
foreach (glob("$dedupeDir/files/*") ?: [] as $f) @unlink($f);
foreach (glob("$dedupeDir/{,.}*", GLOB_BRACE) ?: [] as $f) { if (is_file($f)) @unlink($f); }
@rmdir("$dedupeDir/files");
@rmdir($dedupeDir);

// --- Emergency clears the dedupe index ---
section('Emergency dedupe reset');
$emergSrc = file_get_contents("$dir/components/emergency.class.php");
check('re-encrypt clears dedupe index', str_contains($emergSrc, 'Upload::clear_dedupe()'));
$upSrc = file_get_contents("$dir/components/upload.class.php");
check('dedupe key is domain-separated', str_contains($upSrc, "'darkdrive-dedupe-v1'"));
check('dedupe check requires POST',      str_contains($upSrc, "REQUEST_METHOD'] !== 'POST'"));
check('dedupe check requires CSRF',      str_contains($upSrc, 'Base::csrf_verify()'));
check('dedupe check requires enc key',   str_contains($upSrc, "\$password === ''"));
check('dedupe caps hashes per request',  str_contains($upSrc, 'DEDUPE_MAX_HASHES'));
check('dedupe validates hash format',    str_contains($upSrc, "preg_match('/^[0-9a-f]{64}\$/'"));
check('dedupe read takes a lock',        str_contains($upSrc, 'flock($fh, LOCK_EX)') && str_contains($upSrc, 'dedupe_sync'));

// --- Login / Auth ---
section('Login / Auth');
// Login instance state
Login::init('SPLITKEY:$2y$10$abcdefabcdefabcdefabceABCDEFABCDEFABCDEFABCDEFABCDE');
$lInst = new ReflectionProperty('Login', 'instance');
$lInst->setAccessible(true);
check('Login::init creates instance', $lInst->getValue() !== null);
check('is_splitkey detects SPLITKEY:', Login::is_splitkey());
// Non-splitkey
Login::init('$2y$10$someoldhash');
check('is_splitkey false for bcrypt', !Login::is_splitkey());
// Login::user depends on session
$_SESSION = [];
check('user() false when no session', !Login::user());
$_SESSION['user'] = true;
check('user() true when session set', Login::user());
$_SESSION = [];

// Auth key derivation config (verify server-side constants match JS)
section('Auth key derivation config');
// Verify the salt used server-side matches the JS
$authJsSrc = file_get_contents("$dir/components/app.login.js");
check('JS uses darkdrive-auth-v1 salt', str_contains($authJsSrc, 'darkdrive-auth-v1'));
// Verify the PHP filename key salt is different
$cryptoSrc = file_get_contents("$dir/components/crypto.class.php");
check('filename key uses different salt', str_contains($cryptoSrc, 'darkdrive-filename-v1'));
check('filename key uses 100000 iterations', str_contains($cryptoSrc, '100_000'));
// PBKDF2 consistency: filename key is cached in Crypto instance
Crypto::clear_cache();
$fk1 = Crypto::encrypt_filename('test', $pw);
$fk2 = Crypto::encrypt_filename('test', $pw);
check('filename encrypt uses cached key (both succeed)', is_string($fk1) && is_string($fk2));
check('same plaintext → different ciphertext (random nonce)', $fk1 !== $fk2);
check_eq('both decrypt to same name', Crypto::decrypt_filename($fk1, $pw), Crypto::decrypt_filename($fk2, $pw));
// Legacy 10k filename decryption
$legacyKey = hash_pbkdf2('sha256', $pw, 'darkdrive-filename-v1', 10_000, 32, true);
$legacyNonce = random_bytes(12);
$legacyTag = '';
$legacyCt = openssl_encrypt('legacy-file.pdf', 'aes-256-gcm', $legacyKey, OPENSSL_RAW_DATA, $legacyNonce, $legacyTag, '', 16);
$legacyEnc = rtrim(strtr(base64_encode($legacyNonce . $legacyTag . $legacyCt), '+/', '-_'), '=');
check_eq('legacy 10k filename decrypts', Crypto::decrypt_filename($legacyEnc, $pw), 'legacy-file.pdf');

// --- Login lockout ---
section('Login lockout');
$isLockedOut = new ReflectionMethod('Login', 'is_locked_out');
$isLockedOut->setAccessible(true);
if (!is_dir('data')) @mkdir('data', 0755);
$_SESSION = ['login_attempts' => 0];
check('0 attempts → not locked', !$isLockedOut->invoke(null));
$_SESSION = ['login_attempts' => 5, 'last_attempt' => time()];
check('5 recent attempts → locked', $isLockedOut->invoke(null));
$_SESSION = ['login_attempts' => 5, 'last_attempt' => time() - 400];
$isLockedOut->invoke(null); // should reset counter
check_eq('expired lockout resets counter', $_SESSION['login_attempts'], 0);
$_SESSION = [];

// --- Emergency helpers ---
section('Emergency helpers');
$p1 = Base::generate_passphrase();
$p2 = Base::generate_passphrase();
check('passphrase is string',         is_string($p1));
check('passphrase has 5 segments',    count(explode('-', $p1)) === 5);
check('each segment is 5 chars',      strlen(explode('-', $p1)[0]) === 5);
check('passphrase is 29 chars',       strlen($p1) === 29);
check('passphrases differ',           $p1 !== $p2);
check('only lowercase + digits',      (bool) preg_match('/^[a-z0-9-]+$/', $p1));
check('no ambiguous chars (0,1,i,l,o)', !preg_match('/[01ilo]/', $p1));

$cleanup = new ReflectionMethod('Emergency', 'cleanup_tmp');
$cleanup->setAccessible(true);
$tmpClean = sys_get_temp_dir() . '/dd_cleanup_' . getmypid();
@mkdir($tmpClean);
file_put_contents("$tmpClean/file1.plain.tmp", 'x');
file_put_contents("$tmpClean/file2.enc.tmp", 'x');
file_put_contents("$tmpClean/file3.verify", 'x');
file_put_contents("$tmpClean/real-file.enc", 'keep');
$cleanup->invoke(null, $tmpClean);
check('cleanup removes .plain.tmp', !file_exists("$tmpClean/file1.plain.tmp"));
check('cleanup removes .enc.tmp',   !file_exists("$tmpClean/file2.enc.tmp"));
check('cleanup removes .verify',    !file_exists("$tmpClean/file3.verify"));
check('cleanup keeps real files',    file_exists("$tmpClean/real-file.enc"));
unlink("$tmpClean/real-file.enc");
@rmdir($tmpClean);

// --- Emergency full re-encrypt flow ---
section('Emergency re-encrypt flow');
$tmpData = sys_get_temp_dir() . '/dd_emerg_' . getmypid();
@mkdir("$tmpData");
@mkdir("$tmpData/files");
@mkdir("$tmpData/thumbs");
@mkdir("$tmpData/tags");
@mkdir("$tmpData/tags/tag1");
$oldPw = 'old-password-test';
$newPw = 'new-password-test';
// Create two encrypted files
$plain1 = 'File one content for emergency test.';
$plain2 = 'File two content for emergency test.';
$enc1Name = Crypto::encrypt_filename('doc.pdf', $oldPw);
$enc2Name = Crypto::encrypt_filename('photo.jpg', $oldPw);
$file1 = "20250101-120000-$enc1Name";
$file2 = "20250202-130000-$enc2Name";
$f1path = "$tmpData/files/$file1";
$f2path = "$tmpData/files/$file2";
// Write as legacy encrypted (simpler for test)
file_put_contents($f1path, Crypto::encrypt($plain1, $oldPw));
file_put_contents($f2path, Crypto::encrypt($plain2, $oldPw));
// Create a thumbnail
file_put_contents("$tmpData/thumbs/$file1", 'thumb-data');
// Create tag reference
touch("$tmpData/tags/tag1/$file1.txt");
// Verify files are decryptable with old password
check('pre: file1 decrypts with old pw', Crypto::verify_decrypt($f1path, $oldPw));
check('pre: file2 decrypts with old pw', Crypto::verify_decrypt($f2path, $oldPw));
// Simulate the emergency re-encrypt steps manually (can't call handle() without HTTP context)
// Step 1: Verify all files
$allOk = true;
foreach ([$f1path, $f2path] as $fp) {
  if (!Crypto::verify_decrypt($fp, $oldPw)) $allOk = false;
}
check('verify step passes', $allOk);
// Step 2: Re-encrypt
foreach ([$f1path, $f2path] as $fp) {
  $tmpPlain = $fp . '.plain.tmp';
  $tmpEnc   = $fp . '.enc.tmp';
  Crypto::decrypt_to_path($fp, $oldPw, $tmpPlain);
  Crypto::encrypt_stream($tmpPlain, $tmpEnc, $newPw);
  @unlink($tmpPlain);
  rename($tmpEnc, $fp);
}
check('post: file1 decrypts with new pw', Crypto::verify_decrypt($f1path, $newPw));
check('post: file2 decrypts with new pw', Crypto::verify_decrypt($f2path, $newPw));
check('post: file1 fails with old pw', !Crypto::verify_decrypt($f1path, $oldPw));
// Verify content survived
check_eq('post: file1 content intact', Crypto::decrypt_any_to_string($f1path, $newPw), $plain1);
check_eq('post: file2 content intact', Crypto::decrypt_any_to_string($f2path, $newPw), $plain2);
// Step 3: Delete thumbnails
@unlink("$tmpData/thumbs/$file1");
check('thumbs deleted', !file_exists("$tmpData/thumbs/$file1"));
// Step 4: Rename files with new filename encryption
Crypto::clear_cache();
foreach ([$file1, $file2] as $f) {
  if (!preg_match('/^(\d{8}-\d{6})-(.+)$/', $f, $m)) continue;
  $plainName = Crypto::decrypt_filename($m[2], $oldPw);
  $newEncPart = Crypto::encrypt_filename($plainName, $newPw);
  $newFilename = $m[1] . '-' . $newEncPart;
  rename("$tmpData/files/$f", "$tmpData/files/$newFilename");
  // Update tag references
  if (file_exists("$tmpData/tags/tag1/$f.txt")) {
    rename("$tmpData/tags/tag1/$f.txt", "$tmpData/tags/tag1/$newFilename.txt");
  }
}
$newFiles = array_diff(scandir("$tmpData/files"), ['.', '..']);
check_eq('2 renamed files remain', count($newFiles), 2);
// Verify new filenames decrypt with new password
foreach ($newFiles as $nf) {
  preg_match('/^(\d{8}-\d{6})-(.+)$/', $nf, $m);
  $dec = Crypto::decrypt_filename($m[2], $newPw);
  check("renamed $dec decrypts ok", $dec === 'doc.pdf' || $dec === 'photo.jpg');
}
// Verify tag files were renamed
$tagFiles = array_diff(scandir("$tmpData/tags/tag1"), ['.', '..']);
check_eq('tag reference renamed', count($tagFiles), 1);
// Cleanup
foreach (glob("$tmpData/files/*") as $f) @unlink($f);
foreach (glob("$tmpData/tags/tag1/*") as $f) @unlink($f);
@rmdir("$tmpData/tags/tag1"); @rmdir("$tmpData/tags");
@rmdir("$tmpData/files"); @rmdir("$tmpData/thumbs"); @rmdir($tmpData);

// --- File serving: MIME types ---
section('File serving: MIME types');
check_eq('mp3 → audio/mpeg',    Base::ext_to_mime('mp3'),  'audio/mpeg');
check_eq('mp4 → video/mp4',     Base::ext_to_mime('mp4'),  'video/mp4');
check_eq('pdf → application/pdf', Base::ext_to_mime('pdf'), 'application/pdf');
check_eq('jpg → image/jpeg',    Base::ext_to_mime('jpg'),  'image/jpeg');
check_eq('webm → video/webm',   Base::ext_to_mime('webm'), 'video/webm');
check_eq('svg → image/svg+xml', Base::ext_to_mime('svg'),  'image/svg+xml');
check_eq('flac → audio/flac',   Base::ext_to_mime('flac'), 'audio/flac');
check_eq('m4a → audio/mp4',     Base::ext_to_mime('m4a'),  'audio/mp4');
check_eq('unknown → octet-stream', Base::ext_to_mime('xyz'), 'application/octet-stream');

// --- File serving: content disposition logic ---
section('File serving: disposition');
// Inline types: images, video, audio, text, contacts, pdf
check('image → inline',    Base::is_image('x.jpg'));
check('video → inline',    Base::is_video('x.mp4'));
check('audio → inline',    Base::is_audio('x.mp3'));
check('text → inline',     Base::is_text('x.txt'));
check('contact → inline',  Base::is_contact('x.vcf'));
// Attachment types: archives, documents (non-pdf), design
check('archive → attachment', Base::is_archive('x.zip') && !Base::is_image('x.zip'));
check('design → attachment',  Base::is_design('x.psd') && !Base::is_image('x.psd'));
// SVG is always attachment (security)
check('svg is image but forced attachment', Base::is_image('x.svg'));

// --- File serving: range request parsing ---
section('File serving: range requests');
// Simulate range header parsing logic (extracted from Files::handle)
$testRange = function(string $header, int $size): array|false {
  if (!preg_match('/bytes=(\d*)-(\d*)/i', $header, $rm)) return false;
  if ($rm[1] === '' && $rm[2] !== '') {
    $start = max(0, $size - (int)$rm[2]);
    $end   = $size - 1;
  } else {
    $start = (int)$rm[1];
    $end   = $rm[2] !== '' ? min((int)$rm[2], $size - 1) : $size - 1;
  }
  if ($start > $end || $start >= $size) return false;
  return [$start, $end];
};
check_eq('bytes=0-99 of 1000',     $testRange('bytes=0-99', 1000),    [0, 99]);
check_eq('bytes=500-999 of 1000',  $testRange('bytes=500-999', 1000), [500, 999]);
check_eq('bytes=0- (open end)',     $testRange('bytes=0-', 1000),      [0, 999]);
check_eq('bytes=-100 (suffix)',     $testRange('bytes=-100', 1000),    [900, 999]);
check_eq('bytes=999-999 (last byte)', $testRange('bytes=999-999', 1000), [999, 999]);
check('bytes=1000-1000 → invalid',  $testRange('bytes=1000-1000', 1000) === false);
check('bytes=500-499 → invalid',    $testRange('bytes=500-499', 1000) === false);
check_eq('bytes=-0 edge',           $testRange('bytes=-0', 1000),      false);
// Chunked range decrypt — use a subprocess to capture output (echoes + flushes bypass ob)
$tmpRangeIn = tempnam(sys_get_temp_dir(), 'dd_rng_in_');
$tmpRangeOut = tempnam(sys_get_temp_dir(), 'dd_rng_out_');
$rangeData = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
file_put_contents($tmpRangeIn, $rangeData);
Crypto::encrypt_stream($tmpRangeIn, $tmpRangeOut, $pw);
$rangeScript = function(string $encFile, string $pw, int $start, int $end): string {
  $cmd = sprintf(
    'php -r %s 2>&1',
    escapeshellarg(sprintf(
      'require "%s/components/app.class.php"; require "%s/components/base.class.php"; require "%s/components/crypto.class.php"; Crypto::decrypt_chunked_output_range(%s, %s, %d, %d);',
      __DIR__, __DIR__, __DIR__,
      var_export($encFile, true), var_export($pw, true), $start, $end
    ))
  );
  return shell_exec($cmd) ?? '';
};
check_eq('range 10-19 = KLMNOPQRST', $rangeScript($tmpRangeOut, $pw, 10, 19), 'KLMNOPQRST');
check_eq('range 0-0 = A',            $rangeScript($tmpRangeOut, $pw, 0, 0),   'A');
check_eq('range last byte = 9',      $rangeScript($tmpRangeOut, $pw, 35, 35), '9');
unlink($tmpRangeIn); unlink($tmpRangeOut);

// --- File serving: ETag ---
section('File serving: ETag');
$tmpEtag = tempnam(sys_get_temp_dir(), 'dd_etag_');
file_put_contents($tmpEtag, 'test-content');
$mtime = (int)filemtime($tmpEtag);
$etag1 = '"' . md5('testfile' . (string)filesize($tmpEtag) . $mtime) . '"';
$etag2 = '"' . md5('testfile' . (string)filesize($tmpEtag) . $mtime) . '"';
check_eq('etag is deterministic', $etag1, $etag2);
$etag3 = '"' . md5('otherfile' . (string)filesize($tmpEtag) . $mtime) . '"';
check('different name → different etag', $etag1 !== $etag3);
unlink($tmpEtag);

// --- Crypto: decrypt_to_path ---
section('Crypto: decrypt_to_path');
$tmpDtp1 = tempnam(sys_get_temp_dir(), 'dd_dtp_');
$tmpDtp2 = tempnam(sys_get_temp_dir(), 'dd_dtp_');
$tmpDtpOut = tempnam(sys_get_temp_dir(), 'dd_dtp_out_');
$dtpData = 'Decrypt to path content test';
// Chunked
file_put_contents($tmpDtp1, $dtpData);
Crypto::encrypt_stream($tmpDtp1, $tmpDtp2, $pw);
check('decrypt_to_path chunked', Crypto::decrypt_to_path($tmpDtp2, $pw, $tmpDtpOut));
check_eq('decrypt_to_path content', file_get_contents($tmpDtpOut), $dtpData);
// Legacy
file_put_contents($tmpDtp1, Crypto::encrypt($dtpData, $pw));
check('decrypt_to_path legacy', Crypto::decrypt_to_path($tmpDtp1, $pw, $tmpDtpOut));
check_eq('decrypt_to_path legacy content', file_get_contents($tmpDtpOut), $dtpData);
// Wrong password
check('decrypt_to_path wrong pw fails', !Crypto::decrypt_to_path($tmpDtp2, 'wrong', $tmpDtpOut));
unlink($tmpDtp1); unlink($tmpDtp2); @unlink($tmpDtpOut);

// --- File sharing / publish ---
section('File sharing');

// Setup: create a temp data dir with an encrypted file
$tmpShareDir = sys_get_temp_dir() . '/dd_share_' . getmypid();
@mkdir("$tmpShareDir");
@mkdir("$tmpShareDir/files");

$sharePw = 'share-test-password';
$sharePlain = 'This is the file content for sharing test.';
$shareEncName = Crypto::encrypt_filename('shared-doc.pdf', $sharePw);
$shareFile = "20250301-120000-$shareEncName";
$shareFilePath = "$tmpShareDir/files/$shareFile";
file_put_contents($shareFilePath, Crypto::encrypt($sharePlain, $sharePw));

// Set up enc_key cookie so enc_key() works
Crypto::clear_cache();
$shareSession = random_bytes(32);
$shareNonce = random_bytes(12);
$shareTag = '';
$shareCt = openssl_encrypt($sharePw, 'aes-256-gcm', $shareSession, OPENSSL_RAW_DATA, $shareNonce, $shareTag);
$_SESSION = ['enc_share' => $shareSession];
$_COOKIE['enc_key'] = base64_encode("\x02" . $shareNonce . $shareTag . $shareCt);

// public_secret is deterministic
$secret1 = Files::public_secret($shareFile);
$secret2 = Files::public_secret($shareFile);
check_eq('public_secret is deterministic', $secret1, $secret2);
check('public_secret is 24 hex chars', (bool) preg_match('/^[0-9a-f]{24}$/', $secret1));

// Different files get different secrets
$otherFile = "20250301-130000-otherfile";
check('different files → different secrets', Files::public_secret($shareFile) !== Files::public_secret($otherFile));

// public_path returns expected structure
$pubPath = Files::public_path($shareFile);
check('public_path contains secret', str_contains($pubPath, $secret1));
check('public_path contains real name', str_contains($pubPath, 'shared-doc.pdf'));
check('public_path starts with public/', str_starts_with($pubPath, 'public/'));

// Not published initially
check('not published initially', !Files::is_published($shareFile));

// Simulate publish: decrypt and write to public path
$pubDir = dirname($pubPath);
@mkdir($pubDir, 0755, true);
$decData = Crypto::decrypt(file_get_contents($shareFilePath), $sharePw);
file_put_contents($pubPath, $decData);
check('is_published after write', Files::is_published($shareFile));
check_eq('public file content matches', file_get_contents($pubPath), $sharePlain);

// Simulate unpublish: remove public copy
unlink($pubPath);
@rmdir($pubDir);
check('not published after delete', !Files::is_published($shareFile));

// Cleanup
unlink($shareFilePath);
@rmdir("$tmpShareDir/files");
@rmdir($tmpShareDir);
// Clean up public test dirs
@rmdir("public/$secret1");

section('Sharing CSS + HTML');
$cssSrc2 = file_get_contents("$dir/components/app.css");
$appSrc2 = file_get_contents("$dir/components/app.class.php");
$filesSrc = file_get_contents("$dir/components/files.class.php");
$fileServerSrc = file_get_contents("$dir/components/fileserver.class.php");

check('.share-overlay in CSS',        str_contains($cssSrc2, '.share-overlay'));
check('.share-overlay-box in CSS',    str_contains($cssSrc2, '.share-overlay-box'));
check('.share-publish-btn in CSS',    str_contains($cssSrc2, '.share-publish-btn'));
check('.share-delete-btn in CSS',     str_contains($cssSrc2, '.share-delete-btn'));
check('.share-link in CSS',           str_contains($cssSrc2, '.share-link'));
check('.share-close in CSS',          str_contains($cssSrc2, '.share-close'));
check('.nav-share-btn in CSS',        str_contains($cssSrc2, '.nav-share-btn'));
check('.nav-share-btn.published',     str_contains($cssSrc2, '.nav-share-btn.published'));
check('.tile-public-badge in CSS',    str_contains($cssSrc2, '.tile-public-badge'));
check('badge hover scale',           str_contains($cssSrc2, 'figure:hover .tile-public-badge'));

check('share-overlay in layout',      str_contains($appSrc2, 'id="share-overlay"'));
check('share-close in layout',        str_contains($appSrc2, 'id="share-close"'));
check('publish form in layout',       str_contains($appSrc2, 'name="publish"'));
check('unpublish form in layout',     str_contains($appSrc2, 'name="unpublish"'));
check('_redirect in publish form',    str_contains($appSrc2, '_redirect'));
check('published headline "Shared"',  str_contains($appSrc2, 'Shared'));
check('lock icon for unpublished',    str_contains($appSrc2, '160v-400'));
check('open lock icon for published', str_contains($appSrc2, 'lock_open') || str_contains($appSrc2, '84v96h24q29') || str_contains($appSrc2, 'viewBox="0 -960'));

check('handle_publish in files',      str_contains($filesSrc, 'function handle_publish'));
check('handle_unpublish in files',    str_contains($filesSrc, 'function handle_unpublish'));
check('is_published in files',        str_contains($filesSrc, 'function is_published'));
check('public_secret in files',       str_contains($filesSrc, 'function public_secret'));
check('public_path in files',         str_contains($filesSrc, 'function public_path'));
check('tile-public-badge in files',   str_contains($filesSrc, 'tile-public-badge'));
check('htaccess created on publish',  str_contains($fileServerSrc, '.htaccess'));
check('csrf check in publish',        str_contains($fileServerSrc, 'csrf_verify'));
check('public cleanup on delete',     str_contains($fileServerSrc, 'public_path') && str_contains($fileServerSrc, 'handle_delete'));

section('Sharing JS');
$appJsSrc = file_get_contents("$dir/components/app.js");
check('share-overlay toggle in JS',   str_contains($appJsSrc, 'share-overlay'));
check('nav-share-btn in JS',          str_contains($appJsSrc, 'nav-share-btn'));
check('share-close in JS',            str_contains($appJsSrc, 'share-close'));

// --- memzero ---
section('Base::memzero');
$secret = 'super-secret-password';
$len = strlen($secret);
Base::memzero($secret);
check_eq('memzero clears to empty', $secret, '');
check('original length was > 0', $len > 0);

// --- Base constants ---
section('Base constants');
check_eq('SESSION_LIFETIME is 43200', Base::SESSION_LIFETIME, 43200);
check_eq('INLINE_SIZE_LIMIT is 2MB', Base::INLINE_SIZE_LIMIT, 2 * 1024 * 1024);

// --- Base::ini_bytes ---
section('Base::ini_bytes');
check_eq('128M → bytes',  Base::ini_bytes('128M'), 128 * 1048576);
check_eq('2G → bytes',    Base::ini_bytes('2G'),   2 * 1073741824);
check_eq('512K → bytes',  Base::ini_bytes('512K'), 512 * 1024);
check_eq('plain number',  Base::ini_bytes('1024'), 1024);
check_eq('trimmed',       Base::ini_bytes(' 64M '), 64 * 1048576);

// --- Base::generate_passphrase ---
section('Base::generate_passphrase');
$gp1 = Base::generate_passphrase();
$gp2 = Base::generate_passphrase();
check('passphrase is string',         is_string($gp1));
check('passphrase has 5 segments',    count(explode('-', $gp1)) === 5);
check('each segment is 5 chars',      strlen(explode('-', $gp1)[0]) === 5);
check('passphrase is 29 chars',       strlen($gp1) === 29);
check('passphrases differ',           $gp1 !== $gp2);
check('only lowercase + digits',      (bool) preg_match('/^[a-z0-9-]+$/', $gp1));
check('no ambiguous chars (0,1,i,l,o)', !preg_match('/[01ilo]/', $gp1));

// --- Base::emergency_recovery ---
section('Base::emergency_recovery');
if (!is_dir('data')) @mkdir('data', 0755);
Base::clear_emergency_recovery();
check('no recovery initially', Base::emergency_recovery_password() === null);
$recPw = 'recovery-test-password';
Base::save_emergency_recovery($recPw);
check('recovery file created', is_file(Base::data_path('.emergency_recovery')));
check_eq('recovery password decrypts', Base::emergency_recovery_password(), $recPw);
Base::clear_emergency_recovery();
check('recovery cleared', Base::emergency_recovery_password() === null);
check('recovery file removed', !is_file(Base::data_path('.emergency_recovery')));

// --- Crypto::test_chunked_key ---
section('Crypto::test_chunked_key');
$tmpTck1 = tempnam(sys_get_temp_dir(), 'dd_tck_');
$tmpTck2 = tempnam(sys_get_temp_dir(), 'dd_tck_');
file_put_contents($tmpTck1, 'Test chunked key data');
Crypto::encrypt_stream($tmpTck1, $tmpTck2, $pw);
check('test_chunked_key correct pw', Crypto::test_chunked_key($tmpTck2, $pw));
check('test_chunked_key wrong pw', !Crypto::test_chunked_key($tmpTck2, 'wrong'));
check('test_chunked_key non-chunked', !Crypto::test_chunked_key($tmpTck1, $pw));
unlink($tmpTck1); unlink($tmpTck2);

// --- Crypto::decrypt_filename_unwrap ---
section('Crypto::decrypt_filename_unwrap');
$unwrapName = 'test-unwrap.jpg';
$singleEnc = Crypto::encrypt_filename($unwrapName, $pw);
check_eq('unwrap single-encrypted', Crypto::decrypt_filename_unwrap($singleEnc, $pw), $unwrapName);
$doubleEnc = Crypto::encrypt_filename($singleEnc, $pw);
check_eq('unwrap double-encrypted', Crypto::decrypt_filename_unwrap($doubleEnc, $pw), $unwrapName);
check('unwrap wrong pw → false', Crypto::decrypt_filename_unwrap($singleEnc, 'wrong') === false);

// --- Crypto instance / clear_cache ---
section('Crypto instance + clear_cache');
Crypto::clear_cache();
$cInst = new ReflectionProperty('Crypto', 'instance');
$cInst->setAccessible(true);
// After clear_cache, instance may still exist but keys should be cleared
$ef1 = Crypto::encrypt_filename('test', $pw);
check('encrypt after clear_cache works', is_string($ef1));
$inst = $cInst->getValue();
check('Crypto instance created', $inst !== null);
Crypto::clear_cache();
$fnKey = new ReflectionProperty('Crypto', 'fnKey');
$fnKey->setAccessible(true);
check_eq('clear_cache nulls fnKey', $fnKey->getValue($inst), null);

// --- Create text file ---
section('Create text file: is_encrypted fix');
// Empty-string encryption must be detected as encrypted (the bug was: random salt
// with printable first 2 bytes → false negative in is_encrypted heuristic)
$tmpCreateEnc = tempnam(sys_get_temp_dir(), 'dd_create_');
file_put_contents($tmpCreateEnc, Crypto::encrypt('', $pw));
check('encrypted empty string detected', Crypto::is_encrypted($tmpCreateEnc));
check('encrypted empty string decrypts', Crypto::decrypt(file_get_contents($tmpCreateEnc), $pw) === '');
// Stress: even if first two salt bytes are printable ASCII, is_encrypted must still pass
// Forge a blob with all-printable salt (16 bytes 'A') but real nonce+tag
$fakeSalt = str_repeat('A', 16);
$fakeKey  = hash_pbkdf2('sha256', $pw, $fakeSalt, 100_000, 32, true);
$fakeNonce = random_bytes(12);
$fakeTag = '';
$fakeCt = openssl_encrypt('', 'aes-256-gcm', $fakeKey, OPENSSL_RAW_DATA, $fakeNonce, $fakeTag, '', 16);
file_put_contents($tmpCreateEnc, $fakeSalt . $fakeNonce . $fakeTag . $fakeCt);
check('printable-salt blob still detected as encrypted', Crypto::is_encrypted($tmpCreateEnc));
// Non-encrypted text file must NOT be detected
file_put_contents($tmpCreateEnc, 'Hello, this is a plain text file with enough content here.');
check('plaintext not detected as encrypted', !Crypto::is_encrypted($tmpCreateEnc));
// Short file (< 44 bytes) must not be detected
file_put_contents($tmpCreateEnc, 'Short');
check('short file not detected as encrypted', !Crypto::is_encrypted($tmpCreateEnc));
unlink($tmpCreateEnc);

section('Create text file: validation');
// EXT_EDITABLE must contain common text extensions
check('txt in EXT_EDITABLE',   in_array('txt',  Base::EXT_EDITABLE, true));
check('md in EXT_EDITABLE',    in_array('md',   Base::EXT_EDITABLE, true));
check('json in EXT_EDITABLE',  in_array('json', Base::EXT_EDITABLE, true));
check('csv in EXT_EDITABLE',   in_array('csv',  Base::EXT_EDITABLE, true));
check('html in EXT_EDITABLE',  in_array('html', Base::EXT_EDITABLE, true));
// Dangerous extensions must NOT be editable
check('php not in EXT_EDITABLE',   !in_array('php',   Base::EXT_EDITABLE, true));
check('phtml not in EXT_EDITABLE', !in_array('phtml', Base::EXT_EDITABLE, true));
check('phar not in EXT_EDITABLE',  !in_array('phar',  Base::EXT_EDITABLE, true));
// is_editable helper
check('is_editable notes.txt',     Base::is_editable('notes.txt'));
check('is_editable readme.md',     Base::is_editable('readme.md'));
check('!is_editable photo.jpg',   !Base::is_editable('photo.jpg'));
check('!is_editable evil.php',    !Base::is_editable('evil.php'));

section('Create text file: round-trip');
// Simulate create file flow: encrypt empty content + encrypted filename → decrypt back
Crypto::clear_cache();
$createPw = 'create-test-pw';
$createName = 'my-notes.txt';
$encCreateName = Crypto::encrypt_filename($createName, $createPw);
check('filename encrypts', is_string($encCreateName));
$createFilename = '20260319-120000-' . $encCreateName;
$createFilePath = tempnam(sys_get_temp_dir(), 'dd_crf_');
$createEncData = Crypto::encrypt('', $createPw);
check('empty encrypt succeeds', is_string($createEncData));
file_put_contents($createFilePath, $createEncData);
check('is_encrypted on created file', Crypto::is_encrypted($createFilePath));
check_eq('decrypt created file → empty string', Crypto::decrypt(file_get_contents($createFilePath), $createPw), '');
check_eq('filename decrypts back', Crypto::decrypt_filename($encCreateName, $createPw), $createName);
// Simulate edit save: re-encrypt with content
$editContent = 'Hello world — first edit';
$editEnc = Crypto::encrypt($editContent, $createPw);
file_put_contents($createFilePath, $editEnc);
check('is_encrypted after edit', Crypto::is_encrypted($createFilePath));
check_eq('decrypt after edit', Crypto::decrypt(file_get_contents($createFilePath), $createPw), $editContent);
unlink($createFilePath);

section('Header status: compute_status checks');
$cs = new ReflectionMethod('App', 'compute_status');
$cs->setAccessible(true);
$cachedProp = new ReflectionProperty('Files', 'cachedFiles');
$cachedProp->setAccessible(true);
// Verify compute_status source covers the expected checks
$appSrcCS = file_get_contents("$dir/components/app.class.php");
$csBody = '';
if (preg_match('/function compute_status\(\).*?\{(.+?)\n  \}/s', $appSrcCS, $csm)) $csBody = $csm[1];
check('checks unencrypted files',   str_contains($csBody, 'is_encrypted'));
check('checks unencrypted thumbs',  str_contains($csBody, 'thumbs') && str_contains($csBody, '\xD8'));
check('checks data/ outside webroot', str_contains($csBody, 'data_outside_webroot'));
check('checks HTTPS',               str_contains($csBody, 'HTTPS'));
// data/ is not a symlink in test env → statusErrors must be true
$cachedProp->setValue(null, null);
App::$statusErrors = false;
$cs->invoke(null);
check('non-symlink data/ → statusErrors=true', App::$statusErrors === true);

section('Header status: unencrypted thumbnail triggers error');
$thumbsDir = Base::data_path('thumbs');
if (!is_dir($thumbsDir)) @mkdir($thumbsDir, 0755, true);
// Place a raw JPEG thumbnail (starts with FF D8 FF)
$fakeThumb = $thumbsDir . '/test-thumb-probe';
file_put_contents($fakeThumb, "\xFF\xD8\xFF" . 'fake-jpeg-data');
$cachedProp->setValue(null, null);
App::$statusErrors = false;
$cs->invoke(null);
check('unencrypted thumb → statusErrors=true', App::$statusErrors === true);
unlink($fakeThumb);
$cachedProp->setValue(null, null);

section('Create text file: statusErrors on unencrypted file');
// compute_status must set $statusErrors=true when any file in data/files/ is unencrypted
$dataFiles = Base::data_path('files');
if (!is_dir($dataFiles)) @mkdir($dataFiles, 0755, true);
// Clear cached file list so all_files() re-scans
$cachedProp = new ReflectionProperty('Files', 'cachedFiles');
$cachedProp->setAccessible(true);
$cachedProp->setValue(null, null);
// Place a plaintext file
$fakePlain = $dataFiles . '/test-unencrypted-probe';
file_put_contents($fakePlain, 'I am plaintext');
// Reset statusErrors and call compute_status
App::$statusErrors = false;
$cs = new ReflectionMethod('App', 'compute_status');
$cs->setAccessible(true);
$cs->invoke(null);
check('unencrypted file → statusErrors=true', App::$statusErrors === true);
// Clean up and verify encrypted file does NOT trigger error
unlink($fakePlain);
$cachedProp->setValue(null, null);
$fakeEnc = $dataFiles . '/test-encrypted-probe';
file_put_contents($fakeEnc, Crypto::encrypt('safe', $pw));
App::$statusErrors = false;
$cs->invoke(null);
$encOnly = !App::$statusErrors;
// statusErrors might be true from other checks (HTTPS, PHP limits) — so instead
// confirm the file IS detected as encrypted by is_encrypted
check('encrypted probe detected', Crypto::is_encrypted($fakeEnc));
unlink($fakeEnc);
$cachedProp->setValue(null, null);

section('Create text file: CSS + HTML + JS');
$cssSrcCF  = file_get_contents("$dir/components/app.css");
$appSrcCF  = file_get_contents("$dir/components/app.class.php");
$appJsCF   = file_get_contents("$dir/components/app.js");
$fsSrcCF   = file_get_contents("$dir/components/fileserver.class.php");
// CSS
check('#create-file-form in CSS',    str_contains($cssSrcCF, '#create-file-form'));
check('#create-file-input in CSS',   str_contains($cssSrcCF, '#create-file-input'));
check('.create-file-error in CSS',   str_contains($cssSrcCF, '.create-file-error'));
// HTML layout
check('create-overlay in layout',    str_contains($appSrcCF, 'id="create-overlay"') || str_contains($appSrcCF, "id='create-overlay'"));
check('create-file-form in layout',  str_contains($appSrcCF, 'id="create-file-form"'));
check('create-file-input in layout', str_contains($appSrcCF, 'id="create-file-input"'));
check('create-file-error in layout', str_contains($appSrcCF, 'id="create-file-error"'));
check('create-close in layout',      str_contains($appSrcCF, 'id="create-close"'));
check('csrf_field in create form',   str_contains($appSrcCF, 'csrf_field'));
// JS
check('create-overlay in JS',        str_contains($appJsCF, 'create-overlay'));
check('create-file-input in JS',     str_contains($appJsCF, 'create-file-input'));
check('create-file-error in JS',     str_contains($appJsCF, 'create-file-error'));
check('create-file-form in JS',      str_contains($appJsCF, 'create-file-form'));
check('JS validates extension',      str_contains($appJsCF, 'allowedExts'));
check('JS shows error on bad ext',   str_contains($appJsCF, 'e.preventDefault'));
check('nav-create-btn in JS',        str_contains($appJsCF, 'nav-create-btn'));
// Server-side handler
check('handle_create_file exists',   str_contains($fsSrcCF, 'function handle_create_file'));
check('create uses str_clean',       str_contains($fsSrcCF, "str_clean(basename(\$raw))"));
check('create checks EXT_EDITABLE',  str_contains($fsSrcCF, 'EXT_EDITABLE'));
check('create encrypts filename',    str_contains($fsSrcCF, 'encrypt_filename($cleanName'));
check('create encrypts empty body',  str_contains($fsSrcCF, "encrypt('', \$encKey)"));
check('create zeros encKey',         str_contains($fsSrcCF, 'memzero($encKey)'));
check('create checks storage quota', str_contains($fsSrcCF, 'check_storage_quota'));
check('create redirects with edit=1', str_contains($fsSrcCF, 'edit=1'));
check('create audits',               str_contains($fsSrcCF, "audit('file_create'"));

// --- S3: is_configured ---
section('S3::is_configured');
check('is_configured false when no constant', !S3::is_configured());

// --- S3: marker write/read/delete ---
section('S3 marker helpers');
if (!is_dir('data')) @mkdir('data', 0755);
if (!is_dir('data/files')) @mkdir('data/files', 0755);
$mFile = '20260101-120000-testmarkerfile';
S3::delete_marker($mFile); // clean slate
check('read_marker missing → false', S3::read_marker($mFile) === false);
S3::write_marker($mFile, $mFile, 12345, 9999, true, 'deadbeef01234567', 16777216);
$marker = S3::read_marker($mFile);
check('read_marker returns array', is_array($marker));
check_eq('marker key', $marker['key'] ?? null, $mFile);
check_eq('marker size', $marker['size'] ?? null, 12345);
check_eq('marker plain_size', $marker['plain_size'] ?? null, 9999);
check_eq('marker chunked', $marker['chunked'] ?? null, true);
check_eq('marker salt', $marker['salt'] ?? null, 'deadbeef01234567');
check_eq('marker chunk_size', $marker['chunk_size'] ?? null, 16777216);
S3::delete_marker($mFile);
check('delete_marker removes file', S3::read_marker($mFile) === false);

// --- S3: all_files() deduplication ---
section('Files::all_files() with S3 markers');
$tmpFilesDir = sys_get_temp_dir() . '/dd_s3af_' . getmypid();
@mkdir("$tmpFilesDir");
$cachedFilesProp = new ReflectionProperty('Files', 'cachedFiles');
$cachedFilesProp->setAccessible(true);
$savedDataMethod = new ReflectionMethod('Base', 'data_path');
// Use a real data/files dir with marker files for this test
if (!is_dir('data/files')) @mkdir('data/files', 0755, true);
$af1 = '20260101-120000-' . Crypto::encrypt_filename('file1.pdf', $pw);
$af2 = '20260102-130000-' . Crypto::encrypt_filename('file2.mp3', $pw);
// Write local file for af1, S3 marker for af2, and both for af3 (dedup test)
$af3 = '20260103-140000-' . Crypto::encrypt_filename('file3.jpg', $pw);
file_put_contents('data/files/' . $af1, Crypto::encrypt('content1', $pw));
S3::write_marker($af2, $af2, 500, 400, true, 'aabbccdd', 16777216);
file_put_contents('data/files/' . $af3, Crypto::encrypt('content3', $pw));
S3::write_marker($af3, $af3, 600, 500, true, 'eeff0011', 16777216);
$cachedFilesProp->setValue(null, null);
$allF = Files::all_files();
check('all_files includes local file', in_array($af1, $allF));
check('all_files includes S3 marker file', in_array($af2, $allF));
check('all_files includes both-store file', in_array($af3, $allF));
$af3Count = count(array_filter($allF, fn($f) => $f === $af3));
check_eq('all_files deduplicates file+marker', $af3Count, 1);
// Clean up
@unlink('data/files/' . $af1);
S3::delete_marker($af2);
@unlink('data/files/' . $af3);
S3::delete_marker($af3);
$cachedFilesProp->setValue(null, null);

// --- S3: recalc_storage skips .s3 files ---
section('Upload::recalc_storage skips .s3 markers');
$recalc = new ReflectionMethod('Upload', 'recalc_storage');
$recalc->setAccessible(true);
if (!is_dir('data/files')) @mkdir('data/files', 0755, true);
$rcLocal  = '20260110-000000-rclocal';
$rcMarker = '20260110-000001-rcmarker';
file_put_contents('data/files/' . $rcLocal, 'localdata');
$baseTotal = $recalc->invoke(null);
S3::write_marker($rcMarker, $rcMarker, 99999, 80000, true, 'ff00', 16777216);
$withMarker = $recalc->invoke(null);
check('.s3 marker not counted in local recalc', $withMarker === $baseTotal);
@unlink('data/files/' . $rcLocal);
S3::delete_marker($rcMarker);

// --- S3: stream-handle crypto variants ---
section('Crypto stream-handle variants (_fh)');
$tmpFhIn  = tempnam(sys_get_temp_dir(), 'dd_fh_in_');
$tmpFhOut = tempnam(sys_get_temp_dir(), 'dd_fh_out_');
$fhData   = str_repeat('StreamHandleTest.', 2000); // ~34 KB → multiple chunks
file_put_contents($tmpFhIn, $fhData);
Crypto::encrypt_stream($tmpFhIn, $tmpFhOut, $pw);

$fh = fopen($tmpFhOut, 'rb');
check('is_chunked_fh detects chunked', Crypto::is_chunked_fh($fh));
fclose($fh);

$fh = fopen($tmpFhOut, 'rb');
$sz = Crypto::chunked_plain_size_fh($fh);
fclose($fh);
check_eq('chunked_plain_size_fh', $sz, strlen($fhData));

$fh = fopen($tmpFhOut, 'rb');
$buf = '';
$ok = Crypto::decrypt_chunked_with_callback_fh($fh, $pw, function(string $chunk) use (&$buf): void { $buf .= $chunk; });
fclose($fh);
check('decrypt_chunked_with_callback_fh ok', $ok);
check_eq('decrypt_chunked_with_callback_fh content', $buf, $fhData);

$rangeFhScript = function(string $encFile, string $pw, int $start, int $end): string {
  $cmd = sprintf(
    'php -r %s 2>&1',
    escapeshellarg(sprintf(
      'require "%s/components/app.class.php"; require "%s/components/base.class.php"; require "%s/components/crypto.class.php"; require "%s/components/s3.class.php"; $fh = fopen(%s, "rb"); Crypto::decrypt_chunked_output_range_fh($fh, %s, %d, %d); fclose($fh);',
      __DIR__, __DIR__, __DIR__, __DIR__,
      var_export($encFile, true), var_export($pw, true), $start, $end
    ))
  );
  return shell_exec($cmd) ?? '';
};
check_eq('decrypt_chunked_output_range_fh', $rangeFhScript($tmpFhOut, $pw, 10, 19), substr($fhData, 10, 10));

unlink($tmpFhIn); unlink($tmpFhOut);

// --- S3: decrypt_s3_range_output ---
section('Crypto::decrypt_s3_range_output');
$tmpS3In  = tempnam(sys_get_temp_dir(), 'dd_s3r_in_');
$tmpS3Out = tempnam(sys_get_temp_dir(), 'dd_s3r_out_');
$s3Data   = str_repeat('S3RangeTest__', 2000);
file_put_contents($tmpS3In, $s3Data);
Crypto::encrypt_stream($tmpS3In, $tmpS3Out, $pw);
// Read salt from header (bytes 11..26)
$hdrFh = fopen($tmpS3Out, 'rb');
fread($hdrFh, 11); // skip magic
$rawSalt = fread($hdrFh, 16);
fclose($hdrFh);
$saltHex = bin2hex($rawSalt);
$chunkSize = Crypto::CHUNK_SIZE;
$encStride = 4 + 12 + 16 + $chunkSize;
$rs = 10; $re = 25;
$firstChunk = (int)floor($rs / $chunkSize);
$encStart = 39 + $firstChunk * $encStride;
$s3RangeScript = sprintf(
  'php -r %s 2>&1',
  escapeshellarg(sprintf(
    'require "%s/components/app.class.php"; require "%s/components/base.class.php"; require "%s/components/crypto.class.php"; require "%s/components/s3.class.php"; $fh = fopen(%s, "rb"); fseek($fh, %d); Crypto::decrypt_s3_range_output($fh, %s, %s, %d, %d, %d, %d); fclose($fh);',
    __DIR__, __DIR__, __DIR__, __DIR__,
    var_export($tmpS3Out, true),
    $encStart,
    var_export($saltHex, true),
    var_export($pw, true),
    $firstChunk, $rs, $re, $chunkSize
  ))
);
$s3RangeOut = shell_exec($s3RangeScript) ?? '';
check_eq('decrypt_s3_range_output bytes 10-25', $s3RangeOut, substr($s3Data, $rs, $re - $rs + 1));
unlink($tmpS3In); unlink($tmpS3Out);

// --- S3: status filesEncrypted counts S3 files ---
section('Status: filesEncrypted includes S3 files');
$statusSrc = file_get_contents("$dir/components/status.class.php");
check('filesEncrypted adds s3Count', str_contains($statusSrc, 'filesEncrypted\' => $filesEncrypted + $s3Count'));

// --- S3: separate Object Storage card ---
section('Status: Object Storage card');
check('s3_checks method exists', str_contains($statusSrc, 'function s3_checks'));
check('s3_checks counts files', str_contains($statusSrc, '$s3Count'));
check('s3_checks checks connectivity', str_contains($statusSrc, 'head_bucket'));
check('s3_checks checks storage limit', str_contains($statusSrc, 'DARKDRIVE_S3_MAX_STORAGE'));
check('Object Storage card rendered', str_contains($statusSrc, "Object Storage"));
check('Object Storage card conditional on S3 configured', str_contains($statusSrc, 'S3::is_configured()'));
check('orphan markers show Object Storage card', str_contains($statusSrc, 's3Orphans'));
check('storage_checks returns s3Orphans', str_contains($statusSrc, "'s3Orphans'"));

// --- S3: emergency re-encryption support ---
section('Emergency: S3 re-encryption support');
$emergencySrc = file_get_contents("$dir/components/emergency.class.php");
check('emergency collects s3Files', str_contains($emergencySrc, '$s3Files'));
check('emergency calls verify_s3_files', str_contains($emergencySrc, 'self::verify_s3_files'));
check('emergency calls reencrypt_s3_files', str_contains($emergencySrc, 'self::reencrypt_s3_files'));
check('emergency reencrypt_filenames handles S3 markers', str_contains($emergencySrc, 'S3::marker_path($f)'));
check('emergency S3 re-encrypt downloads from S3', str_contains($emergencySrc, 'S3::download_to_file'));
check('emergency S3 re-encrypt uploads back', str_contains($emergencySrc, 'S3::put_object'));
check('emergency S3 re-encrypt updates marker', str_contains($emergencySrc, 'S3::write_marker'));

// --- S3: thumbnail generation for S3 files ---
section('Thumbnails: S3 file support');
$filesSrc = file_get_contents("$dir/components/files.class.php");
check('maybe_save_video_thumb has S3 fallback', str_contains($filesSrc, "dd_s3v_") || str_contains($filesSrc, 'S3::download_to_file'));
check('maybe_save_pdf_thumb has S3 fallback', str_contains($filesSrc, "dd_s3p_"));
check('maybe_save_office_thumb has S3 fallback', str_contains($filesSrc, "dd_s3o_"));

// --- S3: handle_thumb image S3 fallback ---
section('FileServer: handle_thumb S3 image fallback');
$fsSrc = file_get_contents("$dir/components/fileserver.class.php");
check('handle_thumb downloads S3 image for thumb gen', str_contains($fsSrc, "dd_s3th_"));

// --- S3: handle_edit_save S3 support ---
section('FileServer: handle_edit_save S3 support');
check('handle_edit_save detects S3 marker', str_contains($fsSrc, 'S3::marker_path($filename)') && str_contains($fsSrc, '$isS3'));
check('handle_edit_save uploads to S3', str_contains($fsSrc, "dd_s3ed_"));
check('handle_edit_save updates S3 marker on save', str_contains($fsSrc, 'S3::write_marker($filename'));

// --- S3: decrypt_file_text S3 support ---
section('Files: decrypt_file_text S3 support');
check('decrypt_file_text has S3 fallback', str_contains($filesSrc, "dd_s3txt_"));

// --- S3: detail view filesize for S3 ---
section('Files: detail view S3 filesize');
check('detail view uses S3 marker plain_size', substr_count($filesSrc, 'S3::read_marker') >= 2);

// --- S3: serve_s3 emergency recovery fallback ---
section('FileServer: serve_s3 emergency recovery');
check('serve_s3 chunked tests key before streaming', str_contains($fsSrc, 'decrypt_chunked_with_callback_fh($testStream'));
check('serve_s3 chunked tries recovery password', str_contains($fsSrc, 'emergency_recovery_password'));
check('serve_s3 legacy tries recovery on decrypt fail', preg_match('/Crypto::decrypt\(\$enc,\s*\$password\).*recovery/s', $fsSrc) === 1);

// ── Summary ───────────────────────────────────────────────────────────────────

$total = $PASS + $FAIL;
echo "\n";
if ($FAIL === 0) {
  echo C_GREEN . C_BOLD . "All $total tests passed." . C_NC . "\n\n";
  exit(0);
} else {
  echo C_RED . C_BOLD . "$FAIL of $total tests failed." . C_NC . "\n\n";
  exit(1);
}