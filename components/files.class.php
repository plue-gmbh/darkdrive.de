<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Files — gallery rendering, detail views, thumbnails, and file metadata for Darkdrive
//
//   Gallery:  tile grid with lazy-load pagination, tag-based grouping, type filters
//   Detail:   single-file view with prev/next nav, inline text/markdown/vCard rendering
//   Thumbs:   image (GD), video (ffmpeg), PDF (pdftoppm), Office (LibreOffice) — encrypted at rest
//   Metadata: real_name decryption, type matching, public-sharing helpers
//
//   HTTP serving (file downloads, range requests, ZIP export) and file mutations
//   (publish, delete, edit-save) live in FileServer. Proxy methods here for compat.
//

class Files {

  public static function matches_type(string $file, string $type): bool {
    $rn = self::real_name($file);
    return match($type) {
      'images'    => Base::is_image($rn),
      'videos'    => Base::is_video($rn) && !self::is_webm_audio($file),
      'audio'     => Base::is_audio($rn) || self::is_webm_audio($file),
      'documents' => Base::is_document($rn),
      'archives'  => Base::is_archive($rn),
      'texts'     => Base::is_text($rn),
      'fonts'     => Base::is_font($rn),
      'contacts'  => Base::is_contact($rn),
      'design'    => Base::is_design($rn),
      default     => false,
    };
  }

  public static function public_secret(string $filename): string {
    return substr(hash('sha256', $filename . '-public-' . bin2hex(Base::instance_key())), 0, 24);
  }

  public static function public_path(string $filename): string {
    return 'public/' . self::public_secret($filename) . '/' . self::real_name($filename);
  }

  public static function is_published(string $filename): bool {
    return file_exists(self::public_path($filename));
  }

  public static function handle_publish(): void { FileServer::handle_publish(); }
  public static function handle_unpublish(): void { FileServer::handle_unpublish(); }
  public static function handle_delete(): void { FileServer::handle_delete(); }
  public static function handle_bulk_delete(): void { FileServer::handle_bulk_delete(); }
  public static function handle_edit_save(): void { FileServer::handle_edit_save(); }
  public static function handle_create_file(): void { FileServer::handle_create_file(); }
  public static function handle(): void { FileServer::handle(); }
  public static function handle_thumb(): void { FileServer::handle_thumb(); }

  public static function api_list(): void {
    if (!isset($_GET['api_files'])) return;
    session_write_close();
    $result = [];
    foreach (self::all_files() as $file) {
      $name = self::real_name($file);
      $type = 'other';
      foreach (['images','videos','audio','documents','archives','texts','fonts','contacts','design'] as $t) {
        if (self::matches_type($file, $t)) { $type = $t; break; }
      }
      $path = Base::data_path('files/' . $file);
      if (is_file($path)) {
        if (Crypto::is_chunked($path)) {
          $ps = Crypto::chunked_plain_size($path);
          $size = $ps !== false ? $ps : (int)filesize($path);
        } elseif (Crypto::is_encrypted($path)) {
          $size = max(0, (int)filesize($path) - 44);
        } else {
          $size = (int)filesize($path);
        }
      } else {
        $marker = S3::read_marker($file);
        $size = $marker !== false ? (int)($marker['plain_size'] ?? $marker['size'] ?? 0) : 0;
      }
      $mtime = 0;
      if (preg_match('/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/', $file, $m)) {
        $mtime = (int)mktime((int)$m[4], (int)$m[5], (int)$m[6], (int)$m[2], (int)$m[3], (int)$m[1]);
      }
      $result[] = ['id' => $file, 'name' => $name, 'type' => $type, 'size' => $size, 'mtime' => $mtime];
    }
    header('Content-Type: application/json');
    echo json_encode(['files' => $result], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
  }

  public static function is_webm_audio(string $filename): bool {
    return file_exists(Base::data_path('thumbs/' . $filename . '.webmaudio'));
  }

  public static function maybe_save_video_thumb(string $filename): void {
    $bin = Base::ffmpeg_bin();
    if (!$bin) return;
    $thumbDir  = Base::data_path('thumbs');
    $thumbPath = $thumbDir . '/' . $filename;
    if (file_exists($thumbPath)) return;
    $markerPath = $thumbPath . '.webmaudio';
    if (file_exists($markerPath)) return;
    $password = Base::enc_key();
    if ($password === '') return;
    $filepath = Base::data_path('files/' . $filename);
    $tmpS3 = null;
    if (!file_exists($filepath) || !is_file($filepath)) {
      if (!S3::is_configured()) return;
      $marker = S3::read_marker($filename);
      if ($marker === false) return;
      $tmpS3 = tempnam(sys_get_temp_dir(), 'dd_s3v_');
      if (!S3::download_to_file((string)($marker['key'] ?? $filename), $tmpS3)) { @unlink($tmpS3); return; }
      $filepath = $tmpS3;
    }
    if (!is_dir($thumbDir)) {
      mkdir($thumbDir, 0755, true);
    }
    $tmpDir = sys_get_temp_dir() . '/dd_v_' . bin2hex(random_bytes(8));
    if (!mkdir($tmpDir, 0700, true)) return;
    $tmpIn  = $tmpDir . '/input';
    $tmpOut = $tmpDir . '/thumb.jpg';
    try {
      if (!Crypto::decrypt_to_path($filepath, $password, $tmpIn)) return;
      exec(escapeshellarg($bin) . ' -y -loglevel error -i ' . escapeshellarg($tmpIn)
        . ' -vframes 1 -f image2 ' . escapeshellarg($tmpOut) . ' 2>/dev/null', result_code: $ret);
      if ($ret !== 0 || !file_exists($tmpOut) || filesize($tmpOut) === 0) {
        $rn = self::real_name($filename);
        if (strtolower(pathinfo($rn, PATHINFO_EXTENSION)) === 'webm') {
          file_put_contents($markerPath, '');
        }
        return;
      }
      $jpeg = file_get_contents($tmpOut);
      if (!$jpeg) return;
      $jpeg = self::resize_thumb_data($jpeg, 512);
      if ($jpeg === null) return;
      $enc = Crypto::encrypt($jpeg, $password);
      if ($enc !== false) file_put_contents($thumbPath, $enc);
    } finally {
      Base::memzero($password);
      self::rm_rf($tmpDir);
      if ($tmpS3) @unlink($tmpS3);
    }
  }

  public static function maybe_save_pdf_thumb(string $filename): void {
    $bin = Base::pdftoppm_bin();
    if (!$bin) return;
    $thumbDir  = Base::data_path('thumbs');
    $thumbPath = $thumbDir . '/' . $filename;
    if (file_exists($thumbPath)) return;
    $password = Base::enc_key();
    if ($password === '') return;
    $filepath = Base::data_path('files/' . $filename);
    $tmpS3 = null;
    if (!file_exists($filepath) || !is_file($filepath)) {
      if (!S3::is_configured()) return;
      $marker = S3::read_marker($filename);
      if ($marker === false) return;
      $tmpS3 = tempnam(sys_get_temp_dir(), 'dd_s3p_');
      if (!S3::download_to_file((string)($marker['key'] ?? $filename), $tmpS3)) { @unlink($tmpS3); return; }
      $filepath = $tmpS3;
    }
    if (!is_dir($thumbDir)) {
      mkdir($thumbDir, 0755, true);
    }
    $tmpDir = sys_get_temp_dir() . '/dd_p_' . bin2hex(random_bytes(8));
    if (!mkdir($tmpDir, 0700, true)) return;
    $tmpIn  = $tmpDir . '/input';
    $tmpOut = $tmpDir . '/thumb';
    try {
      if (!Crypto::decrypt_to_path($filepath, $password, $tmpIn)) return;
      exec(escapeshellarg($bin) . ' -jpeg -singlefile -f 1 -r 72 '
        . escapeshellarg($tmpIn) . ' ' . escapeshellarg($tmpOut) . ' 2>/dev/null', result_code: $ret);
      $jpgPath = $tmpOut . '.jpg';
      if (!file_exists($jpgPath) || filesize($jpgPath) === 0) return;
      $jpeg = file_get_contents($jpgPath);
      if (!$jpeg) return;
      $jpeg = self::resize_thumb_data($jpeg, 512);
      if ($jpeg === null) return;
      $enc = Crypto::encrypt($jpeg, $password);
      if ($enc !== false) file_put_contents($thumbPath, $enc);
    } finally {
      Base::memzero($password);
      self::rm_rf($tmpDir);
      if ($tmpS3) @unlink($tmpS3);
    }
  }

  public static function maybe_save_office_thumb(string $filename): void {
    $bin = Base::libreoffice_bin();
    if (!$bin) return;
    $pdfBin = Base::pdftoppm_bin();
    $thumbDir  = Base::data_path('thumbs');
    $thumbPath = $thumbDir . '/' . $filename;
    if (file_exists($thumbPath)) return;
    $password = Base::enc_key();
    if ($password === '') return;
    $filepath = Base::data_path('files/' . $filename);
    $tmpS3 = null;
    if (!file_exists($filepath) || !is_file($filepath)) {
      if (!S3::is_configured()) return;
      $marker = S3::read_marker($filename);
      if ($marker === false) return;
      $tmpS3 = tempnam(sys_get_temp_dir(), 'dd_s3o_');
      if (!S3::download_to_file((string)($marker['key'] ?? $filename), $tmpS3)) { @unlink($tmpS3); return; }
      $filepath = $tmpS3;
    }
    if (!is_dir($thumbDir)) {
      mkdir($thumbDir, 0755, true);
    }
    $id = bin2hex(random_bytes(8));
    $tmpDir = sys_get_temp_dir() . '/dd_lo_' . $id;
    mkdir($tmpDir, 0700, true);
    $profileDir = sys_get_temp_dir() . '/dd_lo_profile_' . $id;
    mkdir($profileDir, 0700, true);
    $profileArg = ' -env:UserInstallation=' . escapeshellarg('file://' . $profileDir);
    $rn = self::real_name($filename);
    $ext = strtolower(pathinfo($rn, PATHINFO_EXTENSION));
    $tmpIn = $tmpDir . '/input.' . $ext;
    try {
      if (!Crypto::decrypt_to_path($filepath, $password, $tmpIn)) return;
      $timeout = 'timeout 30 ';
      if ($pdfBin) {
        exec($timeout . escapeshellarg($bin) . ' --headless' . $profileArg . ' --convert-to pdf --outdir '
          . escapeshellarg($tmpDir) . ' ' . escapeshellarg($tmpIn) . ' 2>/dev/null', result_code: $ret);
        $pdfPath = $tmpDir . '/input.pdf';
        if ($ret !== 0 || !file_exists($pdfPath)) return;
        $tmpOut = $tmpDir . '/thumb';
        exec(escapeshellarg($pdfBin) . ' -jpeg -singlefile -f 1 -r 72 '
          . escapeshellarg($pdfPath) . ' ' . escapeshellarg($tmpOut) . ' 2>/dev/null', result_code: $ret2);
        $jpgPath = $tmpOut . '.jpg';
      } else {
        exec($timeout . escapeshellarg($bin) . ' --headless' . $profileArg . ' --convert-to jpg --outdir '
          . escapeshellarg($tmpDir) . ' ' . escapeshellarg($tmpIn) . ' 2>/dev/null', result_code: $ret);
        $jpgPath = $tmpDir . '/input.jpg';
      }
      if (!file_exists($jpgPath) || filesize($jpgPath) === 0) return;
      $jpeg = file_get_contents($jpgPath);
      if (!$jpeg) return;
      $jpeg = self::resize_thumb_data($jpeg, 768);
      if ($jpeg === null) return;
      $enc = Crypto::encrypt($jpeg, $password);
      if ($enc !== false) file_put_contents($thumbPath, $enc);
    } finally {
      Base::memzero($password);
      self::rm_rf($tmpDir);
      self::rm_rf($profileDir);
    }
  }

  private static function secure_unlink(string $path): void {
    if (!is_file($path)) return;
    $size = filesize($path);
    if ($size > 0) {
      $fh = fopen($path, 'r+');
      if ($fh) {
        $remaining = $size;
        $zeros = str_repeat("\0", min(8192, $size));
        while ($remaining > 0) {
          $written = fwrite($fh, $zeros, min(8192, $remaining));
          if ($written === false) break;
          $remaining -= $written;
        }
        fclose($fh);
      }
    }
    @unlink($path);
  }

  private static function rm_rf(string $dir): void {
    if (!is_dir($dir)) return;
    $items = new \RecursiveIteratorIterator(
      new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
      \RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($items as $item) {
      $item->isDir() ? @rmdir($item->getPathname()) : self::secure_unlink($item->getPathname());
    }
    @rmdir($dir);
  }

  private static function resize_thumb_data(string $jpeg, int $max): ?string {
    if (!function_exists('imagecreatefromstring')) return $jpeg;
    $img = imagecreatefromstring($jpeg);
    if (!$img) return null;
    $w = imagesx($img); $h = imagesy($img);
    if ($w <= $max && $h <= $max) { imagedestroy($img); return $jpeg; }
    if ($w >= $h) {
      $nw = $max; $nh = (int) max(1, round($h * $max / $w));
    } else {
      $nh = $max; $nw = (int) max(1, round($w * $max / $h));
    }
    $thumb = imagecreatetruecolor($nw, $nh);
    $bg = imagecolorallocate($thumb, 255, 255, 255);
    imagefill($thumb, 0, 0, $bg);
    imagecopyresampled($thumb, $img, 0, 0, 0, 0, $nw, $nh, $w, $h);
    imagedestroy($img);
    ob_start();
    imagejpeg($thumb, null, 85);
    $out = ob_get_clean();
    imagedestroy($thumb);
    return $out ?: null;
  }

  public static function maybe_save_thumb(string $filename, string $data): void {
    if (!function_exists('imagecreatefromstring')) return;
    $thumbDir  = Base::data_path('thumbs');
    $thumbPath = $thumbDir . '/' . $filename;
    if (file_exists($thumbPath)) return;
    if (!is_dir($thumbDir)) {
      mkdir($thumbDir, 0755, true);
    }
    $img = imagecreatefromstring($data);
    if (!$img) return;
    $w = imagesx($img);
    $h = imagesy($img);
    if ($w <= 512 && $h <= 512) { imagedestroy($img); return; }
    if ($w >= $h) {
      $nw = 512; $nh = (int) max(1, round($h * 512 / $w));
    } else {
      $nh = 512; $nw = (int) max(1, round($w * 512 / $h));
    }
    $thumb = imagecreatetruecolor($nw, $nh);
    $bg    = imagecolorallocate($thumb, 255, 255, 255);
    imagefill($thumb, 0, 0, $bg);
    imagecopyresampled($thumb, $img, 0, 0, 0, 0, $nw, $nh, $w, $h);
    imagedestroy($img);
    ob_start();
    imagejpeg($thumb, null, 85);
    $jpegData = ob_get_clean();
    imagedestroy($thumb);
    $password = Base::enc_key();
    if ($password === '') return;
    $encrypted = Crypto::encrypt($jpegData, $password);
    Base::memzero($password);
    if ($encrypted !== false) file_put_contents($thumbPath, $encrypted);
  }

  private static array $realNameCache = [];

  public static function real_name(string $filename): string {
    if (isset(self::$realNameCache[$filename])) return self::$realNameCache[$filename];
    $part = preg_replace('/^\d{8}-\d{6}-/', '', $filename);
    if (pathinfo($part, PATHINFO_EXTENSION) !== '') return self::$realNameCache[$filename] = $part;
    $encKey = Base::enc_key();
    if ($encKey !== '') {
      $dec = Crypto::decrypt_filename($part, $encKey);
      if ($dec !== false) { Base::memzero($encKey); return self::$realNameCache[$filename] = $dec; }
    }
    Base::memzero($encKey);
    return self::$realNameCache[$filename] = $part;
  }

  private static int $pageSize = 18;

  private static function date_bucket(string $file): string {
    if (!preg_match('/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/', $file, $m)) return '';
    $ts = mktime((int)$m[4], (int)$m[5], (int)$m[6], (int)$m[2], (int)$m[3], (int)$m[1]);
    if ($ts >= strtotime('today')) return 'Today';
    if ($ts >= strtotime('yesterday')) return 'Yesterday';
    if ((int)$m[1] === (int)date('Y')) return date('F', $ts);
    return date('F Y', $ts);
  }

  private static ?array $cachedFiles = null;

  public static function all_files(): array {
    if (self::$cachedFiles === null) {
      $dir = Base::data_path('files');
      if (!is_dir($dir)) {
        self::$cachedFiles = [];
      } else {
        self::$cachedFiles = [];
        $seen = [];
        foreach (array_diff(scandir($dir), ['.', '..']) as $f) {
          $name = str_ends_with($f, '.s3') ? substr($f, 0, -3) : $f;
          if (!isset($seen[$name])) {
            $seen[$name] = true;
            self::$cachedFiles[] = $name;
          }
        }
        self::$cachedFiles = array_values(self::$cachedFiles);
      }
    }
    return self::$cachedFiles;
  }

  private static ?array $fileIndex = null;

  public static function is_known(string $filename): bool {
    if ($filename === '') return false;
    if (self::$fileIndex === null) self::$fileIndex = array_flip(self::all_files());
    return isset(self::$fileIndex[$filename]);
  }

  public static function filtered_plain_size(): int {
    $total = 0;
    foreach (self::filtered_files() as $file) {
      $path = Base::data_path('files/' . $file);
      if (is_file($path)) {
        $total += (int)filesize($path);
      } else {
        $marker = S3::read_marker($file);
        if ($marker !== false) $total += (int)($marker['plain_size'] ?? $marker['size'] ?? 0);
      }
    }
    return $total;
  }

  public static function handle_zip(): void { FileServer::handle_zip(); }

  public static function filtered_files(): array {
    $uploadDir = Base::data_path('files');
    $tag  = isset($_GET['tag'])  ? strtolower(Base::str_clean($_GET['tag']))  : '';
    $untagged = ($tag === '_untagged');
    $tagDir = (!$untagged && $tag) ? Base::resolve_tag_dir($tag) : null;
    $type = $_GET['type'] ?? '';
    if (!is_dir($uploadDir)) return [];
    $taggedFiles = null;
    if ($untagged) {
      $taggedFiles = [];
      foreach (Base::get_all_tags() as $tPath) {
        foreach (array_diff(scandir($tPath), ['.', '..']) as $entry) {
          $taggedFiles[str_replace('.txt', '', $entry)] = true;
        }
      }
    }
    $files = [];
    foreach (array_reverse(self::all_files()) as $file) {
      if ($untagged && isset($taggedFiles[$file])) continue;
      if ($tag && !$untagged && (!$tagDir || !file_exists("{$tagDir}/{$file}.txt"))) continue;
      if ($type !== '' && !self::matches_type($file, $type)) continue;
      $files[] = $file;
    }
    return $files;
  }

  public static function handle_render_tile(): void {
    if (!isset($_GET['render_tile'])) return;
    $filename = Base::str_clean($_GET['render_tile']);
    if (!self::is_known($filename)) return;
    self::render_tile($filename);
    exit;
  }

  public static function render_tile(string $file): void {
    $allTags = Base::get_all_tags();
    ?>
    <div data-file="<?= htmlspecialchars($file) ?>">
      <?php self::preview($file) ?>
      <div>
        <?php foreach ($allTags as $tagName => $tagPath): $tagName = (string)$tagName; ?>
          <?php if (!file_exists($tagPath.'/'.$file.'.txt')) continue ?>
          <label<?= isset($_GET['tag']) && $_GET['tag'] === $tagName ? ' class="active"' : '' ?>>
            <a href="<?= htmlspecialchars(isset($_GET['tag']) && $_GET['tag'] === $tagName ? '/' : Base::url(['tag' => $tagName])) ?>">#<?= htmlspecialchars($tagName) ?></a>
          </label>
        <?php endforeach ?>
        <form method="post" action="">
          <?php Base::csrf_field() ?>
          <input type="hidden" name="file" value="<?= urlencode($file) ?>">
          <input type="text" name="tag" placeholder="#">
        </form>
      </div>
    </div>
    <?php
  }

  public static function handle_gallery_page(): void {
    if (!isset($_GET['gallery_page'])) return;
    $offset = max(0, (int)($_GET['offset'] ?? 0));
    $files  = self::filtered_files();
    $search = isset($_GET['search']) ? strtolower(trim($_GET['search'])) : '';
    if ($search !== '') {
      $matched = [];
      foreach ($files as $f) {
        if (stripos(self::real_name($f), $search) !== false) $matched[] = $f;
      }
      $files = $matched;
    }
    $all    = isset($_GET['all']);
    $slice  = $all ? array_slice($files, $offset) : array_slice($files, $offset, self::$pageSize);
    $lastBucket = $_GET['last_bucket'] ?? '';
    foreach ($slice as $file) {
      $bucket = self::date_bucket($file);
      if ($bucket !== '' && $bucket !== $lastBucket) {
        $lastBucket = $bucket;
        echo '<h2 class="gallery-date">' . htmlspecialchars($bucket) . '</h2>';
      }
      self::render_tile($file);
    }
    if (!$all) {
      $next = $offset + count($slice);
      if ($next < count($files)) {
        echo '<div id="load-more-sentinel" data-offset="' . $next . '" data-last-bucket="' . htmlspecialchars($lastBucket) . '"></div>';
      }
    }
    exit;
  }

  private static function find_cover(array $files): ?string {
    $thumbsDir = Base::data_path('thumbs');
    $filesDir  = Base::data_path('files');
    foreach ($files as $peer) {
      $rn = self::real_name($peer);
      if (Base::is_audio($rn) || self::is_webm_audio($peer)) continue;
      if (file_exists($thumbsDir . '/' . $peer)) {
        return '/?route=thumb/' . urlencode($peer);
      }
      if (Base::is_image($rn) && file_exists($filesDir . '/' . $peer)) {
        return '/?route=thumb/' . urlencode($peer);
      }
      if (strtolower(pathinfo($rn, PATHINFO_EXTENSION)) === 'pdf') {
        self::maybe_save_pdf_thumb($peer);
        if (file_exists($thumbsDir . '/' . $peer)) {
          return '/?route=thumb/' . urlencode($peer);
        }
      }
    }
    return null;
  }

  public static function home(): void {
    $activeType = $_GET['type'] ?? '';
    $allTags = Base::get_all_tags();
    if (empty($allTags)) { echo '<section class="tags-grid"></section>'; return; }
    $tagCounts = [];
    $tagPaths = [];
    foreach ($allTags as $tName => $tPath) {
      $cnt = 0;
      foreach (array_diff(scandir($tPath), ['.', '..']) as $entry) {
        $peer = str_replace('.txt', '', $entry);
        if ($activeType !== '' && !self::matches_type($peer, $activeType)) continue;
        $cnt++;
      }
      if ($cnt > 0) { $tagCounts[$tName] = $cnt; $tagPaths[$tName] = $tPath; }
    }
    uksort($tagCounts, 'strnatcasecmp');
    $linkCtx = $activeType !== '' ? ['type' => $activeType] : [];
    ?>
    <section class="tags-grid">
      <?php foreach ($tagCounts as $tagName => $tagCount): $tagName = (string)$tagName; ?>
        <?php
          $tagFiles = array_diff(scandir($tagPaths[$tagName]), ['.', '..']);
          rsort($tagFiles);
          $candidates = array_map(fn($e) => str_replace('.txt', '', $e), $tagFiles);
          $coverSrc = self::find_cover($candidates);
        ?>
        <a href="<?= htmlspecialchars(Base::url(array_merge($linkCtx, ['tag' => $tagName]))) ?>" class="tag-tile">
          <?php if ($coverSrc): ?>
            <img class="tile" src="<?= htmlspecialchars($coverSrc) ?>" loading="lazy">
          <?php else: ?>
            <span class="tile tile-text"><span>#<?= htmlspecialchars($tagName) ?></span></span>
          <?php endif ?>
          <span class="tag-tile-label">#<?= htmlspecialchars($tagName) ?> (<?= $tagCount ?>)</span>
        </a>
      <?php endforeach ?>
      <?php
        $taggedFiles = [];
        foreach ($allTags as $tPath) {
          foreach (array_diff(scandir($tPath), ['.', '..']) as $entry) {
            $taggedFiles[str_replace('.txt', '', $entry)] = true;
          }
        }
        $untaggedFiles = [];
        foreach (array_reverse(self::all_files()) as $file) {
          if (isset($taggedFiles[$file])) continue;
          if ($activeType !== '' && !self::matches_type($file, $activeType)) continue;
          $untaggedFiles[] = $file;
        }
        if (!empty($untaggedFiles)):
          $untaggedCover = self::find_cover($untaggedFiles);
      ?>
        <a href="<?= htmlspecialchars(Base::url(array_merge($linkCtx, ['tag' => '_untagged']))) ?>" class="tag-tile">
          <?php if ($untaggedCover): ?>
            <img class="tile" src="<?= htmlspecialchars($untaggedCover) ?>" loading="lazy">
          <?php else: ?>
            <span class="tile tile-text"><span>Untagged</span></span>
          <?php endif ?>
          <span class="tag-tile-label">Untagged (<?= count($untaggedFiles) ?>)</span>
        </a>
      <?php endif ?>
    </section>
    <?php
  }

  public static function gallery(): void {
    $files = self::filtered_files();
    $slice = array_slice($files, 0, self::$pageSize);
    $lastBucket = '';
    ?>
    <section>
      <?php foreach ($slice as $file):
        $bucket = self::date_bucket($file);
        if ($bucket !== '' && $bucket !== $lastBucket):
          $lastBucket = $bucket;
      ?>
        <h2 class="gallery-date"><?= htmlspecialchars($bucket) ?></h2>
      <?php endif ?>
        <?php self::render_tile($file) ?>
      <?php endforeach ?>
      <?php if (count($files) > self::$pageSize): ?>
        <div id="load-more-sentinel" data-offset="<?= self::$pageSize ?>" data-last-bucket="<?= htmlspecialchars($lastBucket) ?>"></div>
      <?php endif ?>
    </section>
    <?php
  }

  public static function render_tags(string $file): void {
    foreach (Base::get_all_tags() as $tagName => $tagPath):
      $tagName = (string)$tagName;
      if (!file_exists("{$tagPath}/{$file}.txt")) continue;
      ?><label><a href="<?= htmlspecialchars(Base::url(['tag' => $tagName])) ?>">#<?= htmlspecialchars($tagName) ?></a></label><?php
    endforeach;
    ?><form method="post" action=""><?php Base::csrf_field() ?><input type="hidden" name="file" value="<?= urlencode($file) ?>"><input type="text" name="tag" placeholder="#"></form><?php
  }

  public static function detail(): void {
    $file = Base::str_clean($_GET['file'] ?? '');
    if (empty($file)) return;

    $activeTag  = isset($_GET['tag'])  ? strtolower(Base::str_clean($_GET['tag']))  : '';
    $activeType = $_GET['type'] ?? '';
    $filtered   = self::filtered_files();
    $pos        = array_search($file, $filtered, true);
    $total      = count($filtered);
    $ctx        = array_filter(['tag' => $activeTag ?: null, 'type' => $activeType ?: null], fn($v) => $v !== null);
    $prev     = ($pos !== false && $pos > 0)             ? $filtered[$pos - 1] : null;
    $next     = ($pos !== false && $pos < $total - 1)    ? $filtered[$pos + 1] : null;
    $prevHref = $prev ? htmlspecialchars(Base::url(array_merge($ctx, ['file' => $prev]))) : null;
    $nextHref = $next ? htmlspecialchars(Base::url(array_merge($ctx, ['file' => $next]))) : null;

    $realName = self::real_name($file);
    $src      = '/?route=load/' . urlencode($file) . '/' . urlencode($realName);
    $ext      = strtolower(pathinfo($realName, PATHINFO_EXTENSION));
    $fp = Base::data_path('files/' . $file);
    if (is_file($fp)) {
      $filesize = filesize($fp);
    } else {
      $marker = S3::read_marker($file);
      $filesize = is_array($marker) ? (int)($marker['plain_size'] ?? 0) : false;
    }
    $tooLarge = $filesize !== false && $filesize > Base::INLINE_SIZE_LIMIT;
    $dateLabel = '';
    if (preg_match('/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/', $file, $m)) {
      $ts = mktime((int)$m[4], (int)$m[5], (int)$m[6], (int)$m[2], (int)$m[3], (int)$m[1]);
      $dateLabel = date('j. M Y, H:i', $ts);
    }
    $editMode = isset($_GET['edit']) && !$tooLarge && Base::is_editable($realName);
    $viewHref = htmlspecialchars(Base::url(array_merge($ctx, ['file' => $file])));
    ?>
      <figure<?= $editMode ? ' class="figure-edit"' : '' ?>>
        <?php if ($editMode): ?>
          <?php $rawData = self::decrypt_file_text($file); ?>
          <form method="post" action="" class="edit-form" id="edit-form">
            <?php Base::csrf_field() ?>
            <input type="hidden" name="edit_save" value="<?= htmlspecialchars($file) ?>">
            <?php if ($activeTag):  ?><input type="hidden" name="_tag"  value="<?= htmlspecialchars($activeTag) ?>"><?php endif ?>
            <?php if ($activeType): ?><input type="hidden" name="_type" value="<?= htmlspecialchars($activeType) ?>"><?php endif ?>
            <textarea name="content" class="edit-textarea" id="edit-textarea" spellcheck="false"><?= htmlspecialchars($rawData) ?></textarea>
            <div class="edit-toolbar">
              <button type="submit" class="edit-btn">Save</button>
              <a href="<?= $viewHref ?>" class="edit-btn">Cancel</a>
            </div>
          </form>
        <?php elseif (Base::is_video($realName) && !self::is_webm_audio($file)): ?>
          <?php $poster = file_exists(Base::data_path('thumbs/' . $file)) ? ' poster="/?route=thumb/' . urlencode($file) . '"' : ''; ?>
          <video class="full" controls preload="none"<?= $poster ?>><source src="<?= $src ?>"></video>
        <?php elseif (Base::is_audio($realName) || self::is_webm_audio($file)): ?>
          <?php $detailCover = self::audio_cover($file); ?>
          <div class="detail-audio">
            <?php if ($detailCover): ?>
              <img src="<?= htmlspecialchars($detailCover) ?>" class="detail-audio-cover">
            <?php endif ?>
            <audio controls preload="none"><source src="<?= $src ?>" type="<?= Base::ext_to_mime($ext) ?>"></audio>
          </div>
        <?php elseif (Base::is_image($realName)): ?>
          <img class="full" src="<?= $src ?>">
        <?php elseif ($tooLarge): ?>
          <a href="<?= $src ?>" class="detail-download">
            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/></svg>
            <span class="detail-download-info">
              <strong><?= htmlspecialchars($realName) ?></strong>
              <span><?= strtoupper($ext) ?><?= $filesize !== false ? ' &middot; ' . Base::format_bytes($filesize) : '' ?><?= $dateLabel ? ' &middot; ' . $dateLabel : '' ?></span>
            </span>
          </a>
        <?php elseif ($ext === 'pdf' || Base::is_office($realName)): ?>
          <?php
            if (!file_exists(Base::data_path('thumbs/' . $file))) {
              if ($ext === 'pdf' && Base::pdftoppm_bin()) self::maybe_save_pdf_thumb($file);
              elseif (Base::is_office($realName) && Base::libreoffice_bin()) self::maybe_save_office_thumb($file);
            }
          ?>
          <?php $hasThumb = file_exists(Base::data_path('thumbs/' . $file)); ?>
          <a href="<?= $src ?>" class="detail-download detail-download-office" download="<?= htmlspecialchars($realName) ?>">
            <?php if ($hasThumb): ?>
              <img class="detail-download-preview" src="/?route=thumb/<?= urlencode($file) ?>">
            <?php endif ?>
            <span class="detail-download-row">
              <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/></svg>
              <span class="detail-download-info">
                <strong><?= htmlspecialchars($realName) ?></strong>
                <span><?= strtoupper($ext) ?><?= $filesize !== false ? ' &middot; ' . Base::format_bytes($filesize) : '' ?><?= $dateLabel ? ' &middot; ' . $dateLabel : '' ?></span>
              </span>
            </span>
          </a>
        <?php elseif (in_array($ext, ['html', 'htm'])): ?>
          <iframe src="<?= $src ?>" sandbox=""></iframe>
        <?php elseif (Base::is_text($realName) && !in_array($ext, ['html', 'htm'])): ?>
          <?php self::detail_text($file, $ext) ?>
        <?php elseif ($ext === 'vcf'): ?>
          <?php self::detail_vcf($file) ?>
        <?php else: ?>
          <a href="<?= $src ?>" class="detail-download">
            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/></svg>
            <span class="detail-download-info">
              <strong><?= htmlspecialchars($realName) ?></strong>
              <span><?= strtoupper($ext) ?><?= $filesize !== false ? ' &middot; ' . Base::format_bytes($filesize) : '' ?><?= $dateLabel ? ' &middot; ' . $dateLabel : '' ?></span>
            </span>
          </a>
        <?php endif ?>
        <?php if ($total > 1): ?>
          <nav class="detail-nav">
            <?php if ($prevHref): ?>
              <a href="<?= $prevHref ?>" class="button" id="nav-prev"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg></a>
            <?php else: ?>
              <span class="button button-disabled"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg></span>
            <?php endif ?>
            <span class="detail-pos"><?= $pos !== false ? ($pos + 1) . ' / ' . $total : '' ?></span>
            <?php if ($nextHref): ?>
              <a href="<?= $nextHref ?>" class="button" id="nav-next"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg></a>
            <?php else: ?>
              <span class="button button-disabled"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg></span>
            <?php endif ?>
          </nav>
        <?php endif ?>
        <div class="detail-tags show-mobile">
          <?php self::render_tags($file) ?>
        </div>
      </figure>
    <?php
  }

  private static function decrypt_file_text(string $file): string {
    $encKey = Base::enc_key();
    if ($encKey === '') return '';
    $filepath = Base::data_path('files/' . $file);
    $tmpS3 = null;
    if (!is_file($filepath)) {
      if (!S3::is_configured()) { Base::memzero($encKey); return ''; }
      $marker = S3::read_marker($file);
      if ($marker === false) { Base::memzero($encKey); return ''; }
      $tmpS3 = tempnam(sys_get_temp_dir(), 'dd_s3txt_');
      if (!S3::download_to_file((string)($marker['key'] ?? $file), $tmpS3)) {
        @unlink($tmpS3); Base::memzero($encKey); return '';
      }
      $filepath = $tmpS3;
    }
    $dec = Crypto::decrypt_any_to_string($filepath, $encKey);
    if ($tmpS3) @unlink($tmpS3);
    Base::memzero($encKey);
    return $dec !== false ? $dec : '';
  }

  private static function detail_text(string $file, string $ext): void {
    $rawData = self::decrypt_file_text($file);
    if ($ext === 'json' && $rawData !== '') {
      $pretty = json_encode(json_decode($rawData), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
      if ($pretty !== false) $rawData = $pretty;
    }
    if ($ext === 'md'): ?>
      <pre id="md-src" hidden><?= htmlspecialchars($rawData) ?></pre>
      <article id="md-out"></article>
    <?php else: ?>
      <pre class="text-view"><?= htmlspecialchars($rawData) ?></pre>
    <?php endif;
  }

  private static function detail_vcf(string $file): void {
    $rawData = self::decrypt_file_text($file);
    $cards = [];
    if ($rawData !== '') {
      $unfolded = preg_replace('/\r?\n[ \t]/', '', $rawData);
      preg_match_all('/BEGIN:VCARD.*?END:VCARD/si', $unfolded, $m);
      foreach ($m[0] as $block) {
        $c = [];
        if (preg_match('/^FN[;:](.+)$/mi', $block, $v))  $c['name'] = trim($v[1]);
        if (preg_match('/^(?:ITEM\d+\.)?ORG[;:](.+)$/mi', $block, $v))
          $c['org'] = rtrim(trim($v[1]), ';');
        if (preg_match('/^(?:ITEM\d+\.)?TITLE[;:](.+)$/mi', $block, $v))
          $c['title'] = trim($v[1]);
        if (preg_match('/^(?:ITEM\d+\.)?NICKNAME[;:](.+)$/mi', $block, $v))
          $c['nickname'] = trim($v[1]);
        if (preg_match('/^(?:ITEM\d+\.)?BDAY[;:](.+)$/mi', $block, $v))
          $c['bday'] = trim($v[1]);
        if (preg_match('/^(?:ITEM\d+\.)?NOTE[;:](.+)$/mi', $block, $v))
          $c['note'] = str_replace('\\n', "\n", trim($v[1]));

        if (preg_match_all('/^(?:ITEM\d+\.)?TEL([^:]*):(.+)$/mi', $block, $v, PREG_SET_ORDER)) {
          $c['tel'] = [];
          foreach ($v as $hit) {
            $label = self::vcf_type_label($hit[1]);
            $c['tel'][] = ['value' => trim($hit[2]), 'label' => $label];
          }
        }
        if (preg_match_all('/^(?:ITEM\d+\.)?EMAIL([^:]*):(.+)$/mi', $block, $v, PREG_SET_ORDER)) {
          $c['email'] = [];
          foreach ($v as $hit) {
            $label = self::vcf_type_label($hit[1]);
            $c['email'][] = ['value' => trim($hit[2]), 'label' => $label];
          }
        }
        if (preg_match_all('/^(?:ITEM\d+\.)?ADR([^:]*):(.+)$/mi', $block, $v, PREG_SET_ORDER)) {
          $c['adr'] = [];
          foreach ($v as $hit) {
            $label = self::vcf_type_label($hit[1]);
            $parts = explode(';', $hit[2]);
            $addr = trim(implode(', ', array_filter(array_map('trim', $parts))));
            if ($addr !== '') $c['adr'][] = ['value' => $addr, 'label' => $label];
          }
        }
        if (preg_match_all('/^(?:ITEM\d+\.)?URL([^:]*):(.+)$/mi', $block, $v, PREG_SET_ORDER)) {
          $c['url'] = [];
          foreach ($v as $hit) {
            $label = self::vcf_type_label($hit[1]);
            $val = trim($hit[2]);
            if (!preg_match('/^(javascript|data|vbscript)\s*:/i', $val)) {
              $c['url'][] = ['value' => $val, 'label' => $label];
            }
          }
        }

        if (!empty($c)) $cards[] = $c;
      }
    }
    ?>
    <div class="vcf-list">
      <?php if (empty($cards)): ?>
        <pre class="text-view"><?= htmlspecialchars($rawData) ?></pre>
      <?php else: ?>
        <?php foreach ($cards as $c): ?>
          <div class="vcf-card">
            <?php if (!empty($c['name'])): ?>
              <strong class="vcf-name"><?= htmlspecialchars($c['name']) ?></strong>
            <?php endif ?>
            <?php if (!empty($c['nickname'])): ?>
              <span class="vcf-dim"><?= htmlspecialchars($c['nickname']) ?></span>
            <?php endif ?>
            <?php if (!empty($c['org']) || !empty($c['title'])): ?>
              <span class="vcf-org"><?php
                $parts = array_filter([!empty($c['title']) ? $c['title'] : '', !empty($c['org']) ? $c['org'] : '']);
                echo htmlspecialchars(implode(' · ', $parts));
              ?></span>
            <?php endif ?>
            <?php if (!empty($c['tel'])): foreach ($c['tel'] as $t): ?>
              <span class="vcf-field">
                <?php if ($t['label']): ?><span class="vcf-label"><?= htmlspecialchars($t['label']) ?></span><?php endif ?>
                <a href="tel:<?= htmlspecialchars($t['value']) ?>"><?= htmlspecialchars($t['value']) ?></a>
              </span>
            <?php endforeach; endif ?>
            <?php if (!empty($c['email'])): foreach ($c['email'] as $e): ?>
              <span class="vcf-field">
                <?php if ($e['label']): ?><span class="vcf-label"><?= htmlspecialchars($e['label']) ?></span><?php endif ?>
                <a href="mailto:<?= htmlspecialchars($e['value']) ?>"><?= htmlspecialchars($e['value']) ?></a>
              </span>
            <?php endforeach; endif ?>
            <?php if (!empty($c['adr'])): foreach ($c['adr'] as $a): ?>
              <span class="vcf-field">
                <?php if ($a['label']): ?><span class="vcf-label"><?= htmlspecialchars($a['label']) ?></span><?php endif ?>
                <?= htmlspecialchars($a['value']) ?>
              </span>
            <?php endforeach; endif ?>
            <?php if (!empty($c['url'])): foreach ($c['url'] as $u): ?>
              <span class="vcf-field">
                <?php if ($u['label']): ?><span class="vcf-label"><?= htmlspecialchars($u['label']) ?></span><?php endif ?>
                <a href="<?= htmlspecialchars($u['value']) ?>" target="_blank" rel="noopener"><?= htmlspecialchars(preg_replace('#^https?://#', '', $u['value'])) ?></a>
              </span>
            <?php endforeach; endif ?>
            <?php if (!empty($c['bday'])): ?>
              <span class="vcf-field">
                <span class="vcf-label">Birthday</span>
                <?= htmlspecialchars($c['bday']) ?>
              </span>
            <?php endif ?>
            <?php if (!empty($c['note'])): ?>
              <span class="vcf-note"><?= nl2br(htmlspecialchars($c['note'])) ?></span>
            <?php endif ?>
          </div>
        <?php endforeach ?>
      <?php endif ?>
    </div>
    <?php
  }

  private static function vcf_type_label(string $params): string {
    $labels = [];
    if (preg_match_all('/TYPE=([^;,]+)/i', $params, $m))
      $labels = $m[1];
    $labels = array_filter($labels, fn($l) => !in_array(strtoupper($l), ['UNKNOWN', 'INTERNET', 'PREF', 'VALUE']));
    return implode(', ', array_map('ucfirst', array_map('strtolower', $labels)));
  }

  private static array $audioCoverCache = [];

  private static function audio_cover(string $filename): ?string {
    if (array_key_exists($filename, self::$audioCoverCache)) return self::$audioCoverCache[$filename];
    $tagsDir = Base::data_path('tags');
    if (!is_dir($tagsDir)) return self::$audioCoverCache[$filename] = null;
    $tagDirs = glob("{$tagsDir}/*/{$filename}.txt");
    if (!$tagDirs) return self::$audioCoverCache[$filename] = null;
    usort($tagDirs, function ($a, $b) {
      return count(scandir(dirname($a))) - count(scandir(dirname($b)));
    });
    foreach ($tagDirs as $tagFile) {
      $tagDir = dirname($tagFile);
      foreach (array_diff(scandir($tagDir), ['.', '..']) as $entry) {
        $peer = str_replace('.txt', '', $entry);
        if ($peer === $filename) continue;
        $peerReal = self::real_name($peer);
        if (Base::is_image($peerReal)) {
          return self::$audioCoverCache[$filename] = '/?route=thumb/' . urlencode($peer);
        }
      }
    }
    return self::$audioCoverCache[$filename] = null;
  }

  public static function preview(string $filename): void {
    $realName = self::real_name($filename);
    $src      = '/?route=load/' . urlencode($filename) . '/' . urlencode($realName);
    $validTypes = ['images', 'videos', 'audio', 'documents', 'archives', 'texts', 'fonts', 'contacts', 'design'];
    $linkCtx  = array_filter(['file' => $filename, 'tag' => isset($_GET['tag']) ? Base::str_clean($_GET['tag']) : null, 'type' => isset($_GET['type']) && in_array($_GET['type'], $validTypes, true) ? $_GET['type'] : null], fn($v) => $v !== null);
    $link     = htmlspecialchars(Base::url($linkCtx));
    $ext      = strtolower(pathinfo($realName, PATHINFO_EXTENSION));
    $name     = htmlspecialchars($realName);
    $fp = Base::data_path('files/' . $filename);
    if (is_file($fp)) {
      $filesize = filesize($fp);
    } else {
      $marker = S3::read_marker($filename);
      $filesize = is_array($marker) ? (int)($marker['plain_size'] ?? 0) : false;
    }
    $tooLarge  = $filesize !== false && $filesize > Base::INLINE_SIZE_LIMIT;
    $sizeLabel = $filesize !== false ? Base::format_bytes($filesize) : '';
    $isPublic  = self::is_published($filename);
    ?>
      <figure>
        <?php if ($isPublic): ?><span class="tile-public-badge"><svg xmlns="http://www.w3.org/2000/svg" height="14" viewBox="0 -960 960 960" width="14" fill="currentColor"><path d="M240-160h480v-400H240v400Zm296.5-143.5Q560-327 560-360t-23.5-56.5Q513-440 480-440t-56.5 23.5Q400-393 400-360t23.5 56.5Q447-280 480-280t56.5-23.5ZM240-160v-400 400Zm0 80q-33 0-56.5-23.5T160-160v-400q0-33 23.5-56.5T240-640h280v-80q0-83 58.5-141.5T720-920q83 0 141.5 58.5T920-720h-80q0-50-35-85t-85-35q-50 0-85 35t-35 85v80h120q33 0 56.5 23.5T800-560v400q0 33-23.5 56.5T720-80H240Z"/></svg></span><?php endif ?>
        <?php if (Base::is_video($realName) && !self::is_webm_audio($filename)): ?>
          <?php if (file_exists(Base::data_path('thumbs/' . $filename)) || Base::ffmpeg_bin()): ?>
            <a href="<?= $link ?>" class="video-play">
              <img class="tile" src="/?route=thumb/<?= urlencode($filename) ?>" loading="lazy">
              <span class="video-btn">
                <span class="play-btn">▶</span>
              </span>
              <video preload="none"><source src="<?= $src ?>"></video>
            </a>
          <?php else: ?>
            <a href="<?= $link ?>" class="video-play">
              <span class="tile tile-text">
                <span><?= strtoupper($ext) ?></span>
                <span class="tile-filename"><?= $name ?></span>
                <?php if ($sizeLabel): ?><span class="tile-filesize"><?= $sizeLabel ?></span><?php endif ?>
              </span>
              <span class="video-btn">
                <span class="play-btn">▶</span>
              </span>
              <video preload="none"><source src="<?= $src ?>"></video>
            </a>
          <?php endif ?>
        <?php elseif (Base::is_audio($realName) || self::is_webm_audio($filename)): ?>
          <?php $cover = self::audio_cover($filename); ?>
          <?php if ($cover): ?>
            <a href="<?= $link ?>" class="audio-play">
              <img class="tile" src="<?= htmlspecialchars($cover) ?>" loading="lazy">
              <span class="audio-btn">
                <span class="play-btn">▶</span>
              </span>
              <audio preload="none"><source src="<?= $src ?>"></audio>
            </a>
          <?php else: ?>
            <a href="<?= $link ?>" class="tile audio-play">
              <span><?= strtoupper($ext) ?></span>
              <span class="tile-filename"><?= $name ?></span>
              <?php if ($sizeLabel): ?><span class="tile-filesize"><?= $sizeLabel ?></span><?php endif ?>
              <span class="audio-btn">
                <span class="play-btn">▶</span>
              </span>
              <audio preload="none"><source src="<?= $src ?>"></audio>
            </a>
          <?php endif ?>
        <?php elseif (Base::is_image($realName)): ?>
          <?php $imgSrc = file_exists(Base::data_path('thumbs/' . $filename)) ? '/?route=thumb/' . urlencode($filename) : $src; ?>
          <a href="<?= $link ?>">
            <img class="tile" src="<?= $imgSrc ?>" loading="lazy">
          </a>
        <?php elseif ($ext === 'pdf'): ?>
          <?php
            if (!file_exists(Base::data_path('thumbs/' . $filename)) && Base::pdftoppm_bin()) {
              self::maybe_save_pdf_thumb($filename);
            }
          ?>
          <?php if (file_exists(Base::data_path('thumbs/' . $filename))): ?>
            <a href="<?= $link ?>">
              <img class="tile" src="/?route=thumb/<?= urlencode($filename) ?>" loading="lazy">
            </a>
          <?php else: ?>
            <a href="<?= $link ?>">
              <span class="tile tile-text">
                <span><?= strtoupper($ext) ?></span>
                <span class="tile-filename"><?= $name ?></span>
                <?php if ($sizeLabel): ?><span class="tile-filesize"><?= $sizeLabel ?></span><?php endif ?>
              </span>
            </a>
          <?php endif ?>
        <?php elseif (Base::is_office($realName)): ?>
          <?php
            if (!file_exists(Base::data_path('thumbs/' . $filename)) && Base::libreoffice_bin()) {
              self::maybe_save_office_thumb($filename);
            }
          ?>
          <?php if (file_exists(Base::data_path('thumbs/' . $filename))): ?>
            <a href="<?= $link ?>">
              <img class="tile" src="/?route=thumb/<?= urlencode($filename) ?>" loading="lazy">
            </a>
          <?php else: ?>
            <a href="<?= $link ?>">
              <span class="tile tile-text">
                <span><?= strtoupper($ext) ?></span>
                <span class="tile-filename"><?= $name ?></span>
                <?php if ($sizeLabel): ?><span class="tile-filesize"><?= $sizeLabel ?></span><?php endif ?>
              </span>
            </a>
          <?php endif ?>
        <?php elseif ($tooLarge): ?>
          <a href="<?= $link ?>">
            <span class="tile tile-text">
              <span><?= strtoupper($ext) ?></span>
              <span class="tile-filename"><?= $name ?></span>
              <?php if ($sizeLabel): ?><span class="tile-filesize"><?= $sizeLabel ?></span><?php endif ?>
            </span>
          </a>
        <?php elseif (in_array($ext, ['html', 'htm'])): ?>
          <a href="<?= $link ?>">
            <iframe class="tile" src="<?= $src ?>" sandbox=""></iframe>
          </a>
        <?php elseif (in_array($ext, ['txt', 'md'])): ?>
          <a href="<?= $link ?>">
            <span class="tile tile-text">
              <span><?= strtoupper($ext) ?></span>
              <span class="tile-filename"><?= $name ?></span>
              <?php if ($sizeLabel): ?><span class="tile-filesize"><?= $sizeLabel ?></span><?php endif ?>
            </span>
          </a>
        <?php elseif ($ext === 'vcf'): ?>
          <a href="<?= $link ?>">
            <span class="tile tile-text tile-vcf">
              <span><?= strtoupper($ext) ?></span>
              <span class="tile-filename"><?= $name ?></span>
            </span>
          </a>
        <?php else: ?>
          <a href="<?= $link ?>">
            <span class="tile tile-text">
              <span><?= strtoupper($ext) ?></span>
              <span class="tile-filename"><?= $name ?></span>
              <?php if ($sizeLabel): ?><span class="tile-filesize"><?= $sizeLabel ?></span><?php endif ?>
            </span>
          </a>
        <?php endif ?>
        <figcaption>
          <small title="<?= htmlspecialchars($realName) ?>"><a href="<?= $link ?>"><?= $name ?></a></small>
        </figcaption>
      </figure>
    <?php
  }

}