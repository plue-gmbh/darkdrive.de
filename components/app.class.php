<?php declare(strict_types=1);
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// App — application controller for Darkdrive
//
//   Bootstrap:  loads all components, initializes data dir, starts session
//   Routing:    maps clean URLs to internal GET params (load, thumb, tag, …)
//   Layout:     renders HTML shell — nav row, main content, footer, overlay modals
//   Status bar: storage percentage, HTTPS/writability/PHP checks
//   PWA:        service worker, manifest.json, offline page
//

class App {

  const VALID_TYPES = ['images', 'videos', 'audio', 'documents', 'archives', 'texts', 'fonts', 'contacts', 'design'];

  public static ?int   $appVersion   = null;
  public static ?array $updateInfo   = null;
  public static bool   $updateReady  = false;
  public static ?int   $storagePct   = null;
  public static bool   $statusErrors = false;
  public static bool   $groupView    = false;
  private static array $detailCtx    = [];
  private static array $zipCtx       = [];
  private static array $createCtx    = [];

  public function __construct() {
    self::boot();
    self::dispatch_early();
    self::dispatch_auth();
    self::check_updates();
    if (Login::user()) self::compute_status();
    self::layout();
  }

  private static function boot(): void {
    require_once __DIR__ . '/base.class.php';
    require_once __DIR__ . '/crypto.class.php';
    require_once __DIR__ . '/s3.class.php';
    require_once __DIR__ . '/login.class.php';
    require_once __DIR__ . '/upload.class.php';
    require_once __DIR__ . '/files.class.php';
    require_once __DIR__ . '/fileserver.class.php';
    require_once __DIR__ . '/emergency.class.php';
    require_once __DIR__ . '/update.class.php';
    require_once __DIR__ . '/status.class.php';
    register_shutdown_function(function() { Crypto::clear_cache(); });
    $dataDir = rtrim(Base::data_path(), '/');
    if (!is_dir($dataDir) && !mkdir($dataDir, 0755, true)) exit('Could not create data directory. Check file permissions.');
    if (!file_exists(Base::data_path('index.php'))) @file_put_contents(Base::data_path('index.php'), "<?php http_response_code(403); exit;\n");
    Base::protect_data_dir();
    FileServer::protect_public_dir();
    if (!Base::session_works()) exit;
    Base::security_headers();
    self::parse_route();
  }

  private static function dispatch_early(): void {
    if (isset($_GET['sw'])) self::service_worker();
    if (isset($_GET['manifest'])) self::manifest();
    if (isset($_GET['share'])) { http_response_code(303); Base::redirect('/?share_failed=nosw'); }

    $passwordFile = Base::data_path('.password');
    if (!file_exists($passwordFile)) self::handle_setup($passwordFile);

    $hash = file_get_contents($passwordFile);
    if ($hash === false) exit('Could not read password file. Check file permissions.');
    Login::init($hash);
    if (isset($_GET['offline'])) self::offline_page();
    Login::handle();

    if (Login::user() && Base::enc_key() === '') {
      Base::untrack_session();
      $_SESSION = [];
      session_regenerate_id(true);
      Base::clear_enc_cookie();
      Base::redirect();
    }
  }

  private static function dispatch_auth(): void {
    if (!Login::user()) {
      if (isset($_GET['api_files'])) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Unauthorized']);
        exit;
      }
      return;
    }

    $groupFile = Base::data_path('.group_view');
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle_group']) && Base::csrf_verify()) {
      if (file_exists($groupFile)) { @unlink($groupFile); } else { @file_put_contents($groupFile, ''); }
      $back = isset($_POST['_redirect']) ? $_POST['_redirect'] : '/';
      if (!str_starts_with($back, '/') || str_starts_with($back, '//')) $back = '/';
      Base::redirect($back);
    }
    self::$groupView = file_exists($groupFile);

    Files::api_list();
    Emergency::handle();
    Files::handle_create_file();
    Files::handle_edit_save();
    Files::handle_publish();
    Files::handle_unpublish();
    Files::handle_delete();
    Files::handle_bulk_delete();
    Files::handle_thumb();
    Files::handle();
    Files::handle_zip();
    Files::handle_gallery_page();
    Files::handle_render_tile();
    Upload::init(Base::data_path('files'), true);
    Upload::handle_dedupe_check();
    Upload::handle();
    Base::handle_tags();
    Update::perform();
  }

  private static function check_updates(): void {
    self::$appVersion  = (int)trim(@file_get_contents(__DIR__ . '/../.version') ?: '0') ?: null;
    self::$updateInfo  = (self::$appVersion && Login::user()) ? Update::check(self::$appVersion) : null;
    self::$updateReady = self::$updateInfo && self::$updateInfo['remote'] > self::$updateInfo['local'];
    if (Login::user() && self::$updateReady && !empty($_SESSION['just_logged_in'])) {
      unset($_SESSION['just_logged_in']);
      $_SESSION['auto_update'] = true;
      Base::redirect('/?route=update');
    }
    unset($_SESSION['just_logged_in']);
  }

  public static function layout(): void {
    self::head();
    ?>
<body>
  <?php self::render_nav_row() ?>
  <?php if (!Login::user()): ?>
    <?php Login::view() ?>
  <?php else: ?>
    <?php self::render_main() ?>
    <?php self::footer() ?>
    <script src="/components/app.js?v=<?= filemtime(dirname(__DIR__) . '/components/app.js') ?>"></script>
    <?php self::render_overlays() ?>
  <?php endif ?>
  <div id="offline-notice" class="offline-notice" style="display:none">You are offline</div>
  <script src="/components/app.offline.js?v=<?= filemtime(dirname(__DIR__) . '/components/app.offline.js') ?>"></script>
</body>
</html><?php
  }

  private static function render_nav_row(): void {
    ?>
  <div class="row">
    <?php if (Login::user()): ?>
      <?php if (isset($_GET['emergency']) && defined('DARKDRIVE_EMERGENCY_PASSWORD')): ?>
        <a href="/" class="button"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg></a>
      <?php elseif (isset($_GET['status']) || isset($_GET['update'])): ?>
        <a href="<?= isset($_GET['update']) ? '/?route=status' : '/' ?>" class="button button-back"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg></a>
      <?php elseif (empty($_GET['file'])): ?>
        <?php Upload::view() ?>
        <?php $mobileSpecial = !empty($_GET['tag']) || !empty($_GET['type']); ?>
        <label class="all-files-mobile<?= $mobileSpecial ? '' : ' active' ?>"><a href="/"<?php if (!$mobileSpecial): ?> data-scroll-top<?php endif ?>><span class="label-long">All Files</span><span class="label-short">All Files</span></a></label>
        <?php self::nav() ?>
      <?php else: ?>
        <?php self::header() ?>
      <?php endif ?>
      <span class="hide-mobile" style="flex:1"></span>
      <div class="row-end">
        <?php self::render_right_tools() ?>
        <?php self::render_title_label() ?>
      </div>
    <?php else: ?>
      <span style="flex:1"></span>
      <label><a href="https://darkdrive.de" target="_blank" rel="noopener noreferrer" style="color:var(--heading)"><?= htmlspecialchars(DARKDRIVE_TITLE) ?></a></label>
      <span style="flex:1"></span>
    <?php endif ?>
  </div>
    <?php
  }

  private static function render_right_tools(): void {
    if (!Login::user() || empty(Files::all_files())) return;

    if ((isset($_GET['status']) || isset($_GET['update']))): ?>
      <?php
        self::$zipCtx = ['url' => '/?zip=1', 'label' => Base::format_bytes(Files::filtered_plain_size()), 'title' => 'Download All Files'];
      ?>
      <div class="right-tools">
        <a href="/" class="nav-search-btn nav-tool-btn" title="Search"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg></a>
        <button type="button" class="nav-zip-btn nav-tool-btn" id="nav-zip-btn" title="Download ZIP"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/></svg></button>
      </div>
    <?php elseif (!isset($_GET['status']) && !isset($_GET['update']) && !(isset($_GET['emergency']) && defined('DARKDRIVE_EMERGENCY_PASSWORD'))): ?>
      <div class="right-tools">
        <?php if (empty($_GET['file'])): ?>
          <?php self::render_gallery_tools() ?>
        <?php else: ?>
          <?php self::render_detail_tools() ?>
        <?php endif ?>
      </div>
    <?php endif;
  }

  private static function render_gallery_tools(): void {
    $zipParams = array_filter(['tag' => isset($_GET['tag']) ? Base::str_clean($_GET['tag']) : null, 'type' => isset($_GET['type']) && in_array($_GET['type'], self::VALID_TYPES, true) ? $_GET['type'] : null], fn($v) => $v !== null);
    $zipTitle = 'Download All Files';
    if (!empty($zipParams['tag'])) $zipTitle = 'Download #' . htmlspecialchars($zipParams['tag']);
    elseif (!empty($zipParams['type'])) $zipTitle = 'Download All ' . ucfirst(htmlspecialchars($zipParams['type']));
    self::$zipCtx = ['url' => '/?' . http_build_query(array_merge(['zip' => '1'], $zipParams)), 'label' => Base::format_bytes(Files::filtered_plain_size()), 'title' => $zipTitle];
    self::$createCtx = ['tag' => isset($_GET['tag']) ? Base::str_clean($_GET['tag']) : null, 'type' => isset($_GET['type']) && in_array($_GET['type'], self::VALID_TYPES, true) ? $_GET['type'] : null];
    ?>
    <div class="nav-search-wrap" id="nav-search-wrap"><input type="text" id="nav-search-input" placeholder="Search ..." autocomplete="off"></div>
    <label class="nav-search-btn nav-tool-btn" id="nav-search-btn"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg></label>
    <button type="button" class="nav-zip-btn nav-tool-btn" id="nav-create-btn" title="Create File"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" fill="currentColor"><path d="M440-280h80v-160h160v-80H520v-160h-80v160H280v80h160v160ZM200-120q-33 0-56.5-23.5T120-200v-560q0-33 23.5-56.5T200-840h560q33 0 56.5 23.5T840-760v560q0 33-23.5 56.5T760-120H200Zm0-80h560v-560H200v560Zm0-560v560-560Z"/></svg></button>
    <button type="button" class="nav-zip-btn nav-tool-btn" id="nav-zip-btn" title="Download ZIP"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/></svg></button>
    <button type="button" class="nav-tool-btn bulk-tool" id="nav-bulk-tag-btn" title="Tag selected" style="display:none"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg></button>
    <button type="button" class="btn-delete nav-tool-btn bulk-tool" id="nav-bulk-delete-btn" title="Delete selected" style="display:none"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg></button>
    <?php
  }

  private static function render_detail_tools(): void {
    $detailFile = Base::str_clean($_GET['file']);
    $detailName = Files::real_name($detailFile);
    $detailHref = '/?route=load/' . urlencode($detailFile) . '/' . urlencode($detailName);

    $detailPath = Base::data_path('files/' . $detailFile);
    $detailSize = is_file($detailPath) ? filesize($detailPath) : false;
    if ($detailSize !== false && $detailSize <= Base::INLINE_SIZE_LIMIT && Base::is_editable($detailName)):
      $editBackType = isset($_GET['type']) && in_array($_GET['type'], self::VALID_TYPES, true) ? $_GET['type'] : null;
      $editCtx  = array_filter(['file' => $detailFile, 'tag' => isset($_GET['tag']) ? Base::str_clean($_GET['tag']) : null, 'type' => $editBackType], fn($v) => $v !== null && $v !== '');
      $editActive = isset($_GET['edit']);
      $editHref = htmlspecialchars($editActive ? Base::url($editCtx) : Base::url($editCtx) . '&edit=1');
    ?>
    <a href="<?= $editHref ?>" class="btn-edit nav-tool-btn<?= $editActive ? ' active' : '' ?>" title="<?= $editActive ? 'Cancel editing' : 'Edit file' ?>"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></a>
    <?php endif ?>
    <?php
      $isPublished = Files::is_published($detailFile);
      $shareSecret = Files::public_secret($detailFile);
      $shareProto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
      $shareLink = $shareProto . '://' . $_SERVER['HTTP_HOST'] . '/public/' . $shareSecret . '/' . rawurlencode($detailName);

      self::$detailCtx = [
        'file' => $detailFile, 'name' => $detailName, 'href' => $detailHref,
        'published' => $isPublished, 'shareLink' => $shareLink,
      ];
    ?>
    <label class="nav-share-btn nav-tool-btn<?= $isPublished ? ' published' : '' ?>" id="nav-share-btn" title="<?= $isPublished ? 'Shared file' : 'Share file' ?>">
      <?php if ($isPublished): ?>
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" fill="currentColor"><path d="M240-160h480v-400H240v400Zm296.5-143.5Q560-327 560-360t-23.5-56.5Q513-440 480-440t-56.5 23.5Q400-393 400-360t23.5 56.5Q447-280 480-280t56.5-23.5ZM240-160v-400 400Zm0 80q-33 0-56.5-23.5T160-160v-400q0-33 23.5-56.5T240-640h280v-80q0-83 58.5-141.5T720-920q83 0 141.5 58.5T920-720h-80q0-50-35-85t-85-35q-50 0-85 35t-35 85v80h120q33 0 56.5 23.5T800-560v400q0 33-23.5 56.5T720-80H240Z"/></svg>
      <?php else: ?>
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" fill="currentColor"><path d="M263.72-96Q234-96 213-117.15T192-168v-384q0-29.7 21.15-50.85Q234.3-624 264-624h24v-96q0-79.68 56.23-135.84 56.22-56.16 136-56.16Q560-912 616-855.84q56 56.16 56 135.84v96h24q29.7 0 50.85 21.15Q768-581.7 768-552v384q0 29.7-21.16 50.85Q725.68-96 695.96-96H263.72Zm.28-72h432v-384H264v384Zm267-141.21q21-21.21 21-51T530.79-411q-21.21-21-51-21T429-410.79q-21 21.21-21 51T429.21-309q21.21 21 51 21T531-309.21ZM360-624h240v-96q0-50-35-85t-85-35q-50 0-85 35t-35 85v96Zm-96 456v-384 384Z"/></svg>
      <?php endif ?>
    </label>
    <button type="button" title="Delete file" class="btn-delete nav-tool-btn" id="nav-delete-btn"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg></button>
    <button type="button" title="Download file" class="nav-zip-btn nav-tool-btn" id="nav-download-btn"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/></svg></button>
    <?php
  }

  private static function render_title_label(): void {
    $titleStyle = self::$updateReady ? 'color:var(--success)' : (self::$statusErrors ? 'color:var(--danger)' : '');
    $titleAttr = $titleStyle ? ' style="' . $titleStyle . '"' : '';
    $pctSuffix = self::$storagePct !== null ? ' (' . self::$storagePct . '%)' : '';
    ?>
    <label class="row-end-label"><span class="row-end-btn<?= isset($_GET['status']) ? ' active' : '' ?>"><?php if (isset($_GET['status'])): ?><span<?= $titleAttr ?>><?= htmlspecialchars(DARKDRIVE_TITLE) ?></span><span class="hide-mobile"> <?= $pctSuffix ?></span><?php else: ?><a href="/?route=status"><span<?= $titleAttr ?>><?= htmlspecialchars(DARKDRIVE_TITLE) ?></span><span class="hide-mobile"> <?= $pctSuffix ?></span></a><?php endif ?></span></label>
    <?php
  }

  private static function render_main(): void {
    ?>
    <main>
      <?php if (isset($_GET['emergency']) && defined('DARKDRIVE_EMERGENCY_PASSWORD')): ?>
        <?php Emergency::view() ?>
      <?php elseif (isset($_GET['update'])): ?>
        <?php Update::view(self::$updateInfo) ?>
      <?php elseif (isset($_GET['status'])): ?>
        <?php Status::view(self::$updateInfo) ?>
      <?php elseif (self::$groupView && empty($_GET['file']) && empty($_GET['tag'])): ?>
        <?php Files::home() ?>
      <?php elseif (empty($_GET['file'])): ?>
        <?php Files::gallery() ?>
      <?php else: ?>
        <?php Files::detail() ?>
      <?php endif ?>
    </main>
    <?php
  }

  private static function render_overlays(): void {
    $d = self::$detailCtx;
    if (!empty($d)): ?>
    <div class="share-overlay overlay-hidden" id="share-overlay">
      <div class="share-overlay-box">
        <span class="share-close" id="share-close">&times;</span>
        <?php if ($d['published']): ?>
          <h3>Shared &bdquo;<?= htmlspecialchars($d['name']) ?>&ldquo;</h3>
          <p>This file is publicly accessible via the link below.</p>
          <div class="share-link"><?= htmlspecialchars($d['shareLink']) ?></div>
          <form method="post" action="/">
            <?php Base::csrf_field() ?>
            <input type="hidden" name="unpublish" value="<?= htmlspecialchars($d['file']) ?>">
            <input type="hidden" name="_redirect" value="<?= htmlspecialchars($_SERVER['REQUEST_URI']) ?>">
            <button type="submit" class="share-delete-btn" id="share-action-btn">Unpublish</button>
          </form>
        <?php else: ?>
          <h3>Share &bdquo;<?= htmlspecialchars($d['name']) ?>&ldquo;</h3>
          <p>This will create an unencrypted, publicly accessible copy of your file behind a secret link.</p>
          <div class="share-link"><?= htmlspecialchars($d['shareLink']) ?></div>
          <form method="post" action="/">
            <?php Base::csrf_field() ?>
            <input type="hidden" name="publish" value="<?= htmlspecialchars($d['file']) ?>">
            <input type="hidden" name="_redirect" value="<?= htmlspecialchars($_SERVER['REQUEST_URI']) ?>">
            <button type="submit" class="share-publish-btn" id="share-action-btn">Publish</button>
          </form>
        <?php endif ?>
      </div>
    </div>
    <div class="share-overlay overlay-hidden" id="delete-overlay">
      <div class="share-overlay-box">
        <span class="share-close" id="delete-close">&times;</span>
        <h3>Delete &bdquo;<?= htmlspecialchars($d['name']) ?>&ldquo;</h3>
        <p>This file will be permanently deleted.</p>
        <form method="post" action="/">
          <?php Base::csrf_field() ?>
          <input type="hidden" name="delete" value="<?= htmlspecialchars($d['file']) ?>">
          <input type="hidden" name="_redirect" value="<?= htmlspecialchars(Base::url(array_filter(['tag' => isset($_GET['tag']) ? Base::str_clean($_GET['tag']) : null, 'type' => isset($_GET['type']) && in_array($_GET['type'], self::VALID_TYPES, true) ? $_GET['type'] : null], fn($v) => $v !== null))) ?>">
          <button type="submit" class="share-delete-btn">Delete</button>
        </form>
      </div>
    </div>
    <?php
      $dlFilesize = is_file(Base::data_path('files/' . $d['file'])) ? filesize(Base::data_path('files/' . $d['file'])) : false;
      $dlSizeLabel = $dlFilesize !== false ? Base::format_bytes($dlFilesize) : '';
    ?>
    <div class="share-overlay overlay-hidden" id="download-overlay">
      <div class="share-overlay-box">
        <span class="share-close" id="download-close">&times;</span>
        <h3>Download &bdquo;<?= htmlspecialchars($d['name']) ?>&ldquo;</h3>
        <?php if ($dlSizeLabel): ?><p><?= $dlSizeLabel ?></p><?php endif ?>
        <a href="<?= $d['href'] ?>" download="<?= htmlspecialchars($d['name']) ?>" class="share-publish-btn" id="download-action">Download</a>
      </div>
    </div>
    <?php endif ?>
    <?php $z = self::$zipCtx; if (!empty($z)): ?>
    <div class="share-overlay overlay-hidden" id="zip-overlay">
      <div class="share-overlay-box">
        <span class="share-close" id="zip-close">&times;</span>
        <h3><?= $z['title'] ?></h3>
        <p><?= $z['label'] ?></p>
        <a href="<?= htmlspecialchars($z['url']) ?>" class="share-publish-btn" id="zip-action">Download ZIP</a>
      </div>
    </div>
    <div class="share-overlay overlay-hidden" id="bulk-delete-overlay">
      <div class="share-overlay-box">
        <span class="share-close" id="bulk-delete-close">&times;</span>
        <h3 id="bulk-delete-title">Delete selected files</h3>
        <p>These files will be permanently deleted.</p>
        <form method="post" action="/" id="bulk-delete-form">
          <?php Base::csrf_field() ?>
          <input type="hidden" name="_redirect" value="<?= htmlspecialchars($_SERVER['REQUEST_URI']) ?>">
          <button type="submit" class="share-delete-btn">Delete</button>
        </form>
      </div>
    </div>
    <div class="share-overlay overlay-hidden" id="bulk-tag-overlay">
      <div class="share-overlay-box">
        <span class="share-close" id="bulk-tag-close">&times;</span>
        <h3 id="bulk-tag-title">Tag selected files</h3>
        <form method="post" action="" id="bulk-tag-form">
          <?php Base::csrf_field() ?>
          <input type="text" name="tag" id="bulk-tag-input" placeholder="#tag" autocomplete="off" spellcheck="false">
          <button type="submit" class="share-publish-btn">Apply Tag</button>
        </form>
      </div>
    </div>
    <?php endif;
    if (!empty(self::$createCtx)): $c = self::$createCtx; ?>
    <div class="share-overlay overlay-hidden" id="create-overlay">
      <div class="share-overlay-box">
        <span class="share-close" id="create-close">&times;</span>
        <h3>Create File</h3>
        <form method="post" action="/" id="create-file-form">
          <?php Base::csrf_field() ?>
          <?php if (!empty($c['tag'])): ?><input type="hidden" name="_tag" value="<?= htmlspecialchars($c['tag']) ?>"><?php endif ?>
          <?php if (!empty($c['type'])): ?><input type="hidden" name="_type" value="<?= htmlspecialchars($c['type']) ?>"><?php endif ?>
          <input type="text" name="create_file" id="create-file-input" placeholder="notes.txt" autocomplete="off" spellcheck="false">
          <span class="create-file-error" id="create-file-error"></span>
          <button type="submit" class="share-publish-btn">Create</button>
        </form>
      </div>
    </div>
    <?php endif;
  }

  public static function head(): void {
    ?><!--
Darkdrive – Your Private Cloud – https://darkdrive.de
Copyright © <?= date('Y') ?> plue GmbH – https://plue.tech
-->
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title><?= htmlspecialchars(DARKDRIVE_TITLE) ?></title>
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="viewport" content="width=device-width, initial-scale=1.0<?= empty($_GET['file']) ? ', maximum-scale=1.0' : '' ?>">
  <meta name="theme-color" content="#0d1117">
  <link rel="icon" href="/favicon.ico">
  <link rel="apple-touch-icon" href="/touchicon.png">
  <link rel="manifest" href="/manifest.json">
  <link href="/components/app.css?v=<?= filemtime(__DIR__ . '/app.css') ?>" rel="stylesheet">
  <?php if (Login::user()): ?>
  <meta name="upload-max" content="<?= DARKDRIVE_MAX_FILESIZE * 1024 * 1024 ?>">
  <meta name="csrf-token" content="<?= Base::csrf_token() ?>">
  <?php endif ?>
</head>
    <?php
  }

  public static function nav(): void {
    $activeType = isset($_GET['type']) && in_array($_GET['type'], self::VALID_TYPES, true) ? $_GET['type'] : '';
    $activeTag  = isset($_GET['tag']) ? Base::str_clean($_GET['tag']) : '';
    $scanDir    = Base::data_path('files');
    $activeTagDir = $activeTag ? Base::resolve_tag_dir($activeTag) : null;

    $presentTypes = [];
    foreach (Files::all_files() as $f) {
      if ($activeTag && (!$activeTagDir || !file_exists("{$activeTagDir}/{$f}.txt"))) continue;
      foreach (self::VALID_TYPES as $tk) {
        if (!isset($presentTypes[$tk]) && Files::matches_type($f, $tk)) $presentTypes[$tk] = true;
      }
      if (count($presentTypes) === count(self::VALID_TYPES)) break;
    }

    $allTags = Base::get_all_tags();
    $tagCounts = [];
    foreach ($allTags as $tagName => $tagPath) {
      $tagName = (string)$tagName;
      $cnt = count(array_diff(scandir($tagPath), ['.', '..']));
      if ($cnt > 0) $tagCounts[$tagName] = $cnt;
    }
    arsort($tagCounts);
    ?>
    <div class="row-nav">
      <?php $isSpecialPage = isset($_GET['status']) || isset($_GET['update']); ?>
      <label class="all-files-nav<?= ($activeType || $activeTag || $isSpecialPage) ? '' : ' active' ?>"><a href="/"<?php if (!$activeType && !$activeTag && !$isSpecialPage): ?> data-scroll-top<?php endif ?>>All Files</a></label>
      <?php if (!$isSpecialPage): ?>
      <?php foreach (['images' => 'Images', 'videos' => 'Videos', 'audio' => 'Audio', 'documents' => 'Documents', 'archives' => 'Archives', 'texts' => 'Text', 'fonts' => 'Fonts', 'contacts' => 'Contacts', 'design' => 'Design'] as $typeKey => $typeLabel): ?>
        <?php if (!isset($presentTypes[$typeKey]) && $activeType !== $typeKey) continue ?>
        <?php $isActive = $activeType === $typeKey; $href = Base::url(array_filter(['tag' => $activeTag ?: null, 'type' => $isActive ? null : $typeKey], fn($v) => $v !== null)); ?>
        <label class="nav-type-filter<?= $isActive ? ' active' : '' ?>">
          <?php if ($isActive): ?><?= $typeLabel ?><?php else: ?><a href="<?= htmlspecialchars($href) ?>"><?= $typeLabel ?></a><?php endif ?>
        </label>
      <?php endforeach ?>
      <select class="nav-type-select">
        <option value="<?= htmlspecialchars(Base::url(array_filter(['tag' => $activeTag ?: null], fn($v) => $v !== null))) ?>">All Files</option>
        <?php foreach (['images' => 'Images', 'videos' => 'Videos', 'audio' => 'Audio', 'documents' => 'Documents', 'archives' => 'Archives', 'texts' => 'Text', 'fonts' => 'Fonts', 'contacts' => 'Contacts', 'design' => 'Design'] as $typeKey => $typeLabel): ?>
          <?php if (!isset($presentTypes[$typeKey]) && $activeType !== $typeKey) continue ?>
          <?php $href = Base::url(array_filter(['tag' => $activeTag ?: null, 'type' => $typeKey], fn($v) => $v !== null)); ?>
          <option value="<?= htmlspecialchars($href) ?>"<?= $activeType === $typeKey ? ' selected' : '' ?>><?= $typeLabel ?></option>
        <?php endforeach ?>
      </select>
      <?php endif ?>
      <?php if (!isset($_GET['status']) && !isset($_GET['update'])): ?>
      <?php foreach ($tagCounts as $tagName => $tagCount): $tagName = (string)$tagName; ?>
        <?php $isTagActive = $activeTag === $tagName; $tagHref = $isTagActive ? '/' : Base::url(array_filter(['tag' => $tagName, 'type' => $activeType ?: null], fn($v) => $v !== null)); ?>
        <label class="nav-tag-filter<?= $isTagActive ? ' active' : '' ?>">
          <?php if ($isTagActive): ?>#<?= htmlspecialchars($tagName) ?><?php else: ?><a href="<?= htmlspecialchars($tagHref) ?>">#<?= htmlspecialchars($tagName) ?></a><?php endif ?>
        </label>
      <?php endforeach ?>
      <?php if (!empty($tagCounts)): ?>
        <select class="nav-tag-select">
          <option value="<?= htmlspecialchars(Base::url(array_filter(['type' => $activeType ?: null], fn($v) => $v !== null))) ?>">#</option>
          <?php foreach ($tagCounts as $tagName => $tagCount): $tagName = (string)$tagName; ?>
            <?php $tagHref = Base::url(array_filter(['tag' => $tagName, 'type' => $activeType ?: null], fn($v) => $v !== null)); ?>
            <option value="<?= htmlspecialchars($tagHref) ?>"<?= $activeTag === $tagName ? ' selected' : '' ?>>#<?= htmlspecialchars($tagName) ?></option>
          <?php endforeach ?>
        </select>
      <?php endif ?>
      <?php endif ?>
      <label id="status"></label>
    </div>
    <?php
  }

  public static function footer(): void {
    $file = Base::str_clean($_GET['file'] ?? '');
    if (!empty($file)) {
      $leftLabel = '–';
      if (preg_match('/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/', $file, $m)) {
        $ts = mktime((int)$m[4], (int)$m[5], (int)$m[6], (int)$m[2], (int)$m[3], (int)$m[1]);
        $leftLabel = date('j. M Y, H:i', $ts);
      }
      $fp = Base::data_path('files/' . $file);
      $footerSize = is_file($fp) ? filesize($fp) : false;
      ?>
      <footer class="footer-bar">
        <div>
          <p><?= htmlspecialchars(Files::real_name($file)) ?></p>
          <?php if ($footerSize !== false): ?><p><?= Base::format_bytes($footerSize) ?></p><?php endif ?>
          <p><?= $leftLabel ?></p>
        </div>
      </footer>
      <?php
      return;
    }

    if (isset($_GET['status']) || isset($_GET['update']) || isset($_GET['emergency'])) { ?><footer class="footer-bar"></footer><?php return; }

    $uploadDir  = Base::data_path('files');
    $activeTag  = isset($_GET['tag'])  ? strtolower(Base::str_clean($_GET['tag']))  : '';
    $activeTagDir = $activeTag ? Base::resolve_tag_dir($activeTag) : null;
    $activeType = isset($_GET['type']) && in_array($_GET['type'], self::VALID_TYPES, true) ? $_GET['type'] : '';
    $statCount  = 0;
    $statBytes  = 0;
    foreach (Files::all_files() as $sf) {
      if ($activeTag && (!$activeTagDir || !file_exists("{$activeTagDir}/{$sf}.txt"))) continue;
      if ($activeType !== '' && !Files::matches_type($sf, $activeType)) continue;
      $statCount++;
      $localPath = "{$uploadDir}/{$sf}";
      if (is_file($localPath)) {
        $statBytes += (int)filesize($localPath);
      } else {
        $marker = S3::read_marker($sf);
        if ($marker !== false) $statBytes += (int)($marker['plain_size'] ?? $marker['size'] ?? 0);
      }
    }
    $statLabel = Base::format_bytes($statBytes);
    ?>
    <footer class="footer-bar">
      <?php if ($statCount > 0 && empty($_GET['file'])): ?>
        <form method="post" action="/" class="group-btn-form"><input type="hidden" name="toggle_group" value="1"><input type="hidden" name="_redirect" value="<?= htmlspecialchars($_SERVER['REQUEST_URI']) ?>"><?php Base::csrf_field() ?><button type="submit" class="group-btn<?= self::$groupView ? ' on' : '' ?>"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"/></svg></button></form>
      <?php endif ?>
      <span id="footer-info" data-count="<?= $statCount ?>" data-bytes="<?= $statBytes ?>"><?= $statCount ?> encrypted file<?= $statCount !== 1 ? 's' : '' ?> &middot; <?= $statLabel ?></span>
    </footer>
    <?php
  }

  private static function status_stamp(): string {
    $parts = [];
    foreach (['files', 'thumbs', '.storage_bytes', '.storage_bytes_s3'] as $p) {
      $parts[] = (int)@filemtime(Base::data_path($p));
    }
    return implode('-', $parts);
  }

  private static function compute_status(): void {
    $cache = $_SESSION['status_cache'] ?? null;
    $stamp = self::status_stamp();
    if (!isset($_GET['status']) && is_array($cache) && (time() - (int)($cache['t'] ?? 0)) < 60
        && ($cache['stamp'] ?? null) === $stamp) {
      self::$storagePct   = $cache['pct'];
      self::$statusErrors = (bool)$cache['err'];
      return;
    }
    $filesDir = Base::data_path('files');
    $totalBytes = 0;
    $allEncrypted = true;
    foreach (Files::all_files() as $f) {
      $fp = $filesDir . '/' . $f;
      if (!is_file($fp)) {
        $marker = S3::read_marker($f);
        if ($marker !== false) $totalBytes += (int)($marker['plain_size'] ?? $marker['size'] ?? 0);
        continue;
      }
      $totalBytes += filesize($fp);
      if ($allEncrypted && !Crypto::is_encrypted($fp)) $allEncrypted = false;
    }
    if (!$allEncrypted) self::$statusErrors = true;
    $thumbsDir = Base::data_path('thumbs');
    if (is_dir($thumbsDir)) {
      foreach (array_diff(scandir($thumbsDir), ['.', '..']) as $t) {
        $tp = $thumbsDir . '/' . $t;
        if (!is_file($tp)) continue;
        $first3 = file_get_contents($tp, false, null, 0, 3);
        if ($first3 === "\xFF\xD8\xFF") { self::$statusErrors = true; break; }
      }
    }
    if (!Base::data_outside_webroot()) self::$statusErrors = true;
    $storageLimitMB = defined('DARKDRIVE_MAX_STORAGE') ? DARKDRIVE_MAX_STORAGE : 1024;
    if ($storageLimitMB > 0) {
      $limitBytes = $storageLimitMB * 1024 * 1024;
      self::$storagePct = (int)round($totalBytes / $limitBytes * 100);
    }
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    if (!$https) self::$statusErrors = true;
    foreach (['', 'files', 'tags', 'thumbs'] as $sub) {
      $p = $sub === '' ? Base::data_path() : Base::data_path($sub);
      if (is_dir($p)) {
        $f = $p . '/.wchk_' . getmypid();
        $ok = @file_put_contents($f, '') !== false;
        if ($ok) @unlink($f);
        if (!$ok) self::$statusErrors = true;
      }
    }
    $uploadMax = Base::ini_bytes((string)ini_get('upload_max_filesize'));
    $postMax   = Base::ini_bytes((string)ini_get('post_max_size'));
    $memLimit  = Base::ini_bytes((string)ini_get('memory_limit'));
    $execTime  = (int)ini_get('max_execution_time');
    if ($uploadMax < 8 * 1048576) self::$statusErrors = true;
    if ($postMax < $uploadMax) self::$statusErrors = true;
    if ($memLimit >= 0 && $memLimit < 128 * 1048576) self::$statusErrors = true;
    if ($execTime > 0 && $execTime < 60) self::$statusErrors = true;
    if (is_readable('/proc/meminfo')) {
      $meminfo = @file_get_contents('/proc/meminfo');
      if ($meminfo && preg_match('/MemAvailable:\s+(\d+)/i', $meminfo, $ma)) {
        if ((int)$ma[1] < 256 * 1024) self::$statusErrors = true;
      }
    }
    $_SESSION['status_cache'] = ['t' => time(), 'stamp' => $stamp, 'pct' => self::$storagePct, 'err' => self::$statusErrors];
  }

  public static function header(): void {
    $file      = Base::str_clean($_GET['file'] ?? '');
    $backType  = isset($_GET['type']) && in_array($_GET['type'], self::VALID_TYPES, true) ? $_GET['type'] : null;
    $backHref  = htmlspecialchars(Base::url(array_filter(['tag' => isset($_GET['tag']) ? Base::str_clean($_GET['tag']) : null, 'type' => $backType], fn($v) => $v !== null)));
    $cleanName = Files::real_name($file);
    ?>
    <a href="<?= $backHref ?>" class="button button-back"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg></a>
    <label class="file-title">
      <a href="/?route=load/<?= urlencode($file) ?>/<?= urlencode($cleanName) ?>"><?= htmlspecialchars($cleanName) ?></a>
    </label>
    <div class="detail-tags header-tags hide-mobile<?= isset($_GET['edit']) ? ' edit-active' : '' ?>">
      <?php Files::render_tags($file) ?>
    </div>
    <?php
  }

  private static function parse_route(): void {
    if (empty($_GET['route'])) return;
    $parts = array_values(array_filter(explode('/', $_GET['route'])));
    for ($i = 0; $i < count($parts); $i++) {
      $p = $parts[$i];
      if ($p === 'manifest.json') { $_GET['manifest'] = '1'; continue; }
      if ($p === 'share') { $_GET['share'] = '1'; continue; }
      if ($p === 'dedupe') { $_GET['dedupe'] = '1'; continue; }
      if (in_array($p, ['logout', 'login', 'setup', 'update', 'status', 'destroy_sessions', 'emergency', 'offline', 'sw'], true)) {
        $_GET[$p] = '1';
      } elseif ($p === 'load' && isset($parts[$i + 1])) {
        $_GET['loadfile'] = rawurldecode($parts[$i + 1]);
        $i++;
      } elseif ($p === 'thumb' && isset($parts[$i + 1])) {
        $_GET['loadthumb'] = rawurldecode($parts[$i + 1]);
        $i++;
      } elseif ($p === 'render_tile' && isset($parts[$i + 1])) {
        $_GET['render_tile'] = rawurldecode($parts[$i + 1]);
        $i++;
      } elseif ($p === 'api' && isset($parts[$i + 1]) && $parts[$i + 1] === 'files') {
        $_GET['api_files'] = '1';
        $i++;
      } elseif (in_array($p, ['tag', 'type', 'file'], true) && isset($parts[$i + 1])) {
        $val = rawurldecode($parts[$i + 1]);
        if ($p === 'type') {
          $_GET[$p] = in_array($val, self::VALID_TYPES, true) ? $val : '';
        } else {
          $_GET[$p] = Base::str_clean($val);
        }
        $i++;
      }
    }
    unset($_GET['route']);
  }

  private static function service_worker(): never {
    $cssV  = filemtime(__DIR__ . '/app.css');
    $jsV   = filemtime(__DIR__ . '/app.offline.js');
    $icoV  = filemtime(__DIR__ . '/../favicon.ico');
    $iconV = filemtime(__DIR__ . '/../touchicon.png');
    $swHash = $cssV . '.' . $jsV . '.' . $icoV . '.' . $iconV;
    header('Content-Type: application/javascript');
    header('Cache-Control: no-cache');
    ?>
var CACHE='darkdrive-v<?= $swHash ?>';
var SHARED='darkdrive-shared';
var SHELL=['/components/app.css?v=<?= $cssV ?>','/components/app.offline.js?v=<?= $jsV ?>','/components/app.ttf','/favicon.ico?v=<?= $icoV ?>','/touchicon.png?v=<?= $iconV ?>','/offline'];
self.addEventListener('install',function(e){e.waitUntil(caches.open(CACHE).then(function(c){return c.addAll(SHELL)}));self.skipWaiting()});
self.addEventListener('activate',function(e){e.waitUntil(caches.keys().then(function(keys){return Promise.all(keys.filter(function(k){return k!==CACHE&&k!==SHARED}).map(function(k){return caches.delete(k)}))}));self.clients.claim()});
self.addEventListener('fetch',function(e){var req=e.request;if(req.method==='POST'&&new URL(req.url).pathname==='/share'){e.respondWith(req.formData().then(function(fd){var files=fd.getAll('upload').filter(function(f){return f&&f.size});var tok=Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,8);return caches.open(SHARED).then(function(c){return Promise.all(files.map(function(f,i){return c.put('/__shared/'+tok+'-'+i+'/'+encodeURIComponent(f.name),new Response(f,{headers:{'Content-Type':f.type||'application/octet-stream'}}))}))})}).then(function(){return Response.redirect('/?shared=1',303)}).catch(function(){return Response.redirect('/?share_failed=cache',303)}));return}if(req.method!=='GET')return;if(req.mode==='navigate'){e.respondWith(fetch(req).catch(function(){return caches.match('/offline')}));return}var path=new URL(req.url).pathname;var isShell=SHELL.some(function(s){return path===s||path.startsWith(s+'?')});if(isShell){e.respondWith(fetch(req).then(function(resp){var clone=resp.clone();caches.open(CACHE).then(function(c){c.put(req,clone)});return resp}).catch(function(){return caches.match(req,{ignoreSearch:true})}))}});
<?php
    exit;
  }

  private static function manifest(): never {
    $static = __DIR__ . '/../manifest.json';
    $iconV = filemtime(__DIR__ . '/../touchicon.png');
    header('Content-Type: application/manifest+json');
    header('Cache-Control: no-cache');
    echo json_encode([
      'name'             => DARKDRIVE_TITLE,
      'short_name'       => DARKDRIVE_TITLE,
      'start_url'        => '/',
      'display'          => 'standalone',
      'background_color' => '#0c0c0c',
      'theme_color'      => '#0c0c0c',
      'icons'            => [[
        'src'     => '/touchicon.png?v=' . $iconV,
        'sizes'   => '1024x1024',
        'type'    => 'image/png',
        'purpose' => 'maskable any',
      ]],
      'share_target' => [
        'action'  => '/share',
        'method'  => 'POST',
        'enctype' => 'multipart/form-data',
        'params'  => [
          'files' => [[
            'name'   => 'upload',
            'accept' => ['image/*', 'video/*', 'audio/*', 'application/pdf'],
          ]],
        ],
      ],
    ], JSON_UNESCAPED_SLASHES);
    exit;
  }

  private static function offline_page(): never {
    header('Cache-Control: no-cache');
    self::head();
    ?>
<body>
  <div class="row">
    <span style="flex:1"></span>
    <label><?= htmlspecialchars(DARKDRIVE_TITLE) ?></label>
    <span style="flex:1"></span>
  </div>
  <div class="login-container">
    <h1 class="login-title">You are offline</h1>
    <p>Check your internet connection and try again.</p>
    <a href="/" class="login-button" id="offline-retry">Retry</a>
  </div>
  <script src="/components/app.offline.js?v=<?= filemtime(__DIR__ . '/app.offline.js') ?>"></script>
</body>
</html><?php
    exit;
  }

  private static function handle_setup(string $passwordFile): void {
    $dataEmpty = !is_dir(Base::data_path('files'));
    if (!$dataEmpty) exit('Password file missing. Cannot regenerate — existing encrypted files would be lost.');
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['auth_key']) && strlen($_POST['auth_key']) <= 512 && Base::csrf_verify()
        && Base::auth_key_matches($_POST['auth_key'], (string)($_POST['password'] ?? ''))) {
      file_put_contents($passwordFile, 'SPLITKEY:' . password_hash($_POST['auth_key'], PASSWORD_DEFAULT));
      $_SESSION = [];
      session_destroy();
      Base::redirect();
    }
    Login::setup();
  }

}