//
// app.js — client-side controller for Darkdrive
//
//   Media:       audio/video toggle playback in gallery tiles and detail view
//   Gallery:     lazy-load pages via IntersectionObserver, infinite scroll
//   Selection:   long-press (touch + mouse) to enter multi-select, shift-click range,
//                ctrl/cmd-click toggle; bulk delete, bulk tag, selective zip download
//   Search:      debounced input filters gallery tiles and tags, fetches server results
//   Upload:      sequential XHR queue with progress bar, drag-and-drop, wake lock,
//                CSRF token, error overlay for failed files
//   Overlays:    reusable modal setup (delete, download, share, zip, create file),
//                keyboard navigation (Escape to close, Enter to confirm)
//   Markdown:    lightweight renderer with HTML-entity escaping and safe-href filtering
//   Editor:      textarea with tab-indent, Ctrl+S save, unsaved-changes guard
//   Navigation:  arrow-key prev/next in detail view, type/tag select dropdowns
//
var currentVideo = null;

function toggleVideo(el, ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  var video = el.querySelector('video');
  var btnWrap = el.querySelector('.video-btn');
  var btn = btnWrap ? btnWrap.querySelector('span') : null;
  var thumb = el.querySelector('.tile');
  if (!video) return;
  if (currentVideo && currentVideo !== video) {
    currentVideo.pause();
    currentVideo.currentTime = 0;
    var prevEl = currentVideo.closest('.video-play');
    if (prevEl) {
      var prevBtn = prevEl.querySelector('.video-btn span');
      var prevBtnWrap = prevEl.querySelector('.video-btn');
      var prevThumb = prevEl.querySelector('.tile');
      if (prevBtn) prevBtn.innerHTML = '&#9654;';
      if (prevBtnWrap) prevBtnWrap.style.display = '';
      currentVideo.style.display = 'none';
      if (prevThumb) prevThumb.style.display = '';
    }
  }
  if (video.paused) {
    if (thumb) thumb.style.display = 'none';
    if (btnWrap) btnWrap.style.display = 'none';
    video.style.display = 'block';
    video.play();
    currentVideo = video;
    if (btn) btn.innerHTML = '&#9646;&#9646;';
    video.addEventListener('ended', function () {
      if (btn) btn.innerHTML = '&#9654;';
      if (btnWrap) btnWrap.style.display = '';
      video.style.display = 'none';
      if (thumb) thumb.style.display = '';
      currentVideo = null;
    }, {once: true});
  } else {
    video.pause();
    video.style.display = 'none';
    if (thumb) thumb.style.display = '';
    if (btnWrap) btnWrap.style.display = '';
    currentVideo = null;
    if (btn) btn.innerHTML = '&#9654;';
  }
}

var currentAudio = null;

function toggleAudio(el, ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  var audio = el.querySelector('audio');
  var btn = el.querySelector('.audio-btn span');
  if (!audio) return;
  if (currentAudio && currentAudio !== audio) {
    currentAudio.pause();
    currentAudio.currentTime = 0;
    var prevBtn = currentAudio.parentElement.querySelector('.audio-btn span');
    if (prevBtn) prevBtn.innerHTML = '&#9654;';
  }
  if (audio.paused) {
    audio.play();
    currentAudio = audio;
    if (btn) btn.innerHTML = '&#9646;&#9646;';
    audio.addEventListener('ended', function () {
      if (btn) btn.innerHTML = '&#9654;';
      currentAudio = null;
    }, {once: true});
  } else {
    audio.pause();
    currentAudio = null;
    if (btn) btn.innerHTML = '&#9654;';
  }
}

function observeSentinel() {
  var sentinel = document.getElementById('load-more-sentinel');
  if (!sentinel) return;
  var observer = new IntersectionObserver(function (entries) {
    if (!entries[0].isIntersecting) return;
    observer.disconnect();
    var offset = sentinel.dataset.offset;
    var lastBucket = sentinel.dataset.lastBucket || '';
    sentinel.remove();
    var url = new URL(location.href);
    url.searchParams.set('gallery_page', '1');
    url.searchParams.set('offset', offset);
    if (lastBucket) url.searchParams.set('last_bucket', lastBucket);
    fetch(url.toString(), { credentials: 'same-origin' })
      .then(function (r) { return r.text(); })
      .then(function (html) {
        var section = document.querySelector('main section');
        if (!section) return;
        var before = section.children.length;
        section.insertAdjacentHTML('beforeend', html);
        observeSentinel();
        var si = document.getElementById('nav-search-input');
        if (si && si.value) si.dispatchEvent(new Event('input'));
      })
      .catch(function () {});
  }, { rootMargin: '400px' });
  observer.observe(sentinel);
}

document.addEventListener('DOMContentLoaded', function () {
  observeSentinel();
  var autoUpdate = document.getElementById('update-auto');
  if (autoUpdate) setTimeout(function () { autoUpdate.submit(); }, 1500);

  var selecting = false;
  var longPressTimer = null;
  var longPressTriggered = false;
  var touchMoved = false;
  var lastToggledTile = null;

  function getTileDiv(el) {
    var d = el.closest('main section > div[data-file]');
    return d;
  }

  function getSelectedFiles() {
    var sel = [];
    document.querySelectorAll('main section > div[data-file].selected').forEach(function(d) {
      sel.push(d.dataset.file);
    });
    return sel;
  }
  window.getSelectedFiles = getSelectedFiles;

  function updateSelectionCount() {
    var count = document.querySelectorAll('main section > div[data-file].selected').length;
    var badge = document.getElementById('select-count');
    if (count > 0) {
      if (!selecting) enterSelecting();
      if (!badge) {
        badge = document.createElement('span');
        badge.id = 'select-count';
        badge.className = 'select-count';
        var row = document.querySelector('.row-end') || document.querySelector('.row');
        if (row) row.prepend(badge);
      }
      badge.textContent = count + (window.innerWidth > 999 ? ' selected' : '');
    } else {
      if (badge) badge.remove();
      if (selecting) exitSelecting();
    }
  }

  function enterSelecting() {
    selecting = true;
    document.body.classList.add('selecting');
  }

  function exitSelecting() {
    selecting = false;
    lastToggledTile = null;
    document.body.classList.remove('selecting');
    document.querySelectorAll('main section > div[data-file].selected').forEach(function(d) {
      d.classList.remove('selected');
    });
    var badge = document.getElementById('select-count');
    if (badge) badge.remove();
  }

  function toggleTile(div) {
    div.classList.toggle('selected');
    lastToggledTile = div;
    updateSelectionCount();
  }

  function selectRange(from, to) {
    var tiles = Array.from(document.querySelectorAll('main section > div[data-file]'));
    var a = tiles.indexOf(from);
    var b = tiles.indexOf(to);
    if (a === -1 || b === -1) return;
    var start = Math.min(a, b);
    var end = Math.max(a, b);
    for (var i = start; i <= end; i++) {
      tiles[i].classList.add('selected');
    }
    lastToggledTile = to;
    updateSelectionCount();
  }

  document.addEventListener('mousedown', function(e) {
    if (e.button !== 0) return;
    var div = getTileDiv(e.target);
    if (!div) return;
    longPressTriggered = false;
    longPressTimer = setTimeout(function() {
      longPressTriggered = true;
      toggleTile(div);
    }, 500);
  });

  document.addEventListener('mouseup', function() {
    clearTimeout(longPressTimer);
    longPressTimer = null;
  });

  document.addEventListener('mousemove', function() {
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
  });

  document.addEventListener('click', function(e) {
    if (longPressTriggered) {
      e.preventDefault();
      e.stopPropagation();
      longPressTriggered = false;
      return;
    }
    var div = getTileDiv(e.target);
    if (!div) return;

    if (e.shiftKey && lastToggledTile) {
      e.preventDefault();
      e.stopPropagation();
      selectRange(lastToggledTile, div);
      return;
    }

    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      e.stopPropagation();
      toggleTile(div);
      return;
    }

    if (selecting) {

      if (e.target.closest('.play-btn')) return;
      e.preventDefault();
      e.stopPropagation();
      toggleTile(div);
    }
  }, true);

  document.addEventListener('touchstart', function(e) {
    var div = getTileDiv(e.target);
    if (!div) return;
    touchMoved = false;
    longPressTriggered = false;
    longPressTimer = setTimeout(function() {
      longPressTriggered = true;
      toggleTile(div);
    }, 500);
  }, { passive: true });

  document.addEventListener('touchmove', function() {
    touchMoved = true;
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
  }, { passive: true });

  document.addEventListener('touchend', function(e) {
    clearTimeout(longPressTimer);
    longPressTimer = null;
    if (longPressTriggered) {
      e.preventDefault();
      return;
    }
    if (selecting && !touchMoved) {
      var div = getTileDiv(e.target);
      if (div) {
        e.preventDefault();
        toggleTile(div);
      }
    }
  });



  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && selecting) {
      var openOverlay = document.querySelector('.share-overlay:not(.overlay-hidden), .error-overlay:not(.overlay-hidden)');
      if (!openOverlay) exitSelecting();
    }
  });

  document.addEventListener('click', function(e) {
    if (!selecting) return;
    var t = e.target;
    if (t === document.body || t.tagName === 'MAIN' || (t.tagName === 'SECTION' && t.closest('main'))
        || t.classList.contains('row') || t.classList.contains('row-end')
        || (t.tagName === 'SPAN' && t.style && t.style.flex)) {
      exitSelecting();
    }
  });

  var bulkDeleteBtn = document.getElementById('nav-bulk-delete-btn');
  var bulkTagBtn    = document.getElementById('nav-bulk-tag-btn');
  var normalTools   = [];
  ['nav-create-btn', 'nav-search-btn'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) normalTools.push(el);
  });

  function updateBulkTools() {
    var count = document.querySelectorAll('main section > div[data-file].selected').length;
    var show = count > 0;
    if (bulkDeleteBtn) bulkDeleteBtn.style.display = show ? '' : 'none';
    if (bulkTagBtn)    bulkTagBtn.style.display    = show ? '' : 'none';
    normalTools.forEach(function(el) { el.style.display = show ? 'none' : ''; });

    var zipTitle = document.querySelector('#zip-overlay h3');
    var zipAction = document.getElementById('zip-action');
    if (zipTitle && zipAction) {
      if (show) {
        zipTitle.textContent = 'Download ' + count + ' Selected File' + (count !== 1 ? 's' : '');
        zipAction.dataset.selectedMode = '1';
      } else {
        delete zipAction.dataset.selectedMode;
        if (zipAction.dataset.origTitle) zipTitle.textContent = zipAction.dataset.origTitle;
      }
    }
  }

  var _zipAction = document.getElementById('zip-action');
  var _zipTitle = document.querySelector('#zip-overlay h3');
  if (_zipAction) {
    _zipAction.dataset.origHref = _zipAction.href;
    _zipAction.dataset.origTitle = _zipTitle ? _zipTitle.textContent : 'Download All Files';
  }

  var _origUpdateCount = updateSelectionCount;
  updateSelectionCount = function() {
    _origUpdateCount();
    updateBulkTools();
  };

  var _origExit = exitSelecting;
  exitSelecting = function() {
    _origExit();
    updateBulkTools();
  };

  if (bulkDeleteBtn) {
    var bulkDeleteOverlay = document.getElementById('bulk-delete-overlay');
    var bulkDeleteForm    = document.getElementById('bulk-delete-form');
    var bulkDeleteTitle   = document.getElementById('bulk-delete-title');
    if (bulkDeleteOverlay) {
      bulkDeleteBtn.addEventListener('click', function() {
        var files = getSelectedFiles();
        if (!files.length) return;
        bulkDeleteTitle.textContent = 'Delete ' + files.length + ' file' + (files.length !== 1 ? 's' : '');

        bulkDeleteForm.querySelectorAll('input[name="bulk_delete[]"]').forEach(function(i) { i.remove(); });
        files.forEach(function(f) {
          var inp = document.createElement('input');
          inp.type = 'hidden'; inp.name = 'bulk_delete[]'; inp.value = f;
          bulkDeleteForm.appendChild(inp);
        });
        bulkDeleteOverlay.classList.remove('overlay-hidden');
      });
      document.getElementById('bulk-delete-close').addEventListener('click', function() {
        bulkDeleteOverlay.classList.add('overlay-hidden');
      });
      bulkDeleteOverlay.addEventListener('click', function(e) {
        if (e.target === bulkDeleteOverlay) bulkDeleteOverlay.classList.add('overlay-hidden');
      });
    }
  }

  if (bulkTagBtn) {
    var bulkTagOverlay = document.getElementById('bulk-tag-overlay');
    var bulkTagForm    = document.getElementById('bulk-tag-form');
    var bulkTagTitle   = document.getElementById('bulk-tag-title');
    var bulkTagInput   = document.getElementById('bulk-tag-input');
    if (bulkTagOverlay) {
      bulkTagBtn.addEventListener('click', function() {
        var files = getSelectedFiles();
        if (!files.length) return;
        bulkTagTitle.textContent = 'Tag ' + files.length + ' file' + (files.length !== 1 ? 's' : '');
        bulkTagForm.querySelectorAll('input[name="bulk_tag_files[]"]').forEach(function(i) { i.remove(); });
        files.forEach(function(f) {
          var inp = document.createElement('input');
          inp.type = 'hidden'; inp.name = 'bulk_tag_files[]'; inp.value = f;
          bulkTagForm.appendChild(inp);
        });
        bulkTagOverlay.classList.remove('overlay-hidden');
        if (bulkTagInput) setTimeout(function() { bulkTagInput.focus(); }, 50);
      });
      document.getElementById('bulk-tag-close').addEventListener('click', function() {
        bulkTagOverlay.classList.add('overlay-hidden');
      });
      bulkTagOverlay.addEventListener('click', function(e) {
        if (e.target === bulkTagOverlay) bulkTagOverlay.classList.add('overlay-hidden');
      });
    }
  }

  (function(){
    var s = document.getElementById('md-src'), o = document.getElementById('md-out');
    if (!s||!o) return;
    function safeHref(u) { return /^(javascript|data|vbscript):/i.test(u.trim()) ? '#' : u; }
    var t = s.textContent
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')
      .replace(/^#{6} (.+)$/gm,'<h6>$1</h6>').replace(/^#{5} (.+)$/gm,'<h5>$1</h5>')
      .replace(/^#{4} (.+)$/gm,'<h4>$1</h4>').replace(/^#{3} (.+)$/gm,'<h3>$1</h3>')
      .replace(/^#{2} (.+)$/gm,'<h2>$1</h2>').replace(/^# (.+)$/gm,'<h1>$1</h1>')
      .replace(/\*\*(.+?)\*\*/g,'<b>$1</b>').replace(/\*(.+?)\*/g,'<i>$1</i>')
      .replace(/`(.+?)`/g,'<code>$1</code>')
      .replace(/\[(.+?)\]\((.+?)\)/g,function(_,text,href){return '<a href="'+safeHref(href)+'">'+text+'</a>';})
      .replace(/^[-*] (.+)$/gm,'<li>$1</li>').replace(/^-{3,}$/gm,'<hr>');
    o.innerHTML = t.split(/\n\n+/).map(function(b){
      return /^<(h[1-6]|li|hr)/.test(b.trim())
        ? b.replace(/\n/g,'') : '<p>'+b.replace(/\n/g,'<br>')+'</p>';
    }).join('');
  })();

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' || e.key === 'Enter') {
      var overlays = document.querySelectorAll('.share-overlay:not(.overlay-hidden), .error-overlay:not(.overlay-hidden)');
      if (overlays.length) {
        var top = overlays[overlays.length - 1];
        if (e.key === 'Escape') {
          var closer = top.querySelector('.share-close, .error-ok-btn:not([style*="display:none"]), .modal-cancel-btn');
          if (!closer) return;
          e.preventDefault();
          if (closer.classList.contains('error-ok-btn')) closer.click();
          else top.classList.add('overlay-hidden');
          return;
        }
        if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
          var btn = top.querySelector('button[type="submit"], a.share-publish-btn, .error-ok-btn');
          if (btn) { e.preventDefault(); btn.click(); }
          return;
        }
      }
    }
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if (e.key === 'ArrowLeft')  { var a = document.getElementById('nav-prev'); if (a) location.href = a.href; }
    if (e.key === 'ArrowRight') { var a = document.getElementById('nav-next'); if (a) location.href = a.href; }
  });

  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.play-btn');
    if (btn) {
      var videoWrap = btn.closest('.video-play');
      if (videoWrap) { toggleVideo(videoWrap, e); return; }
      var audioWrap = btn.closest('.audio-play');
      if (audioWrap) { toggleAudio(audioWrap, e); return; }
    }
  });

  document.addEventListener('click', function(e) {
    var el = e.target.closest('[data-scroll-top]');
    if (el) { e.preventDefault(); scrollTo(0, 0); }
  });

  document.addEventListener('click', function(e) {
    var el = e.target.closest('[data-upload-trigger]');
    if (el) { var input = document.getElementById('uploads'); if (input) input.click(); }
  });

  function setupModal(btnId, overlayId, closeId, cancelId) {
    var btn = document.getElementById(btnId);
    var overlay = document.getElementById(overlayId);
    if (!btn || !overlay) return;
    btn.addEventListener('click', function() { overlay.classList.remove('overlay-hidden'); });
    document.getElementById(closeId).addEventListener('click', function() { overlay.classList.add('overlay-hidden'); });
    if (cancelId) document.getElementById(cancelId).addEventListener('click', function() { overlay.classList.add('overlay-hidden'); });
    overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.classList.add('overlay-hidden'); });
  }
  setupModal('nav-delete-btn', 'delete-overlay', 'delete-close');
  setupModal('nav-download-btn', 'download-overlay', 'download-close');
  var dlAction = document.getElementById('download-action');
  var dlOverlay = document.getElementById('download-overlay');
  if (dlAction && dlOverlay) dlAction.addEventListener('click', function() { setTimeout(function() { dlOverlay.classList.add('overlay-hidden'); }, 200); });

  var searchBtn = document.getElementById('nav-search-btn');
  if (searchBtn) {
    searchBtn.addEventListener('click', function() {
      if (document.querySelector('.file-title')) {
        window.location.href = '/';
      }
      var w = document.getElementById('nav-search-wrap');
      w.classList.toggle('open');
      searchBtn.classList.toggle('active', w.classList.contains('open'));
      var i = document.getElementById('nav-search-input');
      if (i.offsetParent) { i.focus(); } else { i.value = ''; i.dispatchEvent(new Event('input')); }
    });
  }

  setupModal('nav-share-btn', 'share-overlay', 'share-close');
  setupModal('nav-zip-btn', 'zip-overlay', 'zip-close');
  var zipAction = document.getElementById('zip-action');
  var zipOverlay = document.getElementById('zip-overlay');
  if (zipAction && zipOverlay) zipAction.addEventListener('click', function(e) {
    if (zipAction.dataset.selectedMode) {
      e.preventDefault();
      var form = document.createElement('form');
      form.method = 'POST';
      form.action = zipAction.dataset.origHref || zipAction.href;
      getSelectedFiles().forEach(function(f) {
        var inp = document.createElement('input');
        inp.type = 'hidden'; inp.name = 'files[]'; inp.value = f;
        form.appendChild(inp);
      });
      document.body.appendChild(form);
      form.submit();
      form.remove();
    }
    setTimeout(function() { zipOverlay.classList.add('overlay-hidden'); }, 200);
  });

  (function() {
    var createBtn = document.getElementById('nav-create-btn');
    var createOverlay = document.getElementById('create-overlay');
    if (!createBtn || !createOverlay) return;
    var createInput = document.getElementById('create-file-input');
    var createError = document.getElementById('create-file-error');
    var createForm  = document.getElementById('create-file-form');
    var allowedExts = ['txt','md','csv','html','htm','css','js','json','xml','py','ts','tsx','jsx','sh','yaml','yml','toml','sql','rb','go','rs','c','h','cpp','java','swift','kt','lua','r','ini','cfg','env','log','vcf'];
    createBtn.addEventListener('click', function() {
      createError.textContent = '';
      createOverlay.classList.remove('overlay-hidden');
      if (createInput) setTimeout(function() { createInput.focus(); }, 50);
    });
    document.getElementById('create-close').addEventListener('click', function() { createOverlay.classList.add('overlay-hidden'); });
    createOverlay.addEventListener('click', function(e) { if (e.target === createOverlay) createOverlay.classList.add('overlay-hidden'); });
    createForm.addEventListener('submit', function(e) {
      var val = createInput.value.trim();
      var dot = val.lastIndexOf('.');
      var ext = dot !== -1 ? val.slice(dot + 1).toLowerCase() : '';
      if (!ext) { createInput.value = val + '.txt'; }
      else if (allowedExts.indexOf(ext) === -1) {
        e.preventDefault();
        createError.textContent = 'Use a text extension: .txt, .md, .js, .json \u2026';
      }
    });
  })();

  document.querySelectorAll('.nav-type-select, .nav-tag-select').forEach(function(sel) {
    sel.addEventListener('change', function() { location.href = sel.value || '/'; });
  });

  document.querySelectorAll('img.tile').forEach(function(img) {
    if (img.complete) { img.style.animation = 'none'; }
    else { img.addEventListener('load', function() { img.style.animation = 'none'; }); }
  });

  var mainSection = document.querySelector('main section');
  if (mainSection) {
    new MutationObserver(function(mutations) {
      mutations.forEach(function(m) {
        m.addedNodes.forEach(function(node) {
          if (node.nodeType !== 1) return;
          var imgs = node.querySelectorAll ? node.querySelectorAll('img.tile') : [];
          imgs.forEach(function(img) {
            if (img.complete) { img.style.animation = 'none'; }
            else { img.addEventListener('load', function() { img.style.animation = 'none'; }); }
          });
        });
      });
    }).observe(mainSection, { childList: true });
  }

  var searchInput = document.getElementById('nav-search-input');
  var searchGallery = null;
  var searchDebounce = null;
  var footerOriginal = null;

  function updateSearchFooter(count) {
    var info = document.getElementById('footer-info');
    if (!info) return;
    if (footerOriginal === null) footerOriginal = info.innerHTML;
    info.textContent = count + ' search result' + (count !== 1 ? 's' : '');
  }

  function restoreFooter() {
    var info = document.getElementById('footer-info');
    if (info && footerOriginal !== null) info.innerHTML = footerOriginal;
  }

  var allTilesLoaded = false;
  function loadAllRemaining(cb) {
    if (allTilesLoaded) { cb(); return; }
    var sentinel = document.getElementById('load-more-sentinel');
    if (!sentinel) { allTilesLoaded = true; cb(); return; }
    var offset = sentinel.dataset.offset;
    var lastBucket = sentinel.dataset.lastBucket || '';
    sentinel.remove();
    var url = new URL(location.href);
    url.searchParams.set('gallery_page', '1');
    url.searchParams.set('offset', offset);
    if (lastBucket) url.searchParams.set('last_bucket', lastBucket);
    fetch(url.toString(), { credentials: 'same-origin' })
      .then(function (r) { return r.text(); })
      .then(function (html) {
        var section = document.querySelector('main section');
        if (!section) { allTilesLoaded = true; cb(); return; }
        section.insertAdjacentHTML('beforeend', html);
        cb();
        loadAllRemaining(cb);
      })
      .catch(function () { cb(); });
  }

  var searchAbort = null;
  function fetchSearchResults(query, cb) {
    if (searchAbort) searchAbort.abort();
    if (!query) { cb(''); return; }
    searchAbort = new AbortController();
    var url = new URL(location.href);
    url.searchParams.set('gallery_page', '1');
    url.searchParams.set('offset', '0');
    url.searchParams.set('all', '1');
    url.searchParams.set('search', query);
    fetch(url.toString(), { credentials: 'same-origin', signal: searchAbort.signal })
      .then(function (r) { return r.text(); })
      .then(function (html) { searchAbort = null; cb(html); })
      .catch(function () {});
  }

  if (searchInput) {
    searchInput.addEventListener('input', function () {
      var q = searchInput.value.toLowerCase();
      var tagsGrid = document.querySelector('.tags-grid');
      if (tagsGrid) {
        var tagTiles = tagsGrid.querySelectorAll('.tag-tile');
        if (q !== '') {
          var tagCount = 0;
          for (var t = 0; t < tagTiles.length; t++) {
            var label = tagTiles[t].querySelector('.tag-tile-label');
            var tagName = label ? label.textContent.toLowerCase() : '';
            var show = tagName.indexOf(q) !== -1;
            tagTiles[t].style.display = show ? '' : 'none';
            if (show) tagCount++;
          }
          updateSearchFooter(tagCount);
          clearTimeout(searchDebounce);
          searchDebounce = setTimeout(function () {
            var curQ = searchInput.value.toLowerCase();
            if (!curQ) return;
            fetchSearchResults(curQ, function (html) {
              if (!html) return;
              if (searchGallery) searchGallery.remove();
              searchGallery = document.createElement('section');
              searchGallery.className = 'search-gallery';
              searchGallery.innerHTML = html;
              tagsGrid.parentNode.insertBefore(searchGallery, tagsGrid.nextSibling);
              var fileCount = searchGallery.querySelectorAll(':scope > div').length;
              var tc = 0;
              for (var t = 0; t < tagTiles.length; t++) {
                if (tagTiles[t].style.display !== 'none') tc++;
              }
              updateSearchFooter(tc + fileCount);
            });
          }, 300);
        } else {
          clearTimeout(searchDebounce);
          if (searchAbort) searchAbort.abort();
          for (var t = 0; t < tagTiles.length; t++) tagTiles[t].style.display = '';
          if (searchGallery) { searchGallery.remove(); searchGallery = null; }
          restoreFooter();
        }
        return;
      }

      var section = document.querySelector('body > main > section');
      if (!section) return;
      if (!section.dataset.origHtml) section.dataset.origHtml = '1';
      if (q === '') {
        if (section.dataset.searchActive) {
          delete section.dataset.searchActive;
          location.reload();
        }
        restoreFooter();
        return;
      }
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(function () {
        var curQ = searchInput.value.toLowerCase();
        if (!curQ) return;
        fetchSearchResults(curQ, function (html) {
          section.dataset.searchActive = '1';
          section.innerHTML = '<h2 class="gallery-date">Searching for \u201C' + escHtml(searchInput.value) + '\u201D</h2>' + html;
          var dates = section.querySelectorAll(':scope > h2.gallery-date');
          for (var d = 1; d < dates.length; d++) dates[d].style.display = 'none';
          var count = section.querySelectorAll(':scope > div').length;
          updateSearchFooter(count);
        });
      }, 300);
    });
    searchInput.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        searchInput.value = '';
        searchInput.dispatchEvent(new Event('input'));
        document.getElementById('nav-search-wrap').classList.remove('open');
        var btn = document.getElementById('nav-search-btn');
        if (btn) btn.classList.remove('active');
      }
    });
  }

  function escHtml(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  const SHARE_CACHE = 'darkdrive-shared';
  const MAX_QUEUE   = 100;

  function sharedCache() {
    if (!window.caches) return Promise.resolve(null);
    return caches.has(SHARE_CACHE).then(function (exists) {
      return exists ? caches.open(SHARE_CACHE) : null;
    }).catch(function () { return null; });
  }

  const input = document.getElementById('uploads');
  if (!input) return;

  const uploadErrors = [];

  function formatSize(bytes) {
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024)    return Math.round(bytes / 1024) + ' KB';
    return bytes + ' B';
  }

  function showErrorBadge(status) {
    status.innerHTML = '<span class="error-badge" style="color:var(--danger);cursor:pointer">' + uploadErrors.length + ' failed</span>';
    status.querySelector('.error-badge').addEventListener('click', function() {
      var overlay = document.createElement('div');
      overlay.className = 'error-overlay overlay-hidden';
      overlay.innerHTML = '<div class="error-overlay-box">' +
        '<strong style="color:var(--danger)">Failed uploads</strong>' +
        '<ul>' + uploadErrors.map(function(n) { return '<li>' + escHtml(n) + '</li>'; }).join('') + '</ul>' +
        '<button class="error-ok-btn">OK</button></div>';
      document.body.appendChild(overlay);
      requestAnimationFrame(function() { overlay.classList.remove('overlay-hidden'); });
      overlay.querySelector('.error-ok-btn').addEventListener('click', function() {
        uploadErrors.length = 0;
        overlay.classList.add('overlay-hidden');
        setTimeout(function() { overlay.remove(); }, 200);
        status.innerHTML = '';
      });
    });
  }

  function updateFooter(addBytes) {
    const el = document.getElementById('footer-info');
    if (!el) return;
    const count = (parseInt(el.dataset.count, 10) || 0) + 1;
    const bytes = (parseInt(el.dataset.bytes, 10) || 0) + addBytes;
    el.dataset.count = count;
    el.dataset.bytes = bytes;
    el.textContent = count + ' encrypted file' + (count !== 1 ? 's' : '') + ' \u00b7 ' + formatSize(bytes);
  }

  const uploadMax = parseInt((document.querySelector('meta[name="upload-max"]') || {}).content || '0', 10);

  var dragCount = 0;
  document.addEventListener('dragenter', function (e) {
    e.preventDefault();
    if (!e.dataTransfer || !e.dataTransfer.types.includes('Files')) return;
    if (++dragCount === 1) document.body.classList.add('dragover');
  });
  document.addEventListener('dragleave', function (e) {
    e.preventDefault();
    if (--dragCount <= 0) { dragCount = 0; document.body.classList.remove('dragover'); }
  });
  document.addEventListener('dragover', function (e) { e.preventDefault(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { dragCount = 0; document.body.classList.remove('dragover'); }
  });
  document.addEventListener('drop', function (e) {
    e.preventDefault();
    dragCount = 0;
    document.body.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      input.dispatchEvent(new Event('change'));
    }
  });

  const FP_EDGE  = 1048576;
  const FP_FULL  = 33554432;
  const FP_LANES = 4;

  function mapLimit(items, limit, fn) {
    const out = new Array(items.length);
    let next = 0;
    function lane() {
      if (next >= items.length) return Promise.resolve();
      const i = next++;
      return fn(items[i], i).then(function (v) { out[i] = v; return lane(); });
    }
    const lanes = [];
    for (let i = 0; i < Math.min(limit, items.length); i++) lanes.push(lane());
    return Promise.all(lanes).then(function () { return out; });
  }

  function dropShared(file) {
    if (!file.darkdriveCacheKey) return;
    sharedCache().then(function (cache) { if (cache) cache.delete(file.darkdriveCacheKey); });
  }

  function fingerprint(file) {
    if (!window.crypto || !crypto.subtle) return Promise.resolve('');
    let parts;
    if (file.size <= FP_FULL) {
      parts = [file];
    } else {
      parts = [file.slice(0, FP_EDGE)];
      for (let i = 1; i <= 3; i++) {
        const mid = Math.floor(file.size * i / 4);
        parts.push(file.slice(mid, mid + FP_EDGE));
      }
      parts.push(file.slice(file.size - FP_EDGE));
    }
    return new Blob(['2:' + file.size + ':' + file.name.length + ':'].concat(parts)).arrayBuffer()
      .then(function (buf) { return crypto.subtle.digest('SHA-256', buf); })
      .then(function (hash) {
        return [...new Uint8Array(hash)].map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
      })
      .catch(function () { return ''; });
  }

  function filterKnown(files) {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (!csrfMeta) return Promise.resolve(files);
    return mapLimit(files, FP_LANES, fingerprint).then(function (prints) {
      const hashes = prints.filter(Boolean);
      if (hashes.length === 0) return files;
      const fd = new FormData();
      fd.append('csrf_token', csrfMeta.content);
      hashes.forEach(function (h) { fd.append('hashes[]', h); });
      return fetch('/dedupe', { method: 'POST', body: fd }).then(function (r) { return r.json(); }).then(function (data) {
        const known = new Set(data.known || []);
        return files.filter(function (f, i) {
          if (!prints[i] || !known.has(prints[i])) { f.darkdriveFingerprint = prints[i]; return true; }
          dropShared(f);
          return false;
        });
      }).catch(function () { return files; });
    });
  }

  let activeFiles  = null;
  let queueSkipped = 0;
  let queueExcess  = 0;

  function summary(skipped, excess) {
    const parts = [];
    if (skipped > 0) parts.push(skipped + ' already stored');
    if (excess  > 0) parts.push(excess + ' not queued (max ' + MAX_QUEUE + ')');
    return parts.join(' · ');
  }

  function flushSummary() {
    const status = document.getElementById('status');
    const msg = summary(queueSkipped, queueExcess);
    queueSkipped = 0;
    queueExcess  = 0;
    if (uploadErrors.length > 0) { showErrorBadge(status); return; }
    status.textContent = msg;
    setTimeout(function () { status.innerHTML = ''; }, 2500);
  }

  function startUploads(fileList) {
    const all = [...fileList];
    if (all.length === 0) return;
    const batch  = all.slice(0, MAX_QUEUE);
    const excess = all.length - batch.length;
    if (!activeFiles) document.getElementById('status').textContent = 'Checking …';
    filterKnown(batch).then(function (files) {
      runQueue(files, batch.length - files.length, excess);
    });
  }

  function runQueue(files, skipped, excess) {
    queueSkipped += skipped;
    queueExcess  += excess;
    if (activeFiles) { activeFiles.push.apply(activeFiles, files); return; }
    if (files.length === 0) { flushSummary(); return; }
    activeFiles = files;

    const status  = document.getElementById('status');
    const section = document.querySelector('main section');

    let wakeLock = null;
    (async function() {
      try { if (navigator.wakeLock) wakeLock = await navigator.wakeLock.request('screen'); } catch(e) {}
    })();

    const uploadNext = () => {
      if (files.length === 0) {
        status.classList.remove('uploading');
        if (wakeLock) { try { wakeLock.release(); } catch(e) {} wakeLock = null; }
        document.removeEventListener('visibilitychange', reacquireWakeLock);
        activeFiles = null;
        flushSummary();
        return;
      }

      const file = files.shift();
      if (uploadMax > 0 && file.size > uploadMax) {
        uploadErrors.push(file.name);
        dropShared(file);
        setTimeout(uploadNext, 0);
        return;
      }
      const fd   = new FormData();
      fd.append('upload', file);
      if (file.darkdriveFingerprint) fd.append('fingerprint', file.darkdriveFingerprint);
      const csrfMeta = document.querySelector('meta[name="csrf-token"]');
      if (csrfMeta) fd.append('csrf_token', csrfMeta.content);

      const prefixEl   = document.createElement('span');
      const nameEl     = document.createElement('span');
      const suffixEl   = document.createElement('span');
      const progressEl = document.createElement('span');
      prefixEl.className = 'progress-affix progress-label';
      suffixEl.className = 'progress-affix progress-pct';
      nameEl.className   = 'progress-name';
      progressEl.className = 'progress-item';
      prefixEl.textContent = 'Uploading';
      nameEl.textContent   = file.name;
      suffixEl.textContent = '0%';
      progressEl.append(prefixEl, nameEl, suffixEl);
      status.innerHTML = '';
      status.classList.add('uploading');
      status.appendChild(progressEl);

      const xhr = new XMLHttpRequest();
      xhr.open('POST', '', true);

      xhr.upload.onprogress = function (ev) {
        if (!ev.lengthComputable) return;
        const pct = Math.round((ev.loaded / ev.total) * 100);
        if (pct >= 100) {
          progressEl.classList.add('progress-processing');
          prefixEl.textContent  = 'Processing';
          suffixEl.innerHTML    = '&nbsp;';
        } else {
          progressEl.classList.remove('progress-processing');
          prefixEl.textContent  = 'Uploading';
          suffixEl.textContent  = pct + '%';
        }
      };

      xhr.onprogress = function () {
        var text = xhr.responseText || '';
        var last = text.trimEnd().split('\n').pop();
        if (!last) return;
        try {
          var msg = JSON.parse(last);
          if (msg.step === 'encrypting') {
            progressEl.classList.add('progress-processing');
            prefixEl.textContent = 'Encrypting';
            suffixEl.innerHTML = '&nbsp;';
          } else if (msg.step === 'uploading') {
            prefixEl.textContent = 'Uploading';
          }
        } catch(e) {}
      };

      xhr.onload = function () {
        const lines = xhr.responseText.trim().split('\n');
        const response = lines[lines.length - 1].trim();
        const bar = response.indexOf('|');
        const filename = bar >= 0 ? response.slice(0, bar) : response;
        if (filename && filename !== 'false' && !response.startsWith('{"error"')) {
          dropShared(file);
          var tileUrl = new URL(location.href);
          tileUrl.search = '';
          tileUrl.searchParams.set('render_tile', filename);
          var params = new URLSearchParams(location.search);
          if (params.get('tag'))  tileUrl.searchParams.set('tag',  params.get('tag'));
          if (params.get('type')) tileUrl.searchParams.set('type', params.get('type'));
          fetch(tileUrl.toString(), { credentials: 'same-origin' })
            .then(function (r) { return r.text(); })
            .then(function (html) {
              if (section) {
                var todayH2 = null;
                var headings = section.querySelectorAll('h2.gallery-date');
                for (var h = 0; h < headings.length; h++) {
                  if (headings[h].textContent === 'Today') { todayH2 = headings[h]; break; }
                }
                if (todayH2) {
                  todayH2.insertAdjacentHTML('afterend', html);
                } else {
                  section.insertAdjacentHTML('afterbegin', '<h2 class="gallery-date">Today</h2>' + html);
                }
              }
              updateFooter(file.size);
              progressEl.remove();
              setTimeout(uploadNext, 200);
            })
            .catch(function () {
              progressEl.remove();
              setTimeout(uploadNext, 200);
            });
        } else {
          var errMsg = file.name;
          var reason = '';
          try { var j = JSON.parse(response); reason = j.error || ''; if (j.detail) errMsg += ' — ' + j.detail; } catch(e) {}
          uploadErrors.push(errMsg);
          if (reason !== 'rate_limited' && reason !== 'storage_full') dropShared(file);
          progressEl.remove();
          setTimeout(uploadNext, 200);
        }
      };

      xhr.ontimeout = xhr.onerror = function () {
        uploadErrors.push(file.name);
        progressEl.remove();
        setTimeout(uploadNext, 500);
      };

      xhr.send(fd);
    };

    function reacquireWakeLock() {
      if (wakeLock !== null && document.visibilityState === 'visible') {
        navigator.wakeLock.request('screen').then(function(wl) { wakeLock = wl; }).catch(function() {});
      }
    }
    document.addEventListener('visibilitychange', reacquireWakeLock);

    uploadNext();
  }

  input.addEventListener('change', function (e) {
    const picked = [...e.target.files];
    input.value = '';
    startUploads(picked);
  });

  sharedCache().then(function (cache) {
    if (!cache) return;
    return cache.keys().then(function (keys) {
      if (keys.length === 0) return;
      const take = keys.slice(0, MAX_QUEUE);
      return mapLimit(take, FP_LANES, function (req) {
        return cache.match(req).then(function (resp) {
          if (!resp) return null;
          const name = decodeURIComponent(new URL(req.url).pathname.split('/').pop());
          return resp.blob().then(function (blob) {
            const file = new File([blob], name, { type: blob.type });
            file.darkdriveCacheKey = req.url;
            return file;
          });
        }).catch(function () { return null; });
      }).then(function (files) {
        const ready = files.filter(Boolean);
        if (ready.length === 0) return;
        queueExcess += keys.length - take.length;
        startUploads(ready);
      });
    });
  }).catch(function () {});
});

(function () {
  var ta = document.getElementById('edit-textarea');
  if (!ta) return;
  setTimeout(function() { ta.focus(); }, 50);
  var form = document.getElementById('edit-form');
  var dirty = false;

  ta.addEventListener('input', function () { dirty = true; });
  form.addEventListener('submit', function () { dirty = false; });

  ta.addEventListener('keydown', function (e) {
    if (e.key === 'Tab') {
      e.preventDefault();
      var start = ta.selectionStart;
      ta.value = ta.value.substring(0, start) + '  ' + ta.value.substring(ta.selectionEnd);
      ta.selectionStart = ta.selectionEnd = start + 2;
      dirty = true;
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      form.submit();
    }
  });

  window.addEventListener('beforeunload', function (e) {
    if (dirty) { e.preventDefault(); e.returnValue = ''; }
  });
}());