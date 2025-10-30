/* PSX Track List — единый скрипт страницы. */
(function () {
  // ===== Общие утилиты =====
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

  // CSRF
  function getCookie(name) {
    const m = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
    return m ? m.pop() : '';
  }

  // Глобально для inline-обработчика в HTML
  window.clickOnTrackInfo = function (evt) {
    const target = (evt && (evt.target || evt.srcElement)) || null;
    if (target && target.closest('.drag_handle')) return;
    const card = target ? target.closest('.track_container') : null; if (!card) return;
    const info = card.querySelector('.track_info'); if (!info) return;
    const willOpen = !info.classList.contains('selected');
    info.classList.toggle('selected', willOpen);
    card.classList.toggle('open', willOpen);
  };

  // «Караоке»
  window.toggleSyncedLyrics = function (btn) {
    const box = btn.closest('[data-role="synced-lyrics-cta"]'); if (!box) return;
    const flag = box.querySelector('input[type="hidden"][name="track_synced_lyrics[]"]');
    const willOn = !box.classList.contains('is-active');
    box.classList.toggle('is-active', willOn);
    if (flag) flag.value = willOn ? '1' : '0';
    btn.setAttribute('aria-pressed', willOn ? 'true' : 'false');
    btn.classList.toggle('btn-green', willOn);
    btn.classList.toggle('btn-orange', !willOn);
    btn.textContent = willOn ? 'Будет добавлен' : 'Добавить';
  };

  // Добавление ролей
  window.addTrackRoleRow = function (ctx) {
    const card = ctx && ctx.closest ? ctx.closest('.track_container') : $('#track_1');
    const box = card ? (card.querySelector('.roles') || card.querySelector('#roles_track_1')) : $('#roles_track_1');
    if (!box) return;
    const tpl = card.querySelector('#tpl_role_track');
    let node;
    if (tpl?.content?.firstElementChild) {
      node = tpl.content.firstElementChild.cloneNode(true);
    } else {
      const t = document.createElement('template');
      t.innerHTML = '<div class="role_row"><div class="inputs_row"><div class="input_block"><input type="text" name="track_person[]" class="pr-input" placeholder="Имя персоны"></div><div class="input_block"><select name="track_role[]" class="pr-select"><option value="" selected disabled>Роль персоны</option><option value="artist">Исполнитель</option><option value="feat">feat.</option><option value="composer">Автор музыки</option><option value="lyricist">Автор слов</option><option value="producer">Producer</option><option value="remixer">Remixer</option></select></div></div><span class="icon-square icon-trash" role="button" aria-label="Удалить">×</span></div>';
      node = t.content.firstElementChild;
    }
    const del = node.querySelector('.icon-trash');
    if (del) (del.closest('.icon-square') || del).onclick = () => node.remove();
    box.appendChild(node);
  };

  // ===== Инициализация =====
  document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('#track_list .upload_tracks_form');
    const zone = document.getElementById('upload_zone');
    const input = document.getElementById('track_files_input');
    const statusEl = document.getElementById('upload_status');

    if (form) form.addEventListener('submit', (e) => e.preventDefault());

    const firstCard = document.getElementById('track_1');
    if (!form || !zone || !input || !firstCard) return;

    let wrap = firstCard.parentElement;
    if (!wrap.id) wrap.id = 'tracks_wrap';
    if (!wrap.classList.contains('tracks_wrap')) wrap.classList.add('tracks_wrap');

    // Страховка шапки
    function fixHeaderLayout(card) {
      const header = (card || document).querySelector('.track_header'); if (!header) return;
      const time = header.querySelector('.track_time');
      if (time) { header.appendChild(time); time.style.marginLeft = 'auto'; time.style.whiteSpace = 'nowrap'; }
    }
    fixHeaderLayout(firstCard);
    firstCard.hidden = true;
    firstCard.dataset.template = '1';

    // ===== DnD =====
    function ensureDragHandle(card) {
      const header = card.querySelector('.track_header');
      if (!header || header.querySelector('.drag_handle')) return;
      const h = document.createElement('span');
      h.className = 'drag_handle';
      h.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>';
      header.insertBefore(h, header.firstElementChild);
    }
    function renumber() {
      const w = document.querySelector('#track_list .tracks_wrap') || wrap;
      const rows = w.querySelectorAll('.track_container:not([data-template="1"]):not([hidden]) .track_index');
      rows.forEach((el, i) => { el.textContent = String(i + 1); });
    }

    let dragSrc = null;

    function attachDnD(card) {
      ensureDragHandle(card);
      const handle = card.querySelector('.drag_handle');
      if (!handle) return;
      handle.addEventListener('mousedown', () => card.setAttribute('draggable', 'true'));
      ['mouseup', 'mouseleave'].forEach(ev => handle.addEventListener(ev, () => card.removeAttribute('draggable')));
      card.addEventListener('dragstart', (e) => {
        dragSrc = card;
        card.classList.add('drag-shadow');
        try { e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', card.id || 'track'); } catch (_) { }
      });
      card.addEventListener('dragend', () => {
        card.classList.remove('drag-shadow');
        wrap.querySelectorAll('.drop-target').forEach(n => n.classList.remove('drop-target'));
        dragSrc = null;
        renumber();
      });
    }
    wrap.addEventListener('dragover', function (e) {
      if (!dragSrc) return; e.preventDefault();
      const over = e.target.closest('.track_container'); if (!over || over === dragSrc) return;
      const rect = over.getBoundingClientRect();
      const before = e.clientY < rect.top + rect.height / 2;
      over.classList.add('drop-target');
      if (before) wrap.insertBefore(dragSrc, over); else wrap.insertBefore(dragSrc, over.nextSibling);
    });
    wrap.addEventListener('dragleave', (e) => { const c = e.target.closest('.track_container'); if (c) c.classList.remove('drop-target'); });
    wrap.addEventListener('drop', (e) => { e.preventDefault(); });
    attachDnD(firstCard);

    function setBusy(on) {
      zone.classList.toggle('uploading', on);
      if (statusEl) { statusEl.hidden = !on; statusEl.textContent = on ? 'Загрузка…' : ''; }
    }

    // ===== Длительность (для локальных файлов) =====
    function fmtTime(seconds) {
      if (!isFinite(seconds) || seconds <= 0) return '—:—';
      const s = Math.round(seconds);
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      return (h > 0 ? h + ':' + String(m).padStart(2, '0') + ':' : m + ':' + String(sec).padStart(2, '0'));
    }
    function setCardTime(card, seconds) {
      const el = card.querySelector('.track_time');
      if (el) el.textContent = (seconds == null) ? '—:—' : fmtTime(seconds);
    }
    function getDurationWithAudio(file) {
      return new Promise(function (resolve, reject) {
        const url = URL.createObjectURL(file);
        const a = new Audio();
        a.preload = 'metadata';
        a.src = url;
        let done = false;
        function cleanup() { if (!done) { done = true; URL.revokeObjectURL(url); } }
        a.addEventListener('loadedmetadata', function () { cleanup(); resolve(a.duration || 0); }, { once: true });
        a.addEventListener('error', function () { cleanup(); reject(new Error('audio error')); }, { once: true });
        setTimeout(function () { cleanup(); reject(new Error('audio timeout')); }, 8000);
      });
    }
    async function getDurationWithWA(file) {
      if (!(window.AudioContext || window.webkitAudioContext)) throw new Error('no audiocontext');
      const AC = window.AudioContext || window.webkitAudioContext;
      const ctx = new AC();
      try {
        const buf = await file.arrayBuffer();
        const decoded = await ctx.decodeAudioData(buf);
        return decoded.duration || 0;
      } finally { try { ctx.close(); } catch (e) { } }
    }
    async function detectDuration(file) {
      try { return await getDurationWithAudio(file); }
      catch (e) { try { return await getDurationWithWA(file); } catch (e2) { return null; } }
    }

    // ===== Правила текста (popover) =====
    (function () {
      function closeAll() { $all('#track_list .rules-popover:not([hidden])').forEach(p => p.setAttribute('hidden', '')); }
      function togglePanel(id) {
        const p = document.getElementById(id); if (!p) return;
        const willOpen = p.hasAttribute('hidden'); closeAll(); if (willOpen) p.removeAttribute('hidden');
      }
      document.addEventListener('click', function (e) {
        const btn = e.target.closest('#track_list .rules-link-btn');
        if (btn) { e.preventDefault(); e.stopPropagation(); togglePanel(btn.dataset.panel || 'lyrics_rules_panel_1'); return; }
        if (e.target.closest('#track_list .rules-close')) { e.preventDefault(); closeAll(); return; }
        const openPanel = $('#track_list .rules-popover:not([hidden])');
        if (openPanel && !openPanel.contains(e.target)) closeAll();
      }, true);
      document.addEventListener('keydown', e => { if (e.key === 'Escape') closeAll(); });
    })();

    // ===== Форматтер предпрослушивания =====
    (function () {
      const input = $('#track_extra_1 input[name="track_preview_start[]"]');
      if (!input) return;
      input.addEventListener('blur', function () {
        if (this.value === '') return;
        const v = Math.max(0, parseFloat(String(this.value).replace(',', '.')));
        if (!isFinite(v)) { this.value = ''; return; }
        this.value = v.toFixed(3);
      });
      input.addEventListener('input', function () {
        if (this.value === '') return;
        const v = parseFloat(String(this.value).replace(',', '.'));
        if (isFinite(v) && v < 0) this.value = '0.000';
      });
    })();

    // ===== ЯЗЫК ТРЕКА =====
    function ensureTrackLanguage(card, index) {
      const langWrap = card.querySelector('#track_language_1') || card.querySelector('.track_language');
      if (langWrap) langWrap.id = 'track_language_' + index;
      const inputBlock = langWrap ? (langWrap.querySelector('.input_block') || langWrap) : card;

      // Корректно сносим старые обёртки Selectize (с destroy), чтобы не оставался "призрак"
inputBlock.querySelectorAll('.selectize-control').forEach(ctrl => {
  const selInside = ctrl.querySelector('select');
  if (selInside && selInside.selectize) {
    try { selInside.selectize.destroy(); } catch(e) {}
  }
  ctrl.remove();
});
// На всякий случай уберём оторванные дропдауны
inputBlock.querySelectorAll('.selectize-dropdown').forEach(n => n.remove());


      const selects = inputBlock.querySelectorAll('select[name="track_language[]"]');
      let sel = selects[0];
      if (selects.length > 1) {
        for (let i = 1; i < selects.length; i++) selects[i].remove();
      }
      if (!sel) {
        sel = document.createElement('select');
        sel.name = 'track_language[]';
        inputBlock.appendChild(sel);
      }

      sel.id = 'track_language_select_' + index;
      sel.className = 'pr-select';

      if (window.PSX?.resetTrackLanguageSelect) {
        window.PSX.resetTrackLanguageSelect(card, sel.id);
      } else if (window.setupTrackLanguages) {
        window.setupTrackLanguages(sel.id);
      }
      // --- Дедупликация: оставляем только "живой" .selectize-control ---
const langWrapEl = langWrap || card.querySelector('.track_language');
if (langWrapEl) {
  const controls = Array.from(langWrapEl.querySelectorAll('.selectize-control'));
  // "Живой" — тот, у которого следом в DOM идёт сам <select name="track_language[]">
  const keep = controls.find(c => {
    const n = c.nextElementSibling;
    return n && n.tagName === 'SELECT' && n.name === 'track_language[]';
  }) || controls.pop(); // запасной вариант — последний

  controls.forEach(c => { if (c !== keep) c.remove(); });
  if (keep) keep.style.width = '100%';
}




      return sel;
    }

    // ===== Карточки =====
    function resetFields(card) {
      card.querySelectorAll('input[type="text"], input[type="hidden"], textarea').forEach(function (el) {
        if (el.type === 'hidden' && el.name === 'track_synced_lyrics[]') { el.value = '0'; return; }
        el.value = '';
      });
      card.querySelectorAll('input[type="checkbox"]').forEach(function (el) { el.checked = false; });
    }

    function initCard(card, index) {
      card.id = 'track_' + index;
      const idx = card.querySelector('.track_index'); if (idx) idx.textContent = String(index);

      const rolesBox = card.querySelector('#roles_track_1') || card.querySelector('[id^="roles_track_"]');
      if (rolesBox) rolesBox.id = 'roles_track_' + index;

      const addBtn = card.querySelector('#add_role_track_btn');
      if (addBtn) {
        addBtn.onclick = function () { window.addTrackRoleRow(addBtn); };
        const dst = card.querySelector('.roles');
        if (dst && !dst.querySelector('.role_row')) addBtn.click();
      }

      ensureTrackLanguage(card, index);
      fixHeaderLayout(card);
      attachDnD(card);
    }

    function bindTitleSync(card) {
      const input = card.querySelector('input[name="release_title"]') || card.querySelector('.track_titles input[type="text"]');
      const titleEl = card.querySelector('.track_title');
      if (!input || !titleEl) return;
      function apply() {
        const val = (input.value || '').trim();
        const orig = card.dataset.origName || '';
        titleEl.textContent = val || orig || 'Без названия';
      }
      input.addEventListener('input', apply);
      input.addEventListener('change', apply);
      apply();
    }

    function setOriginalCaption(card, base) {
      const label = card.querySelector('.track_orig_label');
      const nameEl = card.querySelector('.track_original');
      if (!label || !nameEl) return;
      if (base) {
        label.hidden = false; nameEl.hidden = false; nameEl.textContent = base; nameEl.title = base;
      } else {
        label.hidden = true; nameEl.hidden = true; nameEl.textContent = ''; nameEl.removeAttribute('title');
      }
    }

    function createCards(files) {
      files.forEach(async function (file) {
        const card = firstCard.cloneNode(true);
        card.removeAttribute('data-template');
        resetFields(card);
        const index = wrap.querySelectorAll('.track_container:not([data-template="1"]):not([hidden])').length + 1;
        initCard(card, index);
        card.hidden = false;

        const base = (file && file.name) ? file.name.replace(/\.[^.]+$/, '') : '';
        card.dataset.origName = base;
        setOriginalCaption(card, base);

        const titleEl = card.querySelector('.track_title');
        if (titleEl) titleEl.textContent = base || ('Трек ' + index);
        const inputTitle = card.querySelector('input[name="release_title"]') || card.querySelector('.track_titles input[type="text"]') || card.querySelector('input[type="text"]');
        if (inputTitle) inputTitle.value = base;

        bindTitleSync(card);

        setCardTime(card, null);
        try {
          const dur = await detectDuration(file);
          setCardTime(card, dur);
        } catch (e) {
          setCardTime(card, null);
        }
        setAudioPreview(card, file);

        wrap.appendChild(card);
        renumber();
      });
    }

    // ===== Очередь загрузок =====
    function getOrCreateQueue() {
      let q = document.getElementById('upload_queue');
      if (!q) {
        q = document.createElement('div');
        q.id = 'upload_queue';
        q.className = 'upload_queue';
        q.hidden = true;
        const statusEl = document.getElementById('upload_status');
        if (statusEl && statusEl.parentElement) {
          statusEl.insertAdjacentElement('afterend', q);
        } else {
          (document.querySelector('#track_list form.upload_tracks_form') || document.body).appendChild(q);
        }
      }
      return q;
    }
    function makeQueueRow(filename) {
      const q = getOrCreateQueue();
      q.hidden = false;
      const row = document.createElement('div');
      row.className = 'upload_item';
      row.innerHTML = '<div class="upload_name"></div><div class="upload_pct">0%</div><div class="upload_bar"><i></i></div>';
      row.querySelector('.upload_name').textContent = filename;
      q.appendChild(row);
      const pct = row.querySelector('.upload_pct');
      const bar = row.querySelector('.upload_bar i');
      return {
        set(v) { v = Math.max(0, Math.min(100, v | 0)); pct.textContent = v + '%'; bar.style.width = v + '%'; },
        done() {
          pct.textContent = '100%'; bar.style.width = '100%'; row.classList.add('is-done');
          setTimeout(() => { row.remove(); if (!q.children.length) q.hidden = true; }, 1200);
        }
      };
    }

    // ===== Загрузка существующих треков =====
    async function loadExistingTracks() {
      const releaseId = window.current_release_id || document.querySelector('[data-release-id]')?.dataset.releaseId;
      if (!releaseId) return;

      try {
        const response = await fetch(`/releases/${releaseId}/tracks/`, {
          headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
        });

        if (response.ok) {
          const data = await response.json();
          console.log('[tracks] GET loaded:', { ok: data.ok, count: Array.isArray(data.items) ? data.items.length : 'n/a' });
          if (data.ok && Array.isArray(data.items)) {
            updateTrackListFromServer(data.items);
          }
        }
      } catch (e) {
        console.warn('Failed to load existing tracks:', e);
      }
    }

    // ===== Обновление трек-листа =====
    function updateTrackListFromServer(tracks) {
      wrap = document.getElementById('tracks_wrap') || wrap;
      const tmpl = document.getElementById('track_1'); // скрытый шаблон
      if (!wrap || !tmpl) return;

      const canSnap = typeof window.snapshotCardFields === 'function';
      const canRestore = typeof window.restoreCardFields === 'function';

      const editedById = {};
      const editedByNum = {};

      if (canSnap) {
        wrap.querySelectorAll('.track_container:not([data-template="1"]):not([hidden])')
          .forEach(card => {
            const snap = window.snapshotCardFields(card);
            const id = card.getAttribute('data-id');
            if (id) editedById[String(id)] = snap;
            const numText = card.querySelector('.track_index')?.textContent?.trim();
            if (numText) editedByNum['#' + numText] = snap;
          });
      }

      wrap.querySelectorAll('.track_container:not([data-template="1"]):not([hidden])').forEach(el => el.remove());

      if (!Array.isArray(tracks) || tracks.length === 0) {
        renumber();
        return;
      }

      const frag = document.createDocumentFragment();

      tracks.forEach((track, idx) => {
        const num = (typeof track.track_number === 'number' && track.track_number > 0) ? track.track_number : (idx + 1);
        const card = tmpl.cloneNode(true);
        card.removeAttribute('data-template');
        card.removeAttribute('hidden');

        // DOM id только локально уникальный (по порядку), чтоб не конфликтовать
        initCard(card, idx + 1);

        if (track.id != null) card.setAttribute('data-id', String(track.id));

        const titleEl = card.querySelector('.track_title');
        const inputTitle = card.querySelector('input[name="track_title[]"]') || card.querySelector('.track_titles input[type="text"]');
        const trackIndex = card.querySelector('.track_index');
        const audioEl = card.querySelector('.track_player');

        if (trackIndex) trackIndex.textContent = String(num);
        if (titleEl) titleEl.textContent = track.title || `Трек ${num}`;
        if (inputTitle) inputTitle.value = track.title || '';

        const origLabel = card.querySelector('.track_orig_label');
        const origName = card.querySelector('.track_original');
        const base = track.original_name || '';
        if (origLabel && origName) {
          if (base) {
            origLabel.hidden = false; origName.hidden = false;
            origName.textContent = base; origName.title = base; card.dataset.origName = base;
          } else {
            origLabel.hidden = true; origName.hidden = true;
            origName.textContent = ''; origName.removeAttribute('title'); delete card.dataset.origName;
          }
        }

        const timeEl = card.querySelector('.track_time');
        const audioSrc = track.audio_url || track.audio_file || '';
        if (audioEl && audioSrc) {
          audioEl.src = audioSrc;
          try { audioEl.load(); } catch (_) { }
          if (timeEl) {
            if (typeof track.duration_seconds === 'number') {
              const s = Math.max(0, Math.round(track.duration_seconds));
              const m = Math.floor(s / 60), sec = s % 60;
              timeEl.textContent = `${m}:${String(sec).padStart(2, '0')}`;
            } else {
              timeEl.textContent = '—:—';
              audioEl.addEventListener('loadedmetadata', () => {
                if (isFinite(audioEl.duration)) {
                  const s = Math.max(0, Math.round(audioEl.duration));
                  const m = Math.floor(s / 60), sec = s % 60;
                  timeEl.textContent = `${m}:${String(sec).padStart(2, '0')}`;
                }
              }, { once: true });
            }
          }
        } else if (timeEl) {
          timeEl.textContent = '—:—';
        }

        if (canRestore) {
          const saved = editedById[String(track.id)] || editedByNum['#' + String(num)];
          if (saved) {
            window.restoreCardFields(card, saved);
            const tInput = card.querySelector('input[name="track_title[]"]') || card.querySelector('.track_titles input[type="text"]');
            if (tInput && titleEl) titleEl.textContent = (tInput.value || titleEl.textContent);
          }
        }

        bindTitleSync(card);
        try { ensureTrackLanguage(card, num); } catch (e) { console.warn(e); }

        frag.appendChild(card);
      });

      wrap.appendChild(frag);
      renumber();
      console.log('[tracks] render complete:', wrap.querySelectorAll('.track_container:not([data-template="1"])').length);
    }

    // ===== Загрузка с прогрессом (XHR) =====
    async function uploadFiles(files) {
      if (!files || !files.length) return;

      const csrf = form?.querySelector('input[name="csrfmiddlewaretoken"]')?.value || '';
      let url = form?.getAttribute('action') || location.href;
      try {
        const u = new URL(url, window.location.origin);
        u.search = '';
        url = u.toString();
      } catch (_) { }

      setBusy(true);
      try {
        for (const f of files) {
          const row = makeQueueRow(f.name);
          const start = Date.now();

          await new Promise(function (resolve) {
            const fd = new FormData();
            fd.append('track_files[]', f);
            if (csrf) fd.append('csrfmiddlewaretoken', csrf);

            const xhr = new XMLHttpRequest();
            xhr.open('POST', url, true);
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.setRequestHeader('X-CSRFToken', csrf || getCookie('csrftoken') || '');

            let fakeTimer = setInterval(() => {
              let cur = parseInt((row._cur || 0), 10) || 0;
              cur = Math.min(cur + 6, 90);
              row._cur = cur; row.set(cur);
            }, 120);

            xhr.upload.onprogress = function (e) {
              if (fakeTimer) { clearInterval(fakeTimer); fakeTimer = null; }
              if (e.lengthComputable) {
                const p = Math.round(e.loaded / e.total * 100);
                row._cur = p; row.set(p);
              }
            };

            xhr.onload = function () {
              if (fakeTimer) { clearInterval(fakeTimer); fakeTimer = null; }

              let resp = null;
              try { resp = JSON.parse(xhr.responseText); } catch (e) { }

              // release_id с сервера
              if (resp && resp.release_id) {
                const root = document.getElementById('track_list');
                if (root) root.dataset.releaseId = String(resp.release_id);
                window.current_release_id = String(resp.release_id);
              }

              const hasRelease = !!(window.current_release_id || document.querySelector('[data-release-id]')?.dataset.releaseId);

              // 1) Если сервер прислал текущий ПОЛНЫЙ список — рисуем по нему и НИЧЕГО не перезатираем GET-ом.
              if (resp && Array.isArray(resp.tracks)) {
                console.log('[tracks] immediate render', resp.tracks.length);
                updateTrackListFromServer(resp.tracks);
              } else if (hasRelease) {
                // 2) Если треков в ответе нет — мягко подтянем GET-ом.
                setTimeout(loadExistingTracks, 250);
              }

              const left = Math.max(0, 500 - (Date.now() - start));
              setTimeout(() => { row.done(); resolve(); }, left);
            };

            xhr.onerror = function () {
              if (fakeTimer) { clearInterval(fakeTimer); fakeTimer = null; }
              row.done(); resolve();
            };

            xhr.send(fd);
          });
        }
      } finally {
        setBusy(false);
      }
    }

    // ===== Drag&Drop зоны + инпут =====
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('is-drag'); });
    zone.addEventListener('dragleave', () => { zone.classList.remove('is-drag'); });
    zone.addEventListener('drop', (e) => {
      e.preventDefault(); zone.classList.remove('is-drag');
      const files = Array.from(e.dataTransfer?.files || []); if (!files.length) return;
      input.files = e.dataTransfer.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });

    input.addEventListener('change', function () {
      const files = Array.from(this.files || []); if (!files.length) return;
      uploadFiles(files);
      this.value = '';
      try { document.getElementById('track_list').scrollIntoView({ behavior: 'smooth', block: 'end' }); } catch (e) { }
    });

    // Не инициализируем язык в шаблонной карточке — чтобы не было второй обёртки selectize
/* (убрано намеренно) */


    // Подтянуть существующие треки при открытии, если есть release_id
    const releaseId = document.querySelector('[data-release-id]')?.dataset.releaseId;
    if (releaseId && releaseId !== 'None') loadExistingTracks();

    // Экспорт внутрь window для inline-обработчиков
    window.createCards = createCards;
    window.uploadFiles = uploadFiles;
    window.updateTrackListFromServer = updateTrackListFromServer;
    window.loadExistingTracks = loadExistingTracks;
    window.ensureTrackLanguage = ensureTrackLanguage;
  });
})();

// Вне IIFE — предпрослушка локального файла
function setAudioPreview(card, file) {
  const audio = card.querySelector('.track_player');
  if (!audio || !file) return;
  try {
    const url = URL.createObjectURL(file);
    audio.src = url;
    audio.load();
  } catch (e) { console.warn('audio preview failed', e); }
}

/* =========================
   --- Patch: audio duration & URL fix ---
   Исправляет относительные пути аудио -> /media/…,
   и заполняет .track_time по метаданным (в т.ч. если они уже готовы).
   ========================= */
(function () {
  const ABS_OK = /^(https?:)?\/\//i;

  function absolutize(u) {
    if (!u) return '';
    if (ABS_OK.test(u) || u.startsWith('/')) return u;
    // при необходимости поменяй '/media/' на свой MEDIA_URL
    return '/media/' + String(u).replace(/^\.?\/+/, '');
  }

  function fmtDuration(sec) {
    if (!isFinite(sec) || sec <= 0) return '—:—';
    const m = Math.floor(sec / 60);
    const s = Math.round(sec - m * 60);
    return m + ':' + String(s).padStart(2, '0');
  }

  function pickFirstUnfilledTimeEl() {
    const list = document.querySelectorAll('.track_container .track_time');
    for (const el of list) {
      if (!el.dataset.filled) {
        const txt = (el.textContent || '').trim();
        if (txt === '' || txt === '—:—') return el;
      }
    }
    return null;
  }

  function updateTimeForAudio(aud) {
    if (!isFinite(aud.duration) || aud.duration <= 0) return false;

    const card  = aud.closest && aud.closest('.track_container');
    let   timeEl = card ? card.querySelector('.track_time') : null;
    if (!timeEl) timeEl = pickFirstUnfilledTimeEl();
    if (!timeEl || timeEl.dataset.filled === '1') return false;

    timeEl.textContent = fmtDuration(aud.duration);
    timeEl.dataset.filled = '1';
    return true;
  }

  function normalizeSrc(aud) {
    const raw = aud.getAttribute('src') || '';
    if (!raw) return;
    if (!ABS_OK.test(raw) && !raw.startsWith('/')) {
      const fixed = absolutize(raw);
      if (fixed !== raw) {
        aud.setAttribute('src', fixed);
        try { aud.load(); } catch (_) {}
      }
    }
  }

  function bindAudio(aud) {
    if (!aud || aud.__psx_bound__) return;
    aud.__psx_bound__ = true;

    normalizeSrc(aud);

    const tryUpdate = () => updateTimeForAudio(aud);

    if (aud.readyState >= 1) tryUpdate();
    ['loadedmetadata', 'durationchange', 'canplay', 'canplaythrough']
      .forEach(ev => aud.addEventListener(ev, tryUpdate));

    aud.addEventListener('error', () => {
      const now = aud.getAttribute('src') || '';
      if (now && !now.startsWith('/media/') && !ABS_OK.test(now)) {
        aud.setAttribute('src', absolutize(now));
        try { aud.load(); } catch (_) {}
      }
    });
  }

  function scan() {
    document.querySelectorAll('audio, .track_container audio, audio.track_player')
      .forEach(bindAudio);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scan);
  } else {
    scan();
  }

  const mo = new MutationObserver((muts) => {
    muts.forEach(m => {
      if (m.type === 'attributes' &&
          m.target && m.target.tagName === 'AUDIO' &&
          m.attributeName === 'src') {
        normalizeSrc(m.target);
        if (m.target.readyState >= 1) updateTimeForAudio(m.target);
        return;
      }
      m.addedNodes && m.addedNodes.forEach(n => {
        if (!n) return;
        if (n.tagName === 'AUDIO') bindAudio(n);
        else if (n.querySelectorAll) n.querySelectorAll('audio').forEach(bindAudio);

        if (n.classList && n.classList.contains('track_container')) {
          const t = n.querySelector('.track_time');
          if (t) t.removeAttribute('data-filled');
        }
      });
    });
  });
  mo.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['src']
  });

})();
