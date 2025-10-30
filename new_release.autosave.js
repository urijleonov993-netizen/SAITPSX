// static/js/pages/new_release.autosave.js  (v=12 + hydrate)
(function () {
  document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('new_release_form');
    if (!form) return;

    // ===== state & guard =====
    let NR_TOUCHED = false;        // пользователь совершил реальное действие?
    let timer = null;
    let inflight = false;
    let HYDRATING = false; // идёт подстановка из БД — блокируем автосейв
    let TRACKS_DIRTY = false; // меняли ли что-то в трек-листе (даже если вкладка скрыта)

    function markTouched() {
  if (HYDRATING) return;   // во время гидратации «касание» игнорируем
  NR_TOUCHED = true;
  setHidden('_ua', '1');   // маркер для бэка
}


    // ===== utils =====
    function getCookie(name) {
      const v = `; ${document.cookie}`.split(`; ${name}=`);
      if (v.length === 2) return v.pop().split(';').shift();
      return '';
    }
    const csrftoken = getCookie('csrftoken');

    function read(el) {
  if (!el) return '';
  // ВАЖНО: для input/textarea всегда берём текущее значение, даже если оно пустое
  if ('value' in el && el.value !== undefined && el.value !== null) {
    return el.value; // позволяем '' — это значит «стереть»
  }
  const a = (n) => (el.getAttribute ? el.getAttribute(n) : '') || '';
  const d = (n) => (el.dataset ? el.dataset[n] : '') || '';
  return a('value') || a('src') || a('data-value') || d('value') || d('selectedValue') || d('url') || '';
}


    function setHidden(name, val) {
      let h = form.querySelector(`input[type="hidden"][name="${name}"]`);
      if (!h) {
        h = document.createElement('input');
        h.type = 'hidden';
        h.name = name;
        form.appendChild(h);
      }
      h.value = (val ?? '').toString();
    }

    function syncHidden() {
      const root = form;
      // Берём язык не только из вкладки «Релиз», но и из селекта на «Трек-листе»
const langSrc = document.querySelector('#language_metadata, [name="language_metadata"], #track_language_metadata, #track_language');
setHidden('language_metadata', read(langSrc));

      setHidden('album_title',      read(root.querySelector('#album_title')));
      setHidden('album_subtitle',   read(root.querySelector('#album_subtitle')));
      setHidden('type_release',     read(root.querySelector('#type_release')));
      setHidden('genre',            read(root.querySelector('#genre')));
      setHidden('subgenre',         read(root.querySelector('#subgenre')));
      setHidden('album_UPC',        read(root.querySelector('#album_UPC')));
      setHidden('release_date',     read(root.querySelector('#release_date')));
      setHidden('start_date',       read(root.querySelector('#start_date')));
      // cover (file) — отдастся <input type="file">
    }

    // ----- release id helper -----
    function getReleaseId() {
      const hid = form.querySelector('input[name="release_id"], #current_release_id');
      if (hid && hid.value) {
        const n = parseInt(hid.value, 10);
        if (!isNaN(n) && n > 0) return n;
      }
      const m = location.search.match(/[?&]edit=(\d+)/);
      if (m) {
        const n = parseInt(m[1], 10);
        if (!isNaN(n) && n > 0) return n;
      }
      if (window.__releaseId) {
        const n = parseInt(window.__releaseId, 10);
        if (!isNaN(n) && n > 0) return n;
      }
      return null;
    }

    // ===== tracks helpers =====
    function getTrackNumberFromCard(card, fallbackIndex) {
      const idxEl = card.querySelector('.track_index');
      if (idxEl && idxEl.textContent) {
        const onlyNums = idxEl.textContent.replace(/\D+/g, '');
        const n = parseInt(onlyNums || '0', 10);
        if (n > 0) return n;
      }
      const di = card.getAttribute('data-index') || (card.dataset ? card.dataset.index : '');
      if (di) {
        const n = parseInt(String(di).replace(/\D+/g, '') || '0', 10);
        if (n > 0) return n;
      }
      return fallbackIndex + 1;
    }

    // ——— title finder (с приоритетом release_title)
    function findTitleInput(card) {
      return (
        card.querySelector('input[name="release_title"]') ||
        card.querySelector('input[name="track_title"]') ||
        card.querySelector('[data-field="track_title"]') ||
        card.querySelector('[data-role="track-title"]') ||
        card.querySelector('.track_titles input[type="text"]') ||
        card.querySelector('.track_title input[type="text"]') ||
        card.querySelector('.track_title') ||
        card.querySelector('input[type="text"]')
      );
    }

    // ——— subtitle/version finder (поддерживает release_subtitle)
    function findVersionInput(card) {
      const el = card.querySelector(
        'input[name="release_subtitle"],' +
        'input[name="release_subtitle[]"],' +
        'textarea[name="release_subtitle"],' +
        'textarea[name="release_subtitle[]"],' +
        '[data-name="release_subtitle"],' +
        '[data-field="release_subtitle"],' +
        '#release_subtitle,' +
        'input[name="track_subtitle"],' +
        'textarea[name="track_subtitle"],' +
        'input[name="subtitle"],' +
        'textarea[name="subtitle"],' +
        'input[name="track_version"],' +
        'textarea[name="track_version"],' +
        'input[name="version"],' +
        'textarea[name="version"],' +
        '.track_titles .input_block:nth-child(2) input,' +
        '.track_subtitle input[type="text"]'
      );
      if (!el) return null;
      if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') return el;
      const inner = el.querySelector && el.querySelector('input, textarea');
      return inner || null;
    }
// --- универсальный поиск чекбоксов версии (explicit/drugs/instrumental)
// Ищем строго в пределах .track_versions, поддерживаем и data-flag, и name-атрибуты
function findVersionFlag(card, key) {
  if (!card) return null;
  const scope = card.querySelector('.track_versions') || card;

  // приоритетно data-flag (самый надёжный)
  let el = scope.querySelector('input[type="checkbox"][data-flag="' + key + '"]');
  if (el) return el;

  // точные имена, которые часто встречаются в твоей вёрстке
  const tries = [
    'input[type="checkbox"][name="track_version_' + key + '[]"]',
    'input[type="checkbox"][name="track_' + key + '[]"]',
    '[data-name="track_version_' + key + '"] input[type="checkbox"]',
    '[data-field="track_version_' + key + '"] input[type="checkbox"]'
  ];

  for (const s of tries) {
    el = scope.querySelector(s);
    if (el) return el;
  }
  return null;
}


// общий поиск инпута "синхронизированные лирики" (поддержка всех вариантов разметки)
function findSyncedLyricsInput(card) {
  const sels = [
    'input[name="track_synced_lyrics[]"]',
    'input[name="synced_lyrics"]',
    'input[name="track_lyrics_synced[]"]',
    'input[name="lyrics_synced"]',
    '[data-flag="synced_lyrics"] input[type="checkbox"]',
    '[data-name="synced_lyrics"] input',
    '[data-flag="lyrics_synced"] input[type="checkbox"]',
    '[data-name="lyrics_synced"] input',
    // запасные универсальные селекторы
    'input[name*="synced"][name*="lyrics"]',
    'input[name*="lyrics"][name*="synced"]',
  ];
  for (const s of sels) {
    const el = card.querySelector(s);
    if (el) return el;
  }
  return null;
}

function applySyncedLyricsUI(card, isOn) {
  if (!card) return;
  const box =
    card.querySelector('[data-role="synced-lyrics-cta"]') ||
    card.querySelector('.synced_lyrics_cta'); // страховка на старую разметку
  if (!box) return;

  // состояние контейнера — как в track_list.js
  box.classList.toggle('is-active', !!isOn);

  // синхронизируем hidden-инпут, который читает track_list.js
  let flag = box.querySelector('input[type="hidden"][name="track_synced_lyrics[]"]');
  if (!flag) {
    flag = document.createElement('input');
    flag.type = 'hidden';
    flag.name = 'track_synced_lyrics[]';
    box.appendChild(flag);
  }
  flag.value = isOn ? '1' : '0';

  // кнопка и её стили (точно как делает toggleSyncedLyrics в track_list.js)
  const btn =
    box.querySelector('[data-role="toggle-synced"]') ||
    box.querySelector('button, .btn');
  if (btn) {
    btn.setAttribute('aria-pressed', isOn ? 'true' : 'false');
    btn.classList.toggle('btn-green',  !!isOn);
    btn.classList.toggle('btn-orange', !isOn);
    btn.textContent = isOn ? 'Будет добавлен' : 'Добавить';
  }
}



function setChecked(el, v) {
  if (!el) return;
  const nv = !!v;
  if (el.checked !== nv) {
    el.checked = nv;
    el.dispatchEvent(new Event('input',  { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }
}

    // --- helpers для поиска инпутов ISRC/partner и безопасной установки значения ---
function findIsrcInput(card) {
  return (
    card.querySelector('input[name="track_isrc[]"]') ||
    card.querySelector('input[name="track_isrc"]') ||
    card.querySelector('input[name="isrc"]') ||
    card.querySelector('[data-name="isrc"] input') ||
    card.querySelector('[data-field="isrc"] input') ||
    card.querySelector('#isrc') ||
    card.querySelector('.identification input[name*="isrc"]') ||
    card.querySelector('.identification input[id*="isrc"]')
  );
}

function findPartnerInput(card) {
  return (
    card.querySelector('input[name="track_partner_code[]"]') ||
    card.querySelector('input[name="track_partner_code"]') ||
    card.querySelector('input[name="partner_code"]') ||
    card.querySelector('[data-name="partner_code"] input') ||
    card.querySelector('[data-field="partner_code"] input') ||
    card.querySelector('#partner_code') ||
    card.querySelector('.identification input[name*="partner"]') ||
    card.querySelector('.identification input[id*="partner"]')
  );
}
function toBool(x) {
  if (x === true || x === 1) return true;
  if (x === false || x === 0 || x === null || x === undefined) return false;
  if (typeof x === 'string') {
    const s = x.trim().toLowerCase();
    return s === '1' || s === 'true' || s === 'yes' || s === 'on';
  }
  return false;
}

function setVal(el, val) {
  if (!el) return;
  const v = String(val ?? '');
  const cur = ('value' in el) ? (el.value ?? '') : (el.textContent ?? '');
  if (cur === v) return;
  if ('value' in el) el.value = v; else el.textContent = v;
  // триггерим события, чтобы виджеты/маски подхватили новое значение
  el.dispatchEvent(new Event('input',  { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

    // === helper: подставить персоны/роли в карточку трека ===
function fillRolesForCard(card, item) {
  if (!card || !item) return;

  // Где держать строки ролей (вёрстка может меняться, поэтому берём оба варианта)
  let rolesWrap =
    card.querySelector('.persons_and_roles .roles') ||
    card.querySelector('.roles');

  if (!rolesWrap) {
    // страховка: если контейнера нет — аккуратно создадим его в блоке трека
    const host = card.querySelector('#track_roles_block') ||
                 card.querySelector('.track_block') ||
                 card;
    rolesWrap = document.createElement('div');
    rolesWrap.className = 'roles';
    host.appendChild(rolesWrap);
  }

  // очищаем то, что было
  rolesWrap.innerHTML = '';

  // есть ли что подставлять?
  const rolesArr = Array.isArray(item.roles) ? item.roles : [];
  if (!rolesArr.length) return;

  // берём <template> из карточки, если он там есть; иначе — из документа
  const tplLocal = card.querySelector('#tpl_role_track');
  const tplGlobal = document.getElementById('tpl_role_track');
  const tpl = tplLocal || tplGlobal;

  rolesArr.forEach(r => {
    let row = null;

    if (tpl && tpl.content && tpl.content.firstElementChild) {
      // нормальный путь — клон из шаблона
      row = tpl.content.firstElementChild.cloneNode(true);
    } else {
      // fallback — собираем строку вручную (минимально достаточная разметка)
      row = document.createElement('div');
      row.className = 'role_row';
      row.innerHTML = `
        <div class="inputs_row">
          <div class="input_block">
            <input type="text" name="track_person[]" class="pr-input" placeholder="Имя персоны">
          </div>
          <div class="input_block">
            <select name="track_role[]" class="pr-select">
              <option value="performer">Исполнитель</option>
              <option value="featured">feat.</option>
              <option value="composer">Автор музыки</option>
              <option value="lyricist">Автор слов</option>
              <option value="producer">Producer</option>
              <option value="remixer">Remixer</option>
            </select>
          </div>
        </div>`;
    }

    // заполняем значения
    const personInput = row.querySelector('input[name="track_person[]"]');
    if (personInput) personInput.value = (r.person || r.name || '').trim();

    const roleSelect = row.querySelector('select[name="track_role[]"]');
    if (roleSelect) roleSelect.value = (r.role || r.code || '').trim();

    rolesWrap.appendChild(row);

  });

  // для наглядности в консоли
  // console.log('✔ roles filled:', {trackId: item.id, roles: rolesArr});
}

    // собираем персоны/роли из карточки трека
function collectRolesFromCard(card) {
  const wrap = card.querySelector('.roles');
  if (!wrap) return null;                              // нет контейнера — не трогаем роли

  const rows = wrap.querySelectorAll('.role_row');
  if (!rows || rows.length === 0) return null;         // нет строк — не трогаем роли

  const items = [];
  rows.forEach(row => {
    const person = (row.querySelector('input[name="track_person[]"]')?.value || '').trim();
    const role   = (row.querySelector('select[name="track_role[]"]')?.value   || '').trim();
    if (person && role) items.push({ person, role });
  });

  return items.length ? items : null;                  // пустышку НЕ возвращаем
}


    function collectTracks() {
      try {
        const list = [];
        const scope = document.getElementById('track_list') || document;
        const cards = scope.querySelectorAll('.track_container');

        cards.forEach((card, idx) => {
          if ((card.dataset && card.dataset.template === '1') || card.getAttribute('data-template') === '1') return;


          const idAttr =
            card.getAttribute('data-id') ||
            (card.dataset ? (card.dataset.id || card.dataset.trackId) : '') ||
            '';
          const id = idAttr && !isNaN(parseInt(idAttr, 10)) ? parseInt(idAttr, 10) : null;

          // title
          let title = '';
          const titleEl = findTitleInput(card);
          if (titleEl) {
            if ('value' in titleEl) title = String(titleEl.value || '').trim();
            else title = String(titleEl.textContent || '').trim();
          }
          if (!title) return;

          // version/subtitle
          let version = '';
          const versionEl = findVersionInput(card);
          if (versionEl && 'value' in versionEl) {
            version = String(versionEl.value || '').trim();
          }
          // --- LYRICS (текст трека) ---
const lyricsEl = card.querySelector('textarea[name="track_lyrics[]"]');
const lyrics = lyricsEl ? String(lyricsEl.value || '') : '';

          // ...после блока version/subtitle:
let lang = '';
{
  const langEl = card.querySelector('select[name="track_language[]"]');
  if (langEl) {
    lang = (langEl.selectize ? langEl.selectize.getValue() : langEl.value) || '';
  }
}



          // preview_start (доп. параметры)
let preview_start = null;
{
  const prevEl = card.querySelector('input[name="track_preview_start[]"]');
  if (prevEl) {
    const raw = String(prevEl.value || '').replace(',', '.').trim();
    if (raw !== '') {
      const num = parseFloat(raw);
      if (!Number.isNaN(num) && num >= 0) preview_start = num;
    }
  }
}

// персоны/роли для трека
const roles = collectRolesFromCard(card);
const track_number = getTrackNumberFromCard(card, idx);

// NEW: идентификация
const isrcEl      = card.querySelector('input[name="track_isrc[]"]');
const partnerEl   = card.querySelector('input[name="track_partner_code[]"]');
const isrc        = isrcEl    ? String(isrcEl.value || '').trim()    : '';
const partnerCode = partnerEl ? String(partnerEl.value || '').trim() : '';

// собираем запись; добавляем поля ТОЛЬКО если они не пустые
const rec = { id: id || null, title, version, track_number, language: lang, lyrics };
console.log('[NR-collectTrack]', { id, title, isrc, partnerCode, track_number });
if (preview_start !== null) rec.preview_start = preview_start;
if (isrc)        rec.isrc = isrc;
if (partnerCode) rec.partner_code = partnerCode;
if (Array.isArray(roles) && roles.length) rec.roles = roles;

// === ДОПОЛНИТЕЛЬНЫЕ ПАРАМЕТРЫ (Версия трека) ===
const fxExp   = findVersionFlag(card, 'explicit') || findVersionFlag(card, 'explicit_content');
const fxInstr = findVersionFlag(card, 'instrumental');
const fxDrugs = findVersionFlag(card, 'drugs');


// СИНХРОНИЗИРОВАННЫЕ ЛИРИКИ — checkbox ИЛИ hidden 0/1
// (ключ в payload добавляем только если элемент реально существует)
const fxSyn = findSyncedLyricsInput(card);


// Записываем в payload ВСЕГДА флаги версии, чтобы можно было и ставить, и снимать
// Пишем флаги ТОЛЬКО если элемент реально найден — иначе не затираем БД «ложным нулём»
if (fxExp)   rec.version_explicit     = !!fxExp.checked;
if (fxInstr) rec.version_instrumental = !!fxInstr.checked;
if (fxDrugs) rec.version_drugs        = !!fxDrugs.checked;


// synced_lyrics — только если поле есть (не затираем БД, когда элемента нет)
if (fxSyn) {
  let syn = false;
  if (fxSyn.type === 'checkbox') {
    syn = !!fxSyn.checked;
  } else {
    const v = String(fxSyn.value || '').trim().toLowerCase();
    syn = (v === '1' || v === 'true' || v === 'on' || v === 'yes' || v === 'да');
  }
  rec.synced_lyrics = syn;
}
// Fallback: если инпута нет, берём состояние из оффера (кнопки/баннера)
if (!('synced_lyrics' in rec)) {
  const offer =
    card.querySelector('[data-addon="synced_lyrics"], [data-addon="lyrics_synced"], .synced_lyrics_offer, .synced-lyrics-offer, .synced_lyrics_cta, [data-role="synced-lyrics-cta"]');
  if (offer) {
        rec.synced_lyrics = offer.classList.contains('is-active');
  }
}


list.push(rec);


        });
        return list;
      } catch (e) {
        console.warn('collectTracks failed:', e);
        return [];
      }
    }

    // ===== hydrate from server (подстановка значений при редактировании) =====
    async function hydrateTracksValues(releaseId, attempt = 0) {
      if (!releaseId) return;
      try {
      HYDRATING = true; // старт гидратации
        const r = await fetch(`/releases/${releaseId}/tracks/`, {
          headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
        });
        if (!r.ok) return;
        const data = await r.json();
        if (!data || !data.ok || !Array.isArray(data.items)) return;

        const scope = document.getElementById('track_list') || document;
        // Берём все карточки, кроме шаблона (data-template="1")
const cards = Array.from(scope.querySelectorAll('.track_container'))
  .filter(c => (c.getAttribute('data-template') !== '1' && (!c.dataset || c.dataset.template !== '1')));

        if (cards.length === 0 && attempt < 5) {
          // если рендер карточек ещё не успел — подождём
          HYDRATING = false; // чтобы не «залип» флаг перед повторной попыткой

          return setTimeout(() => hydrateTracksValues(releaseId, attempt + 1), 200);
        }

        data.items.forEach(it => {
          // ищем карточку по data-id, иначе по порядковому номеру
          let card = scope.querySelector(`.track_container[data-id="${it.id}"]`);
          if (!card) {
            card = cards.find((c, idx) => {
              const n = getTrackNumberFromCard(c, idx);
              return parseInt(n, 10) === parseInt(it.track_number, 10);
            }) || null;
          }
          if (!card) return;

          // title
          const tEl = findTitleInput(card);
          if (tEl && 'value' in tEl) tEl.value = it.title || '';
          const headerTitle = card.querySelector('.track_header .track_title');
          if (headerTitle) headerTitle.textContent = it.title || '';

          // version/subtitle
          const vEl = findVersionInput(card);
          if (vEl && 'value' in vEl) vEl.value = it.version || it.subtitle || '';
          // === LYRICS (HYDRATE) ===
const lyrEl = card.querySelector('textarea[name="track_lyrics[]"]');
if (lyrEl) setVal(lyrEl, it.lyrics || '');


          // === LANGUAGE (HYDRATE) ===

try {
  // гарантируем, что селект языка существует и оформлен как в «Релизе»
  const langHost = card.querySelector('.track_language') || card;
  if (window.PSX?.resetTrackLanguageSelect) {
    // второй аргумент — id селекта; можно передать существующий или сгенерировать
    window.PSX.resetTrackLanguageSelect(langHost, 'track_language_select_' + getTrackNumberFromCard(card, 0));
  }

  const langSel = langHost.querySelector('select[name="track_language[]"]');
  const langVal = (it.language || it.lang || '');

  if (langSel) {
    if (langSel.selectize) {
      langSel.selectize.setValue(langVal || '', true);
    } else {
      langSel.value = langVal || '';
      langSel.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }
} catch (e) {
  console.warn('[hydrate] language set failed', e);
}

// --- Доп. параметры: предпрослушка + флаги версии (HYDRATE) ---
{
  // helper: перевод "mm:ss(.ms)" или "hh:mm:ss(.ms)" → секунды (строка)
  const toSeconds = (v) => {
    if (v === undefined || v === null) return '';
    const s = String(v).trim().replace(',', '.');
    if (!s) return '';
    if (s.includes(':')) {
      const parts = s.split(':').map(x => parseFloat(x));
      if (parts.some(n => Number.isNaN(n))) return '';
      let sec = 0;
      if (parts.length === 3) sec = parts[0] * 3600 + parts[1] * 60 + parts[2];
      else if (parts.length === 2) sec = parts[0] * 60 + parts[1];
      else sec = parts[0];
      return (Math.round(sec * 1000) / 1000).toString();
    }
    const n = parseFloat(s);
    return Number.isFinite(n) && n >= 0 ? (Math.round(n * 1000) / 1000).toString() : '';
  };

  // 1) Начало предпрослушивания (секунды, всегда секундами)
  const prevEl = card.querySelector('input[name="track_preview_start[]"]');
  if (prevEl) {
    const raw = (it.preview_start ?? it.previewStart);
    setVal(prevEl, toSeconds(raw)); // setVal ещё и генерит input/change
  }

  // 2) Флаги версии трека
  // ищем чекбокс explicit по всем вариантам имени
const exEl =
  findVersionFlag(card, 'explicit') ||
  findVersionFlag(card, 'explicit_content');

  if (exEl) {
    const v = !!(it.version_explicit ?? it.explicit ?? false);
    if (exEl.checked !== v) {
      exEl.checked = v;
      exEl.dispatchEvent(new Event('input',  { bubbles: true }));
      exEl.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  const drEl = card.querySelector('input[name="track_version_drugs[]"]');
  if (drEl) {
    const v = !!(it.version_drugs ?? it.drugs ?? false);
    if (drEl.checked !== v) {
      drEl.checked = v;
      drEl.dispatchEvent(new Event('input',  { bubbles: true }));
      drEl.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  const inEl = card.querySelector('input[name="track_version_instrumental[]"]');
  if (inEl) {
    const v = !!(it.version_instrumental ?? it.instrumental ?? false);
    if (inEl.checked !== v) {
      inEl.checked = v;
      inEl.dispatchEvent(new Event('input',  { bubbles: true }));
      inEl.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

    // 3) Синхронизированные лирикс (checkbox или hidden 0/1)
const synEl   = findSyncedLyricsInput(card);
const rawSyn  = (it.synced_lyrics ?? it.lyrics_synced ?? it.lyricsSynced);
const isSynced = (rawSyn === true || rawSyn === 1 || rawSyn === '1');

// если есть checkbox/hidden — выставим напрямую
if (synEl) {
  if (synEl.type === 'checkbox') {
    if (synEl.checked !== isSynced) {
      synEl.checked = isSynced;
      synEl.dispatchEvent(new Event('input',  { bubbles:true }));
      synEl.dispatchEvent(new Event('change', { bubbles:true }));
    }
  } else {
    synEl.value = isSynced ? '1' : '0';
    synEl.dispatchEvent(new Event('input',  { bubbles:true }));
    synEl.dispatchEvent(new Event('change', { bubbles:true }));
  }
}

// всегда синхронизируем «оффер» по правилам track_list.js (is-active + hidden track_synced_lyrics[])
applySyncedLyricsUI(card, isSynced);



}




// идентификация: ISRC и код партнёра
const isrcInput = findIsrcInput(card);
setVal(isrcInput, it.isrc || '');

const partnerInput = findPartnerInput(card);
setVal(partnerInput, it.partner_code || it.partnerCode || '');

          // === DEBUG: что видим в DOM для ролей ===
console.log('[NR-HYDRATE]',
  { id: it.id, num: it.track_number, title: it.title,
    rolesFromAPI: Array.isArray(it.roles) ? it.roles.length : 'null',
    hasRolesWrap: !!card.querySelector('.roles'),
    hasAltWrap: !!card.querySelector('.track_people'),
    hasTemplate: !!document.getElementById('tpl_role_track')
  }
);

          // ⬇️ Персоны и роли — восстановить из БД в DOM
fillRolesForCard(card, it);


        });
} catch (_) {
} finally {
  HYDRATING = false; // завершили гидратацию в любом случае
}
} // <— закрывает ВЕСЬ hydrateTracksValues



    async function refreshClientTrackIdsIfPossible(releaseId) {
  if (!releaseId) return;
  try {
    const r = await fetch(`/releases/${releaseId}/tracks/`, {
      headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    });
    if (!r.ok) return;
    const data = await r.json();
    if (!data || !data.ok || !Array.isArray(data.items)) return;

    const items = data.items;
    const scope = document.getElementById('track_list') || document;
    const cards = Array.from(scope.querySelectorAll('.track_container'));

    cards.forEach((card, idx) => {
      const localNum = getTrackNumberFromCard(card, idx);
      let match = items.find(it => parseInt(it.track_number, 10) === parseInt(localNum, 10));
      if (!match) match = items[idx];
      if (match && match.id != null) {
        card.setAttribute('data-id', String(match.id));
      }
    });
  } catch (_) {
    // no-op
  }
} // ← это закрывает функцию



    // ===== autosave =====
    function scheduleSend(delay) {
  if (HYDRATING) return;
  clearTimeout(timer);
  timer = setTimeout(send, delay);
}


    function pageHasFilesSelected() {
      const files = Array.from(form.querySelectorAll('input[type="file"]'));
      return files.some(inp => inp.files && inp.files.length > 0);
    }
function isTrackListVisible() {
  const el = document.getElementById('track_list');
  if (!el) return false;
  const cs = window.getComputedStyle(el);
  if (cs.display === 'none' || cs.visibility === 'hidden') return false;
  // если элемент вне потока и не fixed — тоже считаем скрытым
  if (el.offsetParent === null && cs.position !== 'fixed') return false;
  return true;
}

    function send() {
  if (HYDRATING) return;
  if (inflight) { scheduleSend(200); return; }

      // синхронизируем скрытые поля
syncHidden();

// решаем, надо ли вообще отправлять блок tracks
const shouldSendTracks = isTrackListVisible() || TRACKS_DIRTY;
let tracks = null;
if (shouldSendTracks) {
  tracks = collectTracks();
}

const hasFiles = pageHasFilesSelected();
if (!NR_TOUCHED && (!tracks || tracks.length === 0) && !hasFiles) {
  return;
}

inflight = true;
setHidden('_ua', NR_TOUCHED ? '1' : '');

const fd = new FormData(form);

// отправляем треки только если это уместно
if (shouldSendTracks && Array.isArray(tracks) && tracks.length > 0) {
  fd.append('tracks', JSON.stringify({ tracks }));
  console.log('[NR-send tracks]', JSON.stringify({ tracks }));
} else {
  try { fd.delete('tracks'); } catch(_) {}
}



      fetch(location.pathname, {
        method: 'POST',
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
          'X-CSRFToken': csrftoken,
          'Accept': 'application/json'
        },
        body: fd
      })
        .then(async (r) => {
          const ct = r.headers.get('content-type') || '';
          if (r.ok && ct.includes('application/json')) return r.json();
          try { console.warn('autosave non-json response', await r.text()); } catch {}
          throw new Error('Autosave failed: non-JSON or HTTP error');
        })
        .then(async (data) => {
          if (data && (data.ok === true || data.status === 'ok')) {
            const rid = data.release_id || data.id;
            await refreshClientTrackIdsIfPossible(rid);
            // ✳️ после того как появились data-id — повторно подставим значения
            await hydrateTracksValues(rid, 0);
          }
        })
        .catch(() => { /* тихо */ })
        .finally(() => { inflight = false; });
    }

    // события формы → помечаем «коснулись» и шлём с дебаунсом
    ['input', 'change', 'paste', 'drop', 'keyup', 'blur'].forEach(ev => {
      form.addEventListener(ev, () => { markTouched(); scheduleSend(ev === 'change' ? 200 : 600); }, true);
    });

    // события трек-листа (не всегда всплывают до формы)
    const tl = document.getElementById('track_list');
    if (tl) {
  ['input','change','keyup','mouseup','drop'].forEach((ev) => {
    tl.addEventListener(ev, () => { TRACKS_DIRTY = true; markTouched(); scheduleSend(350); }, true);
  });
  tl.addEventListener('sortupdate', () => { TRACKS_DIRTY = true; markTouched(); scheduleSend(150); }, true);
  tl.addEventListener('dragend',    () => { TRACKS_DIRTY = true; markTouched(); scheduleSend(150); }, true);
}


    // ✳️ стартовая «гидратация» при редактировании
    const __rid = getReleaseId();
if (__rid) {
  // первый запуск — чуть позже, чтобы успел отрендериться трек-лист
  setTimeout(() => hydrateTracksValues(__rid, 0), 300);

  // повторная гидратация при открытии вкладки «Трек-лист»
  document.addEventListener('click', (e) => {
    const el = e.target && e.target.closest &&
      e.target.closest('[data-tab="track_list"], a[href="#track_list"], [data-target="#track_list"]');
    if (el) setTimeout(() => hydrateTracksValues(__rid, 0), 50);
  });

  // гидратация при появлении/перерисовке карточек треков
  const target = document.getElementById('track_list');
  if (target && window.MutationObserver) {
    let last = 0;
    const obs = new MutationObserver(() => {
      const now = Date.now();
      if (now - last > 300) { // простая дебаунс-защита
        last = now;
        hydrateTracksValues(__rid, 0);
      }
    });
    obs.observe(target, { childList: true, subtree: true });
  }
}

// ====== AUTOSAVE: язык трека ======
document.addEventListener('change', function (e) {
  const sel = e.target && e.target.closest && e.target.closest('#track_list select[name="track_language[]"]');
  if (!sel) return;

  const language = (sel.selectize ? sel.selectize.getValue() : sel.value) || '';
  const card = sel.closest('.track_container');
  const trackId = card && card.getAttribute('data-id');
  if (!trackId) { console.warn('[autosave] нет data-id у карточки трека'); return; }

  try { if (typeof markTouched === 'function') markTouched(); } catch (_) {}

  const csrf = (typeof getCookie === 'function' ? getCookie('csrftoken') :
               (document.cookie.match(/(?:^|;)\s*csrftoken=([^;]+)/) || [,''])[1]) || '';

  fetch(`/tracks/${trackId}/language/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-CSRFToken': csrf
    },
    body: JSON.stringify({ language })
  })
    .then(r => r.ok ? r.json() : null)
    .then(() => console.debug('[autosave] track.language saved', { trackId, language }))
    .catch(err => console.warn('[autosave] track.language failed', err));
});

    // НЕТ стартового пинга!
  });
})();
