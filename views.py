# ===== stdlib =====

import csv
import json
import os
import re
import string
from datetime import date
from io import BytesIO
import math
import uuid
import random

# ===== third-party =====
import requests
from PIL import Image
from app.forms.forms import AddReleaseForm, AddArtistForm, UploadReportFileForm, AddStaffMemberForm
from app.forms.promotion_forms import SearchPlaylistsForm, PlaylistsFilterForm, AddPlaylistForm
from app.forms.user_forms import (
    UserLoginForm, AuthTelegramForm, UserRegistrationForm,
    UserEditForm, PasswordEditForm, AvatarEditForm, SetPasswordForm
)
from app.static.other import different_data
from app.models import ReleasePerson
from celery.result import AsyncResult
# ===== django =====
from django import forms
from django.conf import settings
from django.contrib import auth
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User
from django.core import serializers
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q, Sum, Value, IntegerField, F, Case, When, OuterRef, Subquery
from django.db.models.functions import Coalesce
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse, resolve
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from dotenv import load_dotenv
from openpyxl import Workbook
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle, TA_CENTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from django.contrib.auth.decorators import login_required
from django.core.files.storage import default_storage
from django.db import transaction

# ===== app =====
from .models import (
    Profile, Report, Artist, Release, ReleaseStatus, Playlists,
    GlobalPlaylist, PersonalPlaylist, TikTokUser, TikTokScanningUser, Track,
    ReleasePerson, TrackPerson)

from .tasks import add_global_playlists

load_dotenv()
# === Platform aliases (slug -> tokens found in DB column) ===
PLATFORM_ALIASES = {
    'spotify': ['spotify'],
    'mts':     ['мтс', 'mts', 'мтс музыка'],
    'deezer':  ['deezer'],

    # ключевые проблемные:
    'vk':      ['вконтакте', 'vk', 'вк', 'ВКонтакте'],
    'yandex':  ['Яндекс.Музыка', 'яндекс', 'yandex'],
    'zvuk':    ['СберЗвук', 'звук', 'zvuk', 'sber'],
    'ok':      ['Одноклассники', 'ok', 'ok.ru'],
}


# ---- helper: кто менеджер ----
def is_manager(user):
    return user.is_staff or user.is_superuser
# Поиск по релизам (используется в your_music)
def _apply_release_query_filter(qs, q: str):
    q = (q or "").strip()
    if not q:
        return qs
    return qs.filter(
        Q(album_title__icontains=q) |
        Q(album_UPC__icontains=q) |
        Q(genre__icontains=q) |
        Q(subgenre__icontains=q)
    )



AUTH_CODE_TTL_MINUTES = 1  # время жизни auth-кода в минутах

# ================== regexы (один раз) ==================
ISRC_RE = re.compile(r'^[A-Z]{2}[A-Z0-9]{3}\d{7}$', re.I)  # RUABC1234567
UPC_RE = re.compile(r'^\d{8,14}$')  # 8–14 digits


# =======================================================


# ================== helpers (один раз) =================
def _load_json(request, key=None):
    """
    Пытаемся распарсить JSON из тела запроса независимо от Content-Type.
    Если тела нет — пробуем взять JSON-строку из form-data по ключу `key`.
    """
    # 1) сначала пробуем тело запроса
    try:
        raw = request.body.decode('utf-8') if request.body else ''
    except Exception:
        raw = ''
    if raw and raw.strip():
        try:
            return json.loads(raw)
        except Exception:
            pass  # тело есть, но не JSON — идём дальше

    # 2) если в form-data лежит JSON-строка (например, поле tracks)
    if key:
        raw = request.POST.get(key) or ''
        if raw and raw.strip():
            try:
                return json.loads(raw)
            except Exception:
                pass

    return {}


def _sync_tracks(release, rows):
    """
    Полная синхронизация трек-листа релиза:
    - rows: [{id?, title, version?, track_number, roles?: [{person, role}], ...}, ...]
    - удаляем лишние треки, обновляем существующие, создаём новые
    - для каждого трека полностью пересобираем TrackPerson
    """
    # 1) Приводим вход к списку
    if isinstance(rows, dict) and 'tracks' in rows:
        rows = rows['tracks']
    if not isinstance(rows, list):
        return

    # --- helpers для флагов/алиасов ---
    def _to_bool(x):
        if isinstance(x, bool): return x
        if isinstance(x, (int, float)): return x != 0
        s = str(x).strip().lower()
        return s in ('1','true','t','yes','y','on','да','истина')

    def _set_bool_field(obj, prefer, aliases, val, changed_list):
        """
        Ставит булево поле на треке, учитывая альтернативные имена.
        Например: prefer='version_explicit', aliases=['explicit'].
        Обновляет только если ключ в payload присутствовал (val is not None).
        """
        if val is None:
            return
        for name in [prefer] + list(aliases):
            if hasattr(obj, name):
                cur = bool(getattr(obj, name))
                nv  = bool(_to_bool(val))
                if cur != nv:
                    setattr(obj, name, nv)
                    changed_list.append(name)
                return  # как только нашли существующее поле — останавливаемся

    # --- текстовое поле: если ключ есть в POST, то обновляем; '' -> None (стираем)
    def _set_text_field(obj, field_name, raw_value, changed_fields):
        # если ключа вовсе нет — ничего не делаем (значит фронт не пытался менять)
        if raw_value is None:
            return
        new_val = (raw_value or '').strip() or None  # '' -> None
        old_val = getattr(obj, field_name, None)
        if old_val != new_val:
            setattr(obj, field_name, new_val)
            if isinstance(changed_fields, set):
                changed_fields.add(field_name)

    def _first_existing_field(model_cls, *names):
        """Какое имя поля реально есть у модели (первое найденное)."""
        for n in names:
            if hasattr(model_cls, n):
                return n
        return None


    cleaned = []
    for i, row in enumerate(rows, start=1):
        title   = (row.get('title') or '').strip()
        version = (row.get('version') or row.get('subtitle') or '').strip()
        # --- Язык трека из payload ---
        lang_present = ('language' in row) or ('track_language' in row) or ('language_code' in row)
        lang_val = (row.get('language') or row.get('track_language') or row.get('language_code') or '').strip()

        if not title:
            continue

        # номер трека
        try:
            tn = int(row.get('track_number') or i)
            if tn < 1:
                tn = i
        except Exception:
            tn = i

        # id трека (если редактирование)
        tid = row.get('id')
        try:
            tid = int(tid) if (tid is not None and str(tid).strip() != '') else None
        except Exception:
            tid = None

        # РОЛИ из payload (запоминаем — прислали ли ключ вообще)
        has_roles_key = ('roles' in row)
        roles = []
        for rr in (row.get('roles') or []):
            person = (rr.get('person') or '').strip()
            role = (rr.get('role') or '').strip().lower()
            if role in ('artist',): role = 'performer'
            if role in ('feat', 'featuring'): role = 'featured'
            if person and role:
                roles.append({'person': person, 'role': role})

        # --- Идентификация трека ---
        # важный момент: изменяем ИДЕНТИФИКАТОРЫ ТОЛЬКО если ключ реально пришёл,
        # иначе считаем «не трогать».
        isrc_present = ('isrc' in row)
        partner_present = ('partner_code' in row) or ('partnerCode' in row)

        # если ISRC прислали, нормализуем и проверим; если формат невалидный — НЕ включаем ключ,
        # чтобы не затирать БД мусором
        isrc_val = None
        if isrc_present:
            tmp = (row.get('isrc') or '').strip().upper()
            if tmp:
                if ISRC_RE.match(tmp):
                    isrc_val = tmp
                else:
                    # прислали невалидный — трактуем как «не менять»
                    isrc_present = False

        partner_val = None
        if partner_present:
            partner_val = (row.get('partner_code') or row.get('partnerCode') or '').strip()

        # --- Доп. параметры ---
        # 1) preview_start (строка из UI -> нормализуем в секунды; ключ присутствия фиксируем)
        preview_present = ('preview_start' in row)
        preview_secs = None

        def _parse_preview(v):
            if v is None:
                return None
            txt = str(v).strip()
            if not txt:
                return None
            # варианты: "0:37.500", "1:02.25", "37.5"
            try:
                if ':' in txt:
                    mm, ss = txt.split(':', 1)
                    mm = int(mm.strip() or 0)
                    ss = float(ss.replace(',', '.').strip() or 0)
                    return round(mm * 60 + ss, 3)
                else:
                    return round(float(txt.replace(',', '.')), 3)
            except Exception:
                return None

        if preview_present:
            preview_secs = _parse_preview(row.get('preview_start'))

        # 2) флаги версии (чекбоксы)
        ve_present = ('version_explicit' in row)
        vd_present = ('version_drugs' in row)
        vi_present = ('version_instrumental' in row)

        def _to_bool(x):
            # поддержим true/false, "1"/"0", 1/0, "on"/"off"
            s = str(x).strip().lower()
            return s in ('1', 'true', 'yes', 'y', 'on', 'да', 'истина')

        ve_val = _to_bool(row.get('version_explicit')) if ve_present else None
        vd_val = _to_bool(row.get('version_drugs')) if vd_present else None
        vi_val = _to_bool(row.get('version_instrumental')) if vi_present else None

        # synced_lyrics
        sl_present = ('synced_lyrics' in row)
        sl_val = _to_bool(row.get('synced_lyrics')) if sl_present else None

        # --- ПЛОСКИЙ ТЕКСТ ПЕСНИ (lyrics) ---
        lyrics_present = ('lyrics' in row)
        lyrics_text = row.get('lyrics')
        # аккуратно приводим к строке, но НЕ обрезаем переносы/пробелы внутри
        if lyrics_text is None:
            lyrics_text = ''
        elif not isinstance(lyrics_text, str):
            lyrics_text = str(lyrics_text)

        # собираем запись для дальнейшей синхронизации
        rec = {
            'id': tid,
            'title': title,
            'track_number': tn,
        }
        if lyrics_present:
            rec['lyrics'] = lyrics_text

        if version:
            rec['version'] = version
        if lang_present:
            rec['language'] = (lang_val or None)

        if has_roles_key:
            rec['roles'] = roles
        if isrc_present:
            rec['isrc'] = isrc_val  # может быть строкой или None, если надо очистить (позже решим)
        if partner_present:
            rec['partner_code'] = partner_val

        # доп. параметры — включаем ключи только если они реально присутствовали во входе
        if preview_present:
            rec['preview_start'] = preview_secs  # число секунд или None (очистить)
        if ve_present:
            rec['version_explicit'] = bool(ve_val)
        if vd_present:
            rec['version_drugs'] = bool(vd_val)
        if vi_present:
            rec['version_instrumental'] = bool(vi_val)
        if sl_present:
            rec['synced_lyrics'] = bool(sl_val)

        cleaned.append(rec)

    # 2) Удаляем треки, которых нет во входе
    keep_ids = {x['id'] for x in cleaned if x['id']}
    with transaction.atomic():
        if keep_ids:
            release.tracks.exclude(id__in=keep_ids).delete()
        else:
            release.tracks.all().delete()

        # 3) Создаём/обновляем + СИНХРОНИЗИРУЕМ РОЛИ
        for r in cleaned:
            if r['id']:
                tr = release.tracks.filter(id=r['id']).first()
                if not tr:
                    tr = Track.objects.create(
                        release=release,
                        title=r['title'],
                        version=r.get('version') or '',
                        track_number=r['track_number'],
                    )
                else:
                    changed = []

                    # title
                    if tr.title != r['title']:
                        tr.title = r['title']
                        changed.append('title')

                    # version
                    if tr.version != (r.get('version') or ''):
                        tr.version = (r.get('version') or '')
                        changed.append('version')

                    # track_number
                    if tr.track_number != r['track_number']:
                        tr.track_number = r['track_number']
                        changed.append('track_number')

                    # --- Идентификация: обновляем ТОЛЬКО если ключ присутствует в r ---

                    # ISRC
                    if 'isrc' in r:
                        new_isrc = (r.get('isrc') or '').strip().upper() or None
                        if new_isrc and not ISRC_RE.match(new_isrc):
                            new_isrc = None
                        if (tr.isrc or None) != new_isrc:
                            tr.isrc = new_isrc
                            changed.append('isrc')

                    # Код партнёра
                    if hasattr(tr, 'partner_code') and ('partner_code' in r):
                        new_pcode = (r.get('partner_code') or '').strip() or None
                        if (getattr(tr, 'partner_code', None) or None) != new_pcode:
                            setattr(tr, 'partner_code', new_pcode)
                            changed.append('partner_code')

                    # preview_start (как было)
                    if hasattr(tr, 'preview_start') and ('preview_start' in r):
                        new_ps = r.get('preview_start')
                        try:
                            new_ps = float(new_ps) if new_ps not in ('', None) else None
                        except Exception:
                            new_ps = None
                        if (getattr(tr, 'preview_start', None) or None) != new_ps:
                            setattr(tr, 'preview_start', new_ps)
                            changed.append('preview_start')

                    # language (track-level)
                    lang_field = _first_existing_field(Track, 'language', 'track_language', 'language_code')
                    if lang_field and ('language' in r):
                        new_lang = (r.get('language') or '').strip() or None
                        cur_lang = getattr(tr, lang_field, None) or None
                        if cur_lang != new_lang:
                            setattr(tr, lang_field, new_lang)
                            changed.append(lang_field)
                    # lyrics (plain text)
                    if hasattr(tr, 'lyrics') and ('lyrics' in r):
                        new_lyrics = r.get('lyrics') or ''
                        if (tr.lyrics or '') != new_lyrics:
                            tr.lyrics = new_lyrics
                            changed.append('lyrics')

                    # флаги версии с поддержкой алиасов: version_* или explicit/instrumental/drugs
                    _set_bool_field(tr, 'version_explicit', ['explicit', 'explicit_content'],
                                    r.get('version_explicit') if 'version_explicit' in r else None, changed)
                    _set_bool_field(tr, 'version_instrumental', ['instrumental'],
                                    r.get('version_instrumental') if 'version_instrumental' in r else None, changed)
                    _set_bool_field(tr, 'version_drugs', ['drugs'],
                                    r.get('version_drugs') if 'version_drugs' in r else None, changed)
                    _set_bool_field(tr, 'synced_lyrics', ['lyrics_synced'],
                                    r.get('synced_lyrics') if 'synced_lyrics' in r else None,
                                    changed)

                    if changed:
                        tr.save(update_fields=list(set(changed)))

                # Роли синкаем ТОЛЬКО если ключ есть во входе (не трогаем иначе)
                if 'roles' in r:
                    _sync_track_people(tr, r.get('roles') or [])

            else:
                # создаём новый трек; поля идентификации ставим только если пришли
                kwargs = dict(
                    release=release,
                    title=r['title'],
                    version=r.get('version') or '',
                    track_number=r['track_number'],
                )
                if 'isrc' in r:
                    new_isrc = (r.get('isrc') or '').strip().upper() or None
                    if new_isrc and not ISRC_RE.match(new_isrc):
                        new_isrc = None
                    kwargs['isrc'] = new_isrc
                if 'partner_code' in r:
                    kwargs['partner_code'] = (r.get('partner_code') or '').strip() or None

                # доп. параметры на создание — только если поле реально есть в модели
                if hasattr(Track, 'preview_start') and ('preview_start' in r):
                    try:
                        ps = float(r.get('preview_start')) if r.get('preview_start') not in ('', None) else None
                    except Exception:
                        ps = None
                    kwargs['preview_start'] = ps
                # preview_start
                if hasattr(Track, 'preview_start') and ('preview_start' in r):
                    try:
                        ps = float(r.get('preview_start')) if r.get('preview_start') not in ('', None) else None
                    except Exception:
                        ps = None
                    kwargs['preview_start'] = ps

                # язык трека
                lang_field = _first_existing_field(Track, 'language', 'track_language', 'language_code')
                if lang_field and ('language' in r):
                    kwargs[lang_field] = (r.get('language') or '').strip() or None
                # текст песни
                if hasattr(Track, 'lyrics') and ('lyrics' in r):
                    kwargs['lyrics'] = r.get('lyrics') or ''

                # флаги версии с алиасами
                f = _first_existing_field(Track, 'version_explicit', 'explicit')
                if f and ('version_explicit' in r):
                    kwargs[f] = bool(r.get('version_explicit'))

                f = _first_existing_field(Track, 'version_drugs', 'drugs')
                if f and ('version_drugs' in r):
                    kwargs[f] = bool(r.get('version_drugs'))

                f = _first_existing_field(Track, 'version_instrumental', 'instrumental')
                if f and ('version_instrumental' in r):
                    kwargs[f] = bool(r.get('version_instrumental'))

                # synced_lyrics
                f = _first_existing_field(Track, 'synced_lyrics', 'lyrics_synced')
                if f and ('synced_lyrics' in r):
                    kwargs[f] = bool(r.get('synced_lyrics'))

                tr = Track.objects.create(**kwargs)

                if 'roles' in r:
                    _sync_track_people(tr, r.get('roles') or [])



# =======================================================


# ================== общие вьюхи ========================
def health(request):
    return JsonResponse({'status': 'ok'})


def login(request):
    current_route = resolve(request.path_info)
    if current_route.url_name == "set_password":
        user = request.user
        if not user.has_usable_password():
            should_set_password = True
        else:
            return HttpResponseRedirect(reverse('home'))
    elif current_route.url_name == "login":
        should_set_password = False

    if request.method == 'POST':
        form_name = request.POST.get('form_name')
        if form_name == 'login':
            login_form = UserLoginForm(request, data=request.POST)
            auth_telegram_form = AuthTelegramForm()
            set_password_form = SetPasswordForm(None)
            if login_form.is_valid():
                username = request.POST['username']
                password = request.POST['password']
                user = auth.authenticate(username=username, password=password)
                if user:
                    auth.login(request, user)
                    return HttpResponseRedirect(reverse('home'))
        elif form_name == 'auth_telegram':
            auth_telegram_form = AuthTelegramForm(request.POST)
            login_form = UserLoginForm()
            set_password_form = SetPasswordForm(None)
            if auth_telegram_form.is_valid():
                try:
                    auth_code = request.POST['auth_telegram_code']
                    profile = Profile.objects.get(auth_code=auth_code)
                    if profile.auth_until_datetime < timezone.now() - timedelta(minutes=AUTH_CODE_TTL_MINUTES):
                        auth_telegram_form.add_error(
                            'auth_telegram_code',
                            forms.ValidationError(
                                'Код больше не действителен. Нажмите "Отправить код в Telegram" или в Telegram-боте воспользуйтесь командой /auth')
                        )
                    else:
                        auth.login(request, profile.user, backend='django.contrib.auth.backends.ModelBackend')
                        if len(auth_code) == 6:
                            return HttpResponseRedirect(reverse('home'))
                        elif len(auth_code) == 8:
                            should_set_password = True
                except Profile.DoesNotExist:
                    auth_telegram_form.add_error(
                        'auth_telegram_code',
                        forms.ValidationError("Неверный код. Повторите попытку.")
                    )
        elif form_name == 'set_password':
            set_password_form = SetPasswordForm(user=request.user, data=request.POST)
            login_form = UserLoginForm()
            auth_telegram_form = AuthTelegramForm()
            if set_password_form.is_valid():
                user = set_password_form.save()
                auth.update_session_auth_hash(request, user)
                return HttpResponseRedirect(reverse('home'))
            should_set_password = True
    else:
        login_form = UserLoginForm()
        auth_telegram_form = AuthTelegramForm()
        set_password_form = SetPasswordForm(None)

    return render(request, 'login.html', {
        'login_form': login_form,
        'auth_telegram_form': auth_telegram_form,
        'set_password_form': set_password_form,
        'should_set_password': should_set_password,
    })


def registration(request):
    if request.method == 'POST':
        form = UserRegistrationForm(data=request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse('login'))
    else:
        form = UserRegistrationForm()
    return render(request, 'registration.html', {'registration_form': form})


def logout(request):
    auth.logout(request)
    return HttpResponseRedirect(reverse('login'))


def home(request):
    return render(request, "index.html", {
        "pattern": "home",
    })


# =======================================================
# =================================================================================
# ====== ХЕЛПЕРЫ ДЛЯ АНАЛИТИКИ (ВСТАВЛЕНЫ ДЛЯ ИСПРАВЛЕНИЯ ПАРСИНГА ДАТ) ======
# =================================================================================
def _norm_quarter_label(s: str) -> str:
    """
    Приводит пользовательский ввод к человеку понятному виду.
    Понимает 'Q2 2025', '2 квартал 2025', 'второй квартал 2025' -> '2 квартал 2025'.
    Если распарсить не удалось — вернёт исходную строку (так тоже можно).
    """
    t = (s or '').strip()
    if not t:
        return t
    import re
    m = re.match(r'(?i)q([1-4])\s*[\- ]?\s*(\d{4})', t)
    if m:
        return f"{int(m.group(1))} квартал {m.group(2)}"
    m = re.match(r'(?i)([1-4])\s*квартал\W*(\d{4})', t)
    if m:
        return f"{int(m.group(1))} квартал {m.group(2)}"
    # Примитивная поддержка «первый/второй/третий/четвёртый квартал 2025»
    t2q = {'перв':1,'втор':2,'трет':3,'четв':4}
    m = re.match(r'(?i)(перв|втор|трет|четв)\w*\s+квартал\W*(\d{4})', t)
    if m and m.group(1).lower() in t2q:
        return f"{t2q[m.group(1).lower()]} квартал {m.group(2)}"
    return t

# --- 1. Парсинг периода для отображения (analytics_summary) ---
RU_MONTHS = {
    'январ': 1, 'феврал': 2, 'март': 3, 'апрел': 4, 'ма': 5, 'июн': 6,
    'июл': 7, 'август': 8, 'сентябр': 9, 'октябр': 10, 'ноябр': 11, 'декабр': 12,
}


def _end_of_month(y: int, m: int) -> date:
    if m == 12:
        return date(y, 12, 31)
    nxt = date(y + (m // 12), (m % 12) + 1, 1)
    return nxt - timedelta(days=1)


def _parse_period(s: str) -> date | None:
    """
    Возвращает КОНЕЦ периода (date) или None.
    Теперь поддерживает: DD-MM-YYYY, DD.MM.YYYY, YYYY-MM-DD.
    """
    if not s:
        return None
    txt = str(s).strip()

    # --- 1. Двуточечный диапазон дат ---
    m = re.search(r'(\d{1,2}[\.\-]\d{1,2}[\.\-]\d{4}).+?(\d{1,2}[\.\-]\d{1,2}[\.\-]\d{4})', txt)
    if m:
        for fmt in ('%d.%m.%Y', '%d-%m-%Y'):
            try:
                # Заменяем все разделители на дефисы для унификации
                return datetime.strptime(m.group(2).replace('.', '-'), fmt).date()
            except Exception:
                pass

    # --- 2. Месяц/год или Название месяца ---
    m_dm = re.match(r'^\s*(\d{1,2})\.(\d{4})\s*$', txt)
    m_iso = re.match(r'^\s*(\d{4})-(\d{1,2})\s*$', txt)

    if m_dm or m_iso:
        try:
            if m_iso:
                yy, mm = int(m_iso.group(1)), int(m_iso.group(2))
            else:
                mm, yy = int(m_dm.group(1)), int(m_dm.group(2))
            if 1 <= mm <= 12:
                return _end_of_month(yy, mm)
        except Exception:
            pass

    m_mon = re.match(r'^\s*([А-Яа-яA-Za-zёЁ]+)\s+(\d{4})\s*$', txt)
    if m_mon:
        mon, yy = m_mon.group(1).lower(), int(m_mon.group(2))
        for key, val in RU_MONTHS.items():
            if mon.startswith(key):
                return _end_of_month(yy, val)

    # --- 3. Одиночная дата (ВКЛЮЧАЯ DD-MM-YYYY) ---
    for fmt in ('%Y-%m-%d', '%d.%m.%Y', '%d-%m-%Y'):
        try:
            return datetime.strptime(txt.replace('.', '-'), fmt).date()
        except Exception:
            pass

    return None


# --- 2. Парсинг даты при импорте (normalize_date_like) ---

def normalize_date_like(s):
    """
    КРИТИЧЕСКИ ВАЖНАЯ ФУНКЦИЯ ДЛЯ ИМПОРТА!
    Пытается привести дату из Excel (серийный номер или строка) к формату DD.MM.YYYY.
    """
    if pd.isna(s) or s is None:
        return None
    s = str(s).strip()

    # 1. Попытка парсинга как дата со всеми разделителями
    try:
        s_dot = s.replace('-', '.')
        dt = pd.to_datetime(s_dot, dayfirst=True, errors='coerce')
        if not pd.isna(dt):
            # Сохраняем в базу в формате с точками
            return dt.strftime('%d.%m.%Y')
    except Exception:
        pass

    # 2. Попытка парсинга как серийный номер Excel (если это чистое число)
    try:
        if re.match(r'^\d+(\.\d+)?$', s):
            num = float(s)
            dt = pd.to_datetime('1899-12-30') + pd.to_timedelta(num, unit='D')
            if pd.Timestamp('1970-01-01') < dt < pd.Timestamp('2050-01-01'):
                return dt.strftime('%d.%m.%Y')
    except Exception:
        pass

    return s or None


# =======================================================

# ================== Tracks API (единый комплект) =======
@login_required(login_url='login')
def release_tracks(request, pk: int):
    """JSON-список треков релиза (для владельца и для staff)."""
    release = get_object_or_404(Release, pk=pk)
    if not (request.user.is_staff or request.user == release.user):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    items = []
    for t in release.tracks.order_by('track_number', 'id'):
        # язык трека (ищем первое существующее поле)
        lang = ""
        for _f in ("language", "track_language", "language_code"):
            if hasattr(t, _f):
                lang = getattr(t, _f) or ""
                break

        row = {
            "id": t.id,
            "title": t.title or "",
            "version": t.version or "",
            "subtitle": t.version or "",
            "track_number": t.track_number,
            "isrc": t.isrc or "",
            "partner_code": getattr(t, "partner_code", None) or "",
            "language": getattr(t, "language", "") or "",
            "audio_url": t.audio_file.url if t.audio_file else "",
            "roles": [{"person": p.name, "role": p.role} for p in t.people.order_by('id')],
            "lyrics": getattr(t, "lyrics", "") or "",
            # ▼--- ДОБАВЬ ЭТО ---▼

            "version_explicit": bool(
                getattr(t, "version_explicit", getattr(t, "explicit", False))
            ),
            "version_instrumental": bool(
                getattr(t, "version_instrumental", getattr(t, "instrumental", False))
            ),
            "version_drugs": bool(
                getattr(t, "version_drugs", getattr(t, "drugs", False))
            ),
            "synced_lyrics": bool(getattr(t, "synced_lyrics", getattr(t, "lyrics_synced", False))),
        }

        # Доп. параметры → безопасно добавляем, только если поля есть в модели
        if hasattr(t, "preview_start"):
            # В БД часто храним число секунд, а на фронт удобнее строкой. Отдадим строку «m:ss.mmm»
            val = getattr(t, "preview_start")  # может быть float/Decimal/None/str
            if val is None or val == "":
                row["preview_start"] = ""
            else:
                try:
                    sec = float(val)
                    m = int(sec // 60)
                    s = sec - m * 60
                    row["preview_start"] = f"{m}:{s:06.3f}".replace(".", ".")  # 0:37.500
                except Exception:
                    row["preview_start"] = str(val)
        if hasattr(t, "version_explicit"):
            row["version_explicit"] = bool(getattr(t, "version_explicit"))
        if hasattr(t, "version_drugs"):
            row["version_drugs"] = bool(getattr(t, "version_drugs"))
        if hasattr(t, "version_instrumental"):
            row["version_instrumental"] = bool(getattr(t, "version_instrumental"))
        # --- ДОБАВЬТЕ ЭТОТ БЛОК ---
        if hasattr(t, "synced_lyrics") or hasattr(t, "lyrics_synced"):
            row["synced_lyrics"] = bool(getattr(t, "synced_lyrics", getattr(t, "lyrics_synced", False)))

        items.append(row)

    return JsonResponse({"ok": True, "items": items})
@login_required(login_url='login')
def track_language(request, pk: int):
    """
    POST /tracks/<pk>/language/
    Body: {"language": "russian"|"english"|...|"none"|""}
    Сохраняет Track.language и возвращает ok.
    """
    if request.method != 'POST':
        return JsonResponse({"ok": False, "error": "method_not_allowed"}, status=405)

    track = get_object_or_404(Track, pk=pk)
    release = getattr(track, 'release', None)

    # доступ: владелец релиза или staff
    if not (request.user.is_staff or (release and request.user == release.user)):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    # читаем JSON
    try:
        data = json.loads(request.body.decode('utf-8') or '{}')
    except Exception:
        data = {}

    lang = (data.get('language') or '').strip()

    # простая валидация: латиница/нижние подчёркивания, как на фронте (slug)
    if lang and not re.fullmatch(r'[a-z_]{2,32}', lang):
        return JsonResponse({"ok": False, "error": "bad_language"}, status=400)

    track.language = (lang or None)
    track.save(update_fields=['language'])

    return JsonResponse({"ok": True, "track_id": track.id, "language": track.language or ""})

def _sync_track_people(track, roles_list):
    TrackPerson.objects.filter(track=track).delete()

    valid = {k for k, _ in TrackPerson.ROLE_CHOICES}
    role_map = {
        'artist': 'performer',
        'feat': 'featured',
        'featuring': 'featured',
    }

    bulk = []
    for r in roles_list or []:
        person = (r.get('person') or '').strip()
        role   = (r.get('role') or '').strip().lower()
        role   = role_map.get(role, role)
        if person and role in valid:
            bulk.append(TrackPerson(track=track, name=person, role=role))
    if bulk:
        TrackPerson.objects.bulk_create(bulk)


@login_required(login_url='login')
@require_POST
def release_tracks_save(request, pk: int):
    """
    Сохраняем весь трек-лист релиза.

    - Владельцу: можно только в статусах DRAFT/CHANGES.
    - Staff/superuser: можно в любом статусе (для модерации).
    - Принимаем ЛЮБОЙ из форматов payload:
        1) JSON-объект: {"tracks":[ ... ]}
        2) JSON-массив: [ ... ]
        3) form-data: tracks="<JSON>" (объект или массив)
    """
    release = get_object_or_404(Release, pk=pk)

    is_owner = (request.user == release.user)
    is_mgr = (request.user.is_staff or request.user.is_superuser)

    if not (is_owner or is_mgr):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    if is_owner and release.status not in (ReleaseStatus.DRAFT, ReleaseStatus.CHANGES):
        return JsonResponse({"ok": False, "error": "locked_by_status"}, status=400)

    # --- читаем payload гибко ---
    def _read_payload():
        raw = ''
        try:
            if request.content_type and 'application/json' in request.content_type:
                raw = request.body.decode('utf-8') or ''
            else:
                raw = request.POST.get('tracks') or request.body.decode('utf-8') or ''
        except Exception:
            raw = ''

        if not raw.strip():
            return {}

        try:
            obj = json.loads(raw)
        except Exception:
            return {}

        if isinstance(obj, list):  # голый массив
            return {"tracks": obj}
        if isinstance(obj, dict):  # объект
            if "tracks" in obj:
                return obj
            # на всякий случай поддержим альтернативные ключи
            for k in ("items", "data"):
                if k in obj and isinstance(obj[k], list):
                    return {"tracks": obj[k]}
        return {}

    payload = _read_payload()
    rows = payload.get('tracks') or []
    if not isinstance(rows, list):
        return JsonResponse({"ok": False, "error": "invalid_tracks"}, status=400)

    _sync_tracks(release, rows)

    fields = [
        'id', 'track_number', 'title', 'version', 'isrc', 'audio_file',
        'partner_code', 'preview_start',
        'version_explicit', 'version_drugs', 'version_instrumental'
    ]
    if hasattr(Track, 'lyrics'):
        fields.append('lyrics')

    if hasattr(Track, 'language'):
        fields.append('language')

    sl_field = 'synced_lyrics' if hasattr(Track, 'synced_lyrics') else (
        'lyrics_synced' if hasattr(Track, 'lyrics_synced') else None
    )
    if sl_field:
        fields.append(sl_field)

    items = list(release.tracks.order_by('track_number', 'id').values(*fields))

    # Приведём ключ к тому, что ждёт фронт
    if sl_field and sl_field != 'synced_lyrics':
        for it in items:
            it['synced_lyrics'] = bool(it.pop(sl_field, False))
    else:
        for it in items:
            it['synced_lyrics'] = bool(it.get('synced_lyrics', False))

    return JsonResponse({"ok": True, "items": items})

# ================== People API (персоны/роли по релизу) =======================
@login_required(login_url='login')
def release_people(request, pk: int):
    """
    JSON-список персон релиза (для владельца и для staff).
    """
    release = get_object_or_404(Release, pk=pk)
    if not (request.user.is_staff or request.user == release.user):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    items = list(
        ReleasePerson.objects.filter(release=release)
        .order_by('id')
        .values('id', 'name', 'role', 'share', 'ipi', 'isni', 'notes')
    )
    # приведение Decimal -> float
    for it in items:
        if it.get('share') is not None:
            try:
                it['share'] = float(it['share'])
            except Exception:
                it['share'] = None
    return JsonResponse({"ok": True, "items": items})



# ==============================================================================
@login_required(login_url='login')
@require_POST
@transaction.atomic
def release_people_save(request, pk: int):
    """
    Полная синхронизация списка персон релиза с таблицей ReleasePerson.
    Принимает JSON:
      - {"people": [ {id?, name, role, share?, ipi?, isni?, notes?}, ... ]}
      - или просто массив: [ {...}, {...} ]
    Право редактирования:
      - владелец: только в статусах DRAFT/CHANGES
      - staff/superuser: всегда
    """
    release = get_object_or_404(Release, pk=pk)

    is_owner = (request.user == release.user)
    is_mgr   = (request.user.is_staff or request.user.is_superuser)
    if not (is_owner or is_mgr):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    editable = is_mgr or (is_owner and release.status in (ReleaseStatus.DRAFT, ReleaseStatus.CHANGES))
    if not editable:
        return JsonResponse({"ok": False, "error": "locked_by_status"}, status=400)

    # --- читаем JSON гибко ---
    try:
        raw = request.body.decode("utf-8") if request.body else ""
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    people = payload.get("people", payload) if isinstance(payload, dict) else payload
    if not isinstance(people, list):
        return HttpResponseBadRequest("Expected JSON array or {'people': [...]}")

    # --- нормализация входных строк ---
    cleaned = []
    keep_ids = []
    for row in people:
        if not isinstance(row, dict):
            continue
        pid = row.get("id")
        name = (row.get("name") or "").strip()
        role = (row.get("role") or "").strip()
        share = row.get("share")
        ipi = (row.get("ipi") or "").strip()
        isni = (row.get("isni") or "").strip()
        notes = (row.get("notes") or "").strip()

        if not name or not role:
            continue

        try:
            pid = int(pid) if pid not in (None, "",) else None
        except Exception:
            pid = None

        try:
            if isinstance(share, str):
                share = share.replace(",", ".").strip()
            share = None if share in ("", None) else float(share)
        except Exception:
            share = None

        cleaned.append({
            "id": pid, "name": name, "role": role,
            "share": share, "ipi": ipi, "isni": isni, "notes": notes
        })
        if pid:
            keep_ids.append(pid)

    # 1) синхронизация в БД (единым хелпером)
    _sync_people_to_db(release, cleaned)

    # 2) параллельно сохраняем черновик (для фронта)
    form = release.form_data or {}
    form["people"] = cleaned
    release.form_data = form
    release.autosave_at = timezone.now()
    release.save(update_fields=["form_data", "autosave_at"])

    # вернём свежий список (с id)
    items = list(
        ReleasePerson.objects.filter(release=release)
        .order_by('id')
        .values('id', 'name', 'role', 'share', 'ipi', 'isni', 'notes')
    )
    for it in items:
        if it.get('share') is not None:
            try:
                it['share'] = float(it['share'])
            except Exception:
                it['share'] = None

    return JsonResponse({"ok": True, "created": 0, "updated": 0, "items": items})

    # вернём свежий список (с id)
    items = list(
        ReleasePerson.objects.filter(release=release)
        .order_by('id').values('id', 'name', 'role', 'share', 'ipi', 'isni', 'notes')
    )
    return JsonResponse({"ok": True, "created": created, "updated": updated, "items": items})


@login_required(login_url='login')
@require_POST
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def release_assign_isrc(request, pk: int):
    """
    Менеджер массово присваивает ISRC.
    Принимаем:
      - {"tracks":[{"id":..., "isrc":"..."}, ...]}
      - [{"id":..., "isrc":"..."}, ...]
      - form-data tracks="<json>"
    """
    release = get_object_or_404(Release, pk=pk)

    # читаем payload гибко
    def _read_payload():
        raw = ''
        try:
            if request.content_type and 'application/json' in request.content_type:
                raw = request.body.decode('utf-8') or ''
            else:
                raw = request.POST.get('tracks') or request.body.decode('utf-8') or ''
        except Exception:
            raw = ''
        if not raw.strip():
            return {}
        try:
            obj = json.loads(raw)
        except Exception:
            return {}
        if isinstance(obj, list):
            return {"tracks": obj}
        if isinstance(obj, dict):
            if "tracks" in obj:
                return obj
            for k in ("items", "data"):
                if k in obj and isinstance(obj[k], list):
                    return {"tracks": obj[k]}
        return {}

    payload = _read_payload()
    rows = payload.get('tracks') or []
    if not isinstance(rows, list):
        return JsonResponse({"ok": False, "error": "invalid_tracks"}, status=400)

    updated, errors = [], []
    for row in rows:
        try:
            tid = int(row.get('id'))
            code = (row.get('isrc') or '').strip().upper()
        except Exception:
            errors.append({"row": row, "error": "bad_row"})
            continue

        if code and not ISRC_RE.match(code):
            errors.append({"id": tid, "error": "bad_isrc"})
            continue

        track = release.tracks.filter(id=tid).first()
        if not track:
            errors.append({"id": tid, "error": "not_in_release"})
            continue

        track.isrc = code or None
        track.save(update_fields=['isrc'])
        updated.append({"id": track.id, "isrc": track.isrc or ""})

    return JsonResponse({"ok": True, "updated": updated, "errors": errors})


# =======================================================
@login_required(login_url='login')
@require_POST
def autosave_track(request, pk: int, track_id: int):
    """
Локальный автосейв одного трека:
  - title
  - version        # НОВОЕ
  - track_number
  - isrc (валидируем по ISRC_RE)
JSON в body, например: {"title":"...", "version":"Acoustic", "track_number":2, "isrc":"RUABC1234567"}
"""

    release = get_object_or_404(Release, pk=pk)

    # права: владелец или staff
    if not (request.user.is_staff or request.user == release.user):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    # владелец может править только DRAFT/CHANGES
    if (request.user == release.user) and (release.status not in (ReleaseStatus.DRAFT, ReleaseStatus.CHANGES)):
        return JsonResponse({"ok": False, "error": "locked_by_status"}, status=400)

    # парсим JSON
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
        if not isinstance(payload, dict):
            return HttpResponseBadRequest("JSON object expected")
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    track = release.tracks.filter(id=track_id).first()
    if not track:
        return JsonResponse({"ok": False, "error": "track_not_found"}, status=404)

    changed = []

    # title
    if "title" in payload:
        new_title = (payload.get("title") or "").strip()
        if new_title and new_title != track.title:
            track.title = new_title
            changed.append("title")

    # version (подзаголовок)
    if "version" in payload:
        new_version = (payload.get("version") or "").strip()
        if new_version != (track.version or ""):
            track.version = new_version
            changed.append("version")

    # track_number
    if "track_number" in payload:
        try:
            tn = int(payload.get("track_number"))
            if tn > 0 and tn != track.track_number:
                track.track_number = tn
                changed.append("track_number")
        except Exception:
            pass

    # isrc (может быть пустым)
    if "isrc" in payload:
        code = (payload.get("isrc") or "").strip().upper()
        if code and not ISRC_RE.match(code):
            return JsonResponse({"ok": False, "error": "bad_isrc"}, status=400)
        if (code or None) != track.isrc:
            track.isrc = code or None
            changed.append("isrc")
    # partner_code (может быть пустым) — ИМЯ ПОЛЯ ЗАМЕНИ, если у тебя иное
    if ("partner_code" in payload) or ("partnerCode" in payload):
        pcode = (payload.get("partner_code") or payload.get("partnerCode") or "").strip()
        current = getattr(track, "partner_code", None)
        if (pcode or None) != (current or None):
            setattr(track, "partner_code", pcode or None)
            changed.append("partner_code")

    if changed:
        track.save(update_fields=changed)

    return JsonResponse({
        "ok": True,
        "changed": changed,
        "track": {
            "id": track.id,
            "title": track.title,
            "version": track.version or "",  # НОВОЕ
            "track_number": track.track_number,
            "isrc": track.isrc or "",
            "partner_code": (getattr(track, "partner_code", "") or ""),
        }
    })


@login_required(login_url='login')
@require_POST
def autosave_people(request, pk: int):
    release = get_object_or_404(Release, pk=pk)

    # права
    if not (request.user.is_staff or request.user == release.user):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)
    if (request.user == release.user) and (release.status not in (ReleaseStatus.DRAFT, ReleaseStatus.CHANGES)):
        return JsonResponse({"ok": False, "error": "locked_by_status"}, status=400)

    # читаем JSON (массив или {"people":[...]})
    try:
        raw = request.body.decode("utf-8") or ""
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    people = payload.get("people", payload) if isinstance(payload, dict) else payload
    if not isinstance(people, list):
        return HttpResponseBadRequest("JSON array or {'people': [...]} expected")

    # --- НОРМАЛИЗАЦИЯ ---
    clean_people = []
    for row in people:
        if not isinstance(row, dict):
            continue
        name = (row.get("name") or "").strip()
        role = (row.get("role") or "").strip()
        if not name or not role:
            continue
        share = row.get("share")
        try:
            if isinstance(share, str):
                share = share.replace(",", ".").strip()
            share = None if share in ("", None) else float(share)
        except Exception:
            share = None
        clean_people.append({
            "name": name,
            "role": role,
            "share": share,
            "ipi": (row.get("ipi") or "").strip() or None,
            "isni": (row.get("isni") or "").strip() or None,
            "notes": (row.get("notes") or "").strip() or None,
        })

    # --- СИНХРОН В ЧЕРНОВИК (form_data) ---
    form = release.form_data or {}
    form["people"] = clean_people
    release.form_data = form
    release.autosave_at = timezone.now()
    release.save(update_fields=["form_data", "autosave_at"])


    # --- СИНХРОН В БАЗУ (ТО ЧТО ТЫ ХОЧЕШЬ «СРАЗУ») ---
    _sync_people_to_db(release, clean_people)

    # отдаём, что реально лежит в БД
    items = list(
        ReleasePerson.objects.filter(release=release)
        .order_by("id")
        .values("id", "name", "role", "share", "ipi", "isni", "notes")
    )
    for it in items:
        if it.get("share") is not None:
            try:
                it["share"] = float(it["share"])
            except Exception:
                it["share"] = None

    return JsonResponse({
        "ok": True,
        "autosave_at": release.autosave_at.isoformat(),
        "draft_people": clean_people,   # что в form_data
        "db_people": items              # что реально в таблице
    })



# ================== Профиль/пользователи ===============
@login_required(login_url='login')
def profile(request):
    instance = request.user
    form_info = UserEditForm(instance=instance)
    form_password = PasswordEditForm(user=instance)
    form_avatar = AvatarEditForm()
    if request.method == "POST":
        form_name = request.POST.get('form_name')
        if form_name == 'info':
            form_info = UserEditForm(instance=instance, data=request.POST)
            if form_info.is_valid():
                form_info.save()
                return redirect('profile')
        elif form_name == 'password':
            form_password = PasswordEditForm(user=instance, data=request.POST)
            if form_password.is_valid():
                user = form_password.save()
                auth.update_session_auth_hash(request, user)
                return redirect('profile')
        elif form_name == 'avatar':
            form_avatar = AvatarEditForm(instance=instance.profile, data=request.POST, files=request.FILES)
            if form_avatar.is_valid():
                user_profile = form_avatar.save(commit=False)
                if 'avatar' in request.FILES:
                    user_profile.avatar_thumbnail = request.FILES['avatar']
                user_profile.save()
                return redirect('profile')

    return render(request, "index.html", {
        "pattern": "profile",
        "form_info": form_info,
        "form_password": form_password,
        "form_avatar": form_avatar
    })


# =======================================================


# ================== Telegram API =======================
@csrf_exempt
@require_POST
def update_telegram_user_id(request):
    try:
        data = json.loads(request.body)
        api_key = data.get('api_key')
        user_id = data.get('site_user_id')
        telegram_user_id = data.get('telegram_user_id')

        if not all([api_key, user_id, telegram_user_id]):
            return JsonResponse({'error': 'Missing parameters'}, status=400)

        try:
            user = Profile.objects.get(user_id=user_id, api_key=api_key)
            user.telegram_user_id = telegram_user_id
            user.save()
            return JsonResponse({'status': 'success'})
        except Profile.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)


@csrf_exempt
@require_POST
def send_password_recovery(request):
    try:
        data = json.loads(request.body)
        telegram_user_id = data.get('telegram_user_id')
        if not telegram_user_id:
            return JsonResponse({'status': 'error', 'message': 'Missing telegram_user_id'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    password_length = 8
    new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=password_length))

    try:
        user = Profile.objects.get(telegram_user_id=telegram_user_id).user
        user.set_password(new_password)
        user.save()
    except Profile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'User not found for this telegram_user_id'}, status=404)

    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
    if not TELEGRAM_BOT_TOKEN:
        return JsonResponse({'status': 'error', 'message': 'Telegram bot token not configured'}, status=500)

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': telegram_user_id, 'text': f"Ваш новый пароль:\n<code>{new_password}</code>",
               'parse_mode': 'HTML'}

    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        result = response.json()
        if result.get('ok'):
            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({'status': 'error', 'message': result.get('description')}, status=500)
    except requests.exceptions.RequestException as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


def send_telegram_message(telegram_user_id, text_message):
    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
    if not TELEGRAM_BOT_TOKEN:
        return JsonResponse({'status': 'error', 'message': 'Telegram bot token not configured'}, status=500)

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': telegram_user_id, 'text': text_message, 'parse_mode': 'HTML'}

    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        result = response.json()
        if result.get('ok'):
            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({'status': 'error', 'message': result.get('description')}, status=500)
    except requests.exceptions.RequestException as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


def send_telegram_auth_code(telegram_user_id, code_length):
    new_code = ''.join(random.choices(string.digits, k=code_length))
    try:
        profile = Profile.objects.get(telegram_user_id=telegram_user_id)
        profile.auth_code = new_code
        profile.auth_until_datetime = datetime.now() + timedelta(minutes=AUTH_CODE_TTL_MINUTES)
        profile.save()
    except Profile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'User not found for this telegram_user_id'}, status=404)

    send_telegram_message(telegram_user_id, f"Ваш код для входа на сайт:\n<code>{new_code}</code>")


@csrf_exempt
@require_POST
def telegram_auth(request):
    try:
        data = json.loads(request.body)
        telegram_user_id = data.get('telegram_user_id')
        if not telegram_user_id:
            return JsonResponse({'status': 'error', 'message': 'Missing telegram_user_id'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    try:
        Profile.objects.get(telegram_user_id=telegram_user_id).user
        send_telegram_auth_code(telegram_user_id=telegram_user_id, code_length=6)
        return JsonResponse({'status': 'success'})
    except Profile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'User not found for this telegram_user_id'}, status=404)


@csrf_exempt
@require_POST
def telegram_username_fits(request):
    try:
        data = json.loads(request.body)
        telegram_username = data.get('username')
        if not telegram_username:
            return JsonResponse({'status': 'error', 'message': 'Missing telegram_username'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    count = User.objects.filter(username=telegram_username).count()
    if count == 0:
        return JsonResponse({'status': 'success'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Профиль с таким username уже существует.'}, status=409)


@csrf_exempt
@require_POST
def telegram_registration(request):
    try:
        data = json.loads(request.body)
        username = data.get('username')
        telegram_user_id = data.get('telegram_user_id')
        if not username:
            return JsonResponse({'status': 'error', 'message': 'Missing username'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    alphabet = string.ascii_letters + string.digits + "!#$_+-="
    password = ''.join(random.choice(alphabet) for _ in range(12))

    try:
        user = User.objects.create_user(username=username, password=password)
        user.profile.telegram_user_id = telegram_user_id
        user.profile.save()
        send_telegram_message(
            telegram_user_id,
            "Вы успешно зарегистрировались на сайте PLATINUMSOUNDX!\n\n"
            "Можете войти на сайт используя username и пароль представленные ниже.\n"
            "Обязательно поменяйте пароль на новый в разделе Профиль, когда войдёте на сайт!\n"
            f"Username: <code>{username}</code>\n"
            f"Временный пароль (на сайте будет возможность его изменить): <code>{password}</code>\n\n"
            "Рекомендуем использовать код из следующего сообщения, чтобы войти на сайт и без дополнительных действий сразу открыть страницу с установкой нового пароля."
        )
        send_telegram_auth_code(telegram_user_id=telegram_user_id, code_length=8)
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


# =======================================================


# ================== Artists / Admin ====================
@login_required(login_url='login')
def artists(request):
    all_artists = Artist.objects.filter(user_id=request.user.id)
    add_artist_form = AddArtistForm()
    if request.method == "POST":
        form_name = request.POST.get('form_name')
        if form_name == 'add_artist':
            add_artist_form = AddArtistForm(request.POST or None)
            if add_artist_form.is_valid():
                Artist.objects.create(
                    user=request.user,
                    name=add_artist_form.cleaned_data['name'],
                    spotify=add_artist_form.cleaned_data['spotify'],
                    apple=add_artist_form.cleaned_data['apple'],
                    vk=add_artist_form.cleaned_data['vk'],
                    yandex=add_artist_form.cleaned_data['yandex'],
                )
                add_artist_form = AddArtistForm()
        elif form_name == 'delete_artist':
            try:
                delete_artist = Artist.objects.get(id=request.POST.get("delete_artist_id"), user_id=request.user.id)
                delete_artist.delete()
            except Artist.DoesNotExist:
                pass

    return render(request, "index.html", {
        "pattern": "artists",
        "all_artists": all_artists,
        "add_artist_form": add_artist_form,
    })


@login_required(login_url='login')
def administration(request):
    staff_members = User.objects.filter(is_staff=True)
    add_staff_member_form = AddStaffMemberForm()
    if request.method == "POST":
        form_name = request.POST.get('form_name')
        if form_name == 'add_staff_member':
            add_staff_member_form = AddStaffMemberForm(request.POST)
            if add_staff_member_form.is_valid():
                staff_member_username = add_staff_member_form.cleaned_data['staff_member_username']
                try:
                    new_staff_member = User.objects.get(username=staff_member_username)
                    if new_staff_member.is_staff:
                        add_staff_member_form.add_error(
                            'staff_member_username',
                            forms.ValidationError(
                                "Пользователь с таким username уже является сотрудником. Введите другой username.")
                        )
                    else:
                        new_staff_member.is_staff = True
                        new_staff_member.save()
                        add_staff_member_form = AddStaffMemberForm()
                except User.DoesNotExist:
                    add_staff_member_form.add_error(
                        'staff_member_username',
                        forms.ValidationError("Пользователя с таким username не существует. Введите другой username.")
                    )
        elif form_name == 'degrade_staff_member':
            degrade_staff_member = User.objects.get(username=request.POST.get('degrade_staff_member_username'))
            degrade_staff_member.is_staff = False
            degrade_staff_member.save()

    return render(request, "index.html", {
        "pattern": "administration",
        "staff_members": staff_members,
        "add_staff_member_form": add_staff_member_form,
    })


# =======================================================


# ================== Новый релиз ========================
@login_required(login_url='login')
def new_release(request):
    # --- helper: привести список жанров к единому виду [{value, label}] ---
    def _normalize_genres(raw_list):
        norm = []
        for item in (raw_list or []):
            if isinstance(item, dict):
                label = (item.get('name') or item.get('title') or item.get('value') or '').strip()
                value = (item.get('value') or label).strip()
            else:
                label = value = str(item).strip()
            if value:
                norm.append({'value': value, 'label': label})
        return norm

    """
    - ?edit=<id> — открываем существующий релиз (если есть права)
    - Без edit — НЕ создаём черновик на GET; берём релиз из сессии, если он там есть
    - POST — создаём черновик ТОЛЬКО при реальном изменении (поля/файлы/треки)
    """
    # 0) Сброс «привязки» при клике «Новый релиз»
    if request.method == "GET" and request.GET.get('new') == '1':
        request.session.pop('current_release_id', None)

    # 1) Определяем релиз
    release = None
    edit_id = request.GET.get('edit')

    if edit_id:
        release = get_object_or_404(Release, id=edit_id)
        if not (request.user.is_staff or release.user_id == request.user.id):
            return redirect('your_music')
        request.session['current_release_id'] = release.id
    else:
        rid = request.session.get('current_release_id')
        release = Release.objects.filter(id=rid, user=request.user).first() if rid else None

    # 2) POST (AJAX автосейв)
    if request.method == "POST":
        is_ajax = (
            request.headers.get('x-requested-with') == 'XMLHttpRequest'
            or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'
        )

        # form-data + JSON -> общий dict
        data = request.POST.dict()
        json_in = _load_json(request)
        if isinstance(json_in, dict) and json_in:
            data.update(json_in)

        # --- ЛЕНИВАЯ ИНИЦИАЛИЗАЦИЯ ЧЕРНОВИКА (WHITELIST) ---
        if release is None:
            EDITABLE_FIELDS = {
                'language_metadata', 'album_title', 'album_subtitle',
                'type_release', 'genre', 'subgenre', 'album_UPC',
                'release_date', 'start_date', 'cover',
            }
            IGNORE_KEYS = {
                'csrfmiddlewaretoken', 'X-Requested-With', 'x-requested-with',
                '_', 'action', 'pattern', 'tab', 'page', 'release_id',
            }

            def _truthy(v):
                if v is None:
                    return False
                if isinstance(v, str):
                    s = v.strip().lower()
                    return s not in ("", "0", "none", "null")
                if isinstance(v, (list, tuple, set)):
                    return any(_truthy(x) for x in v)
                if isinstance(v, dict):
                    return any(_truthy(x) for x in v.values())
                return bool(v)

            has_editable_data = any(
                (k in EDITABLE_FIELDS) and _truthy(v)
                for k, v in data.items()
                if k not in IGNORE_KEYS
            )

            has_files = bool(request.FILES) and any(
                request.FILES.getlist(k) for k in request.FILES.keys()
            )

            tracks_payload = _load_json(request, key='tracks')
            rows = (tracks_payload.get('tracks') if isinstance(tracks_payload, dict) else tracks_payload)
            has_tracks = bool(rows) and isinstance(rows, list) and len(rows) > 0

            if not (has_editable_data or has_files or has_tracks):
                # Никаких реальных действий — не создаём запись
                if is_ajax:
                    return JsonResponse({
                        "ok": True, "created": False,
                        "release_id": None, "changed": [], "editable": False
                    })
                return redirect('new_release')

            # Есть реальные действия — создаём черновик
            release = Release.objects.create(user=request.user, status=ReleaseStatus.DRAFT)
            request.session['current_release_id'] = release.id
        # --- конец ленивой инициализации ---

        changed = []

        # Загрузка аудиофайлов треков
        if 'track_files[]' in request.FILES:
            track_files = request.FILES.getlist('track_files[]')
            if track_files and release.status in (ReleaseStatus.DRAFT, ReleaseStatus.CHANGES):
                current_track_count = release.tracks.count()
                for i, file in enumerate(track_files, start=1):
                    track_title = file.name
                    for ext in ['.wav', '.flac', '.WAV', '.FLAC']:
                        if track_title.endswith(ext):
                            track_title = track_title[:-len(ext)]
                            break
                    Track.objects.create(
                        release=release,
                        title=track_title,
                        track_number=current_track_count + i,
                        audio_file=file
                    )

        def set_if(name, attr=None, value=None, transform=lambda v: v):
            nonlocal changed
            if value is None:
                value = data.get(name, '')
            if value not in (None, ''):
                setattr(release, attr or name, transform(value))
                changed.append(attr or name)

        # Разрешено править только DRAFT/CHANGES
        editable = release.status in (ReleaseStatus.DRAFT, ReleaseStatus.CHANGES)
        uploaded_cover_saved = False
        if 'cover' in request.FILES and editable:
            cover_file = request.FILES['cover']

            # ===== 0) Базовая валидация формата/размера файла =====
            ALLOWED = {'image/jpeg', 'image/png'}
            MAX_MB = 20

            ctype = (cover_file.content_type or '').lower()
            size_mb = (cover_file.size or 0) / (1024 * 1024)

            if ctype not in ALLOWED or size_mb > MAX_MB:
                is_ajax = (
                    request.headers.get('x-requested-with') == 'XMLHttpRequest'
                    or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'
                )
                if is_ajax:
                    return JsonResponse({
                        "ok": False,
                        "error": "bad_cover",
                        "reason": (
                            "Недопустимый тип файла. Разрешены JPG/PNG."
                            if ctype not in ALLOWED else
                            f"Файл слишком большой: {size_mb:.1f} МБ (максимум {MAX_MB} МБ)."
                        )
                    }, status=400)
            else:
                # ===== 1) Детальная проверка изображения (пиксели и DPI) =====
                try:
                    cover_file.seek(0)
                    img = Image.open(cover_file)
                    width, height = img.size

                    dpi_x = dpi_y = None
                    info = getattr(img, "info", {}) or {}

                    if isinstance(info.get("dpi"), tuple) and len(info.get("dpi")) >= 2:
                        dpi_x, dpi_y = info.get("dpi")[0], info.get("dpi")[1]

                    if (dpi_x is None or dpi_y is None) and info.get("jfif_density"):
                        dens = info.get("jfif_density")
                        unit = info.get("jfif_unit")  # 1 = dpi, 2 = dpcm
                        if isinstance(dens, tuple) and len(dens) >= 2:
                            if unit == 1:
                                dpi_x, dpi_y = float(dens[0]), float(dens[1])
                            elif unit == 2:
                                dpi_x, dpi_y = float(dens[0]) * 2.54, float(dens[1]) * 2.54

                    if dpi_x is None or dpi_y is None:
                        dpi_x = dpi_y = 72.0

                    if width != height:
                        raise ValueError(f"Обложка должна быть квадратной. Сейчас: {width}×{height}px.")
                    if width < 1400 or height < 1400:
                        raise ValueError(f"Минимальный размер 1400×1400px. Сейчас: {width}×{height}px.")
                    if width > 6000 or height > 6000:
                        raise ValueError(f"Максимальный размер 6000×6000px. Сейчас: {width}×{height}px.")
                    if min(float(dpi_x), float(dpi_y)) < 72:
                        raise ValueError(
                            f"Разрешение должно быть не менее 72 dpi. Сейчас: ~{dpi_x:.0f}×{dpi_y:.0f} dpi."
                        )

                except Exception as e:
                    is_ajax = (
                        request.headers.get('x-requested-with') == 'XMLHttpRequest'
                        or request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'
                    )
                    if is_ajax:
                        return JsonResponse({"ok": False, "error": "bad_cover", "reason": str(e)}, status=400)

                # ===== 2) Сохраняем новый файл =====
                cover_file.seek(0)
                base, ext = os.path.splitext(cover_file.name)
                filename = f"{uuid.uuid4().hex}{(ext or '.jpg').lower()}"
                rel_path = f"covers/{filename}"
                saved_path = default_storage.save(rel_path, cover_file)
                cover_url = f"{settings.MEDIA_URL}{saved_path}"

                old_url = (release.cover or '').strip()

                release.cover = cover_url
                release.cover_thumbnail = cover_url
                changed.extend(['cover', 'cover_thumbnail'])
                uploaded_cover_saved = True

                try:
                    if old_url and old_url.startswith(settings.MEDIA_URL):
                        rel_old = old_url[len(settings.MEDIA_URL):]
                        if rel_old.startswith('covers/'):
                            default_storage.delete(rel_old)
                except Exception:
                    pass

        if editable:
            # простые поля
            set_if('language_metadata')
            set_if('album_title')
            set_if('album_subtitle')
            set_if('type_release')
            set_if('genre')
            set_if('subgenre')
            set_if('album_UPC')

            # обложка (если файла не было — сохраняем значение из POST/JSON)
            if not uploaded_cover_saved:
                cover_val = data.get('cover')
                if cover_val and not cover_val.startswith('/') and '://' not in cover_val:
                    cover_val = '/media/' + cover_val
                set_if('cover', value=cover_val)
                set_if('cover', attr='cover_thumbnail', value=cover_val)

            # даты
            rd = data.get('release_date')
            if rd:
                for fmt in ('%d.%m.%Y', '%Y-%m-%d'):
                    try:
                        release.release_date = datetime.strptime(rd, fmt).date()
                        changed.append('release_date')
                        break
                    except Exception:
                        pass
            sd = data.get('start_date')
            if sd:
                for fmt in ('%d.%m.%Y', '%Y-%m-%d'):
                    try:
                        release.start_date = datetime.strptime(sd, fmt).date()
                        changed.append('start_date')
                        break
                    except Exception:
                        pass

            if changed:
                release.save(update_fields=list(set(changed)))

            # синхронизация трек-листа
            payload = _load_json(request, key='tracks')
            if payload:
                rows = payload.get('tracks') if isinstance(payload, dict) else payload
                can_sync = (
                    request.user.is_staff or request.user.is_superuser or
                    (request.user == release.user and release.status in (ReleaseStatus.DRAFT, ReleaseStatus.CHANGES))
                )
                if can_sync and isinstance(rows, list):
                    _sync_tracks(release, rows)

        if is_ajax:
            response_data = {
                "ok": True,
                "release_id": release.id,
                "changed": changed,
                "editable": editable,
            }
            if 'track_files[]' in request.FILES:
                response_data['tracks'] = list(
                    release.tracks.order_by('track_number', 'id')
                    .values('id', 'track_number', 'title', 'version', 'isrc', 'audio_file',
                            'partner_code', 'preview_start',
                            'version_explicit', 'version_drugs', 'version_instrumental',
                            'synced_lyrics')
                )
            return JsonResponse(response_data)

        return redirect('new_release')

    # 3) GET — форма без падений при release=None
    if release is None:
        add_release_form = AddReleaseForm()
    else:
        try:
            add_release_form = AddReleaseForm(instance=release)
        except TypeError:
            add_release_form = AddReleaseForm(initial={
                'language_metadata': getattr(release, 'language_metadata', ''),
                'album_title': getattr(release, 'album_title', ''),
                'album_subtitle': getattr(release, 'album_subtitle', ''),
                'type_release': getattr(release, 'type_release', ''),
                'genre': getattr(release, 'genre', ''),
                'subgenre': getattr(release, 'subgenre', ''),
                'album_UPC': getattr(release, 'album_UPC', ''),
                'release_date': getattr(release, 'release_date', None),
                'start_date': getattr(release, 'start_date', None),
                'cover': getattr(release, 'cover', ''),
            })

    # -------- ПРЕДЗАПОЛНЕНИЕ ДЛЯ ФРОНТА (вкладка «Релиз») --------
    prefill = {}
    if release:
        prefill = {
            "language_metadata": release.language_metadata or "",
            "album_title": release.album_title or "",
            "album_subtitle": release.album_subtitle or "",
            "type_release": release.type_release or "",
            "genre": release.genre or "",
            "subgenre": release.subgenre or "",
            "album_UPC": release.album_UPC or "",
            "release_date": release.release_date.strftime("%Y-%m-%d") if release.release_date else "",
            "start_date": release.start_date.strftime("%Y-%m-%d") if release.start_date else "",
            "cover": release.cover or "",
            "cover_thumbnail": release.cover_thumbnail or "",
        }
    # --- нормализуем жанры для шаблона ---
    _raw_genres = different_data.get_data("musical_genres") or []
    _musical_genres = []
    for g in _raw_genres:
        if isinstance(g, dict):
            v = g.get("value") or g.get("name") or g.get("title") or str(g)
            t = g.get("title") or g.get("name") or g.get("value") or str(g)
        else:
            v = t = str(g)
        _musical_genres.append({"value": v, "text": t})
    # --- конец нормализации жанров ---

    return render(request, "index.html", {

        "pattern": "new_release",
        "musical_genres": _musical_genres,
        "current_release_id": (release.id if release else ""),
        "release": release,
        "add_release_form": add_release_form,
        "release_prefill": prefill,  # <-- НОВОЕ: данные для предзаполнения на фронте
    })


# =======================================================
# === AUTOSAVE: частичное сохранение полей релиза (без миграций) ===


@login_required(login_url='login')
@require_POST
@transaction.atomic
def autosave_release(request, pk: int):
    """
    Принимает JSON-объект с изменениями и точечно обновляет поля модели Release.
    Работает только в статусах DRAFT/CHANGES для владельца; staff/superuser — всегда.
    """
    release = get_object_or_404(Release, pk=pk)

    is_owner = (request.user == release.user)
    is_mgr = (request.user.is_staff or request.user.is_superuser)
    if not (is_owner or is_mgr):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    editable = is_mgr or (is_owner and release.status in (ReleaseStatus.DRAFT, ReleaseStatus.CHANGES))
    if not editable:
        return JsonResponse({"ok": False, "error": "locked_by_status"}, status=400)

    # читаем JSON
    try:
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        if not isinstance(payload, dict):
            return HttpResponseBadRequest("JSON object expected")
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    # Список ТОЛЬКО существующих полей в вашей модели Release
    allowed = {
        # базовые
        "language_metadata",
        "album_title",
        "album_subtitle",
        "type_release",
        "genre",
        "subgenre",
        "album_UPC",
        # даты
        "release_date",
        "start_date",
        # обложка
        "cover",
    }

    def _parse_date(s):
        if not s:
            return None
        for fmt in ("%d.%m.%Y", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                pass
        return None

    changed = []
    for field, value in payload.items():
        if field not in allowed:
            continue

        if field in {"release_date", "start_date"}:
            dt = _parse_date(value)
            if dt:
                setattr(release, field, dt)
                changed.append(field)
            continue

        if field == "cover":
            # нормализация относительного пути, если нужно
            if value and not str(value).startswith("/") and "://" not in str(value):
                value = "/media/" + str(value)
            # дублируем в cover_thumbnail, как у вас сделано в new_release()
            release.cover = value
            release.cover_thumbnail = value
            changed.extend(["cover", "cover_thumbnail"])
            continue

        # простые поля (строки/ID)
        setattr(release, field, value)
        changed.append(field)

    if changed:
        release.save(update_fields=list(set(changed)))  # set -> на случай cover/cover_thumbnail

    return JsonResponse({"ok": True, "updated": changed})


# ================== Аналитика / отчеты =================
@login_required(login_url='login')
def analytics(request):
    return render(request, "index.html", {"pattern": "analytics"})


@staff_member_required
def tiktok_analytics(request):
    avatar_medium_subquery = TikTokScanningUser.objects.filter(
        account_id=OuterRef('account_id')
    ).order_by('-created_at').values('avatar_medium')[:1]

    scanning_created_at_subquery = TikTokScanningUser.objects.filter(
        account_id=OuterRef('account_id')
    ).order_by('-created_at').values('created_at')[:1]

    tiktok_users = TikTokUser.objects.annotate(
        avatar_medium=Subquery(avatar_medium_subquery),
        scanning_created_at=Subquery(scanning_created_at_subquery)
    )

    return render(request, "index.html", {
        "pattern": "tiktok_analytics",
        "tiktok_users": tiktok_users,
    })


@login_required(login_url='login')
def get_data_for_reports(request):
    if not request.user.is_authenticated:
        return JsonResponse([], safe=False)

    qs = _apply_access(request, RoyaltyStatement.objects.all())
    if qs is None:
        return JsonResponse({
            "music_platforms": [],
            "artists": [],
            "releases": [],
            "unique_usage_period": []
        })

    all_music_platforms = (qs.values_list('music_platform', flat=True)
                             .distinct().order_by('-music_platform'))
    all_artists = (qs.values('performer')
                     .distinct().order_by('performer'))
    # вернём id/name/upc в том же формате, что и раньше
    all_releases = (Release.objects.filter(album_UPC__in=qs.values_list('album_UPC', flat=True))
                                  .values('id', 'album_title', 'album_UPC'))

    unique_usage_period = (qs.values_list('usage_period', flat=True)
                             .distinct().order_by('-usage_period'))

    return JsonResponse({
        "music_platforms": list(all_music_platforms),
        "artists": [{"id": a["performer"], "name": a["performer"]} for a in all_artists if a["performer"]],
        "releases": list(all_releases),
        "unique_usage_period": list(unique_usage_period)
    })

@login_required(login_url='login')
def get_reports_earnings(request):
    """
    Возвращает:
      balance: сумма total_reward по доступным пользователю данным
      quarters: [{label: "24-Q1", amount: 123.45}, ...] — суммы по usage_period
    Поддерживает ярлыки вида "2 квартал 2025", "Q2 2025", "2025-Q2".
    Все приводим к "YY-Q#".
    """
    qs = _apply_access(request, RoyaltyStatement.objects.all())
    if qs is None:
        return JsonResponse({"balance": 0, "quarters": []})

    rows = qs.values('usage_period').annotate(amount=Sum('total_reward'))

    def canon_label(s: str) -> tuple[str, tuple[int,int]]:
        """-> ('25-Q2', (2025,2)) либо исходная строка и «большой» ключ для конца сортировки."""
        t = (s or '').strip()

        # 2 квартал 2025
        m = re.search(r'(?i)\b([1-4])\s*квартал\W*(\d{4})', t)
        if m:
            q = int(m.group(1)); y = int(m.group(2))
            return (f"{str(y)[-2:]}-Q{q}", (y, q))

        # Q2 2025 / 2025 Q2
        m = re.search(r'(?i)q([1-4]).*?(\d{4})', t)
        if m:
            q = int(m.group(1)); y = int(m.group(2))
            return (f"{str(y)[-2:]}-Q{q}", (y, q))

        # 2025-Q2 / 2025Q2
        m = re.search(r'(?i)(\d{4})\s*[- ]?\s*q([1-4])', t)
        if m:
            y = int(m.group(1)); q = int(m.group(2))
            return (f"{str(y)[-2:]}-Q{q}", (y, q))

        # Дата/месяц -> квартал (на всякий случай)
        for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%Y-%m", "%m.%Y"):
            try:
                dt = datetime.strptime(t, fmt)
                q = (dt.month - 1)//3 + 1
                return (f"{str(dt.year)[-2:]}-Q{q}", (dt.year, q))
            except Exception:
                pass

        # fallback — оставляем как есть, сортируем в хвост
        return (t or "—", (9999, 9))

    per_quarter = {}
    total = 0.0
    for r in rows:
        lbl, _ = canon_label(r.get('usage_period'))
        amt = float(r.get('amount') or 0)
        total += amt
        per_quarter[lbl] = per_quarter.get(lbl, 0.0) + amt

    # сортируем по году/кварталу, а «непонятные» ярлыки — в самом конце по алфавиту
    def sort_key(lbl: str):
        m = re.match(r'^(\d{2})-Q([1-4])$', lbl)
        if m:
            return (int('20' + m.group(1)), int(m.group(2)), '')
        return (9999, 9, lbl)

    quarters = [{"label": k, "amount": round(v, 2)}
                for k, v in sorted(per_quarter.items(), key=lambda kv: sort_key(kv[0]))]

    return JsonResponse({"balance": round(total, 2), "quarters": quarters})

def _parse_quarter_label_yq(s: str):
    """
    Пытаемся вытащить (year, quarter) из строк типа:
    '2 квартал 2025', 'Q2 2025', '2025-Q2', '25-Q2', 'второй квартал 2025'
    Возвращает (год:int, квартал:int) или None
    """
    if not s:
        return None
    t = str(s).strip()

    import re
    # Q2 2025 / Q2-2025
    m = re.match(r'(?i)q([1-4])\s*[- ]?\s*(\d{2,4})$', t)
    if m:
        q = int(m.group(1)); y = int(m.group(2))
        if y < 100: y += 2000 if y < 70 else 1900
        return (y, q)

    # 2025-Q2 / 25-Q2
    m = re.match(r'(?i)(\d{2,4})\s*[- ]?\s*q([1-4])$', t)
    if m:
        y = int(m.group(1)); q = int(m.group(2))
        if y < 100: y += 2000 if y < 70 else 1900
        return (y, q)

    # 2 квартал 2025 / второй квартал 2025
    m = re.match(r'(?i)(перв|втор|трет|четв|\d)\w*\s+квартал\W*(\d{4})$', t)
    if m:
        part = m.group(1).lower()
        year = int(m.group(2))
        m2q = {'перв':1,'втор':2,'трет':3,'четв':4}
        q = m2q.get(part, None) if not part.isdigit() else int(part)
        if q in (1,2,3,4): return (year, q)

    return None

def _yq_short_label(year: int, q: int) -> str:
    return f"{str(year)[-2:]}-Q{q}"

@login_required(login_url='login')
def get_reports_summary(request):
    """
    Баланс и разбивка по кварталам (usage_period) из RoyaltyStatement,
    с учётом прав доступа пользователя.
    """
    qs = _apply_access(request, RoyaltyStatement.objects.all())
    if qs is None:
        return JsonResponse({"balance": 0, "points": []})

    agg = qs.aggregate(total=Coalesce(Sum('total_reward'), Value(0.0)))
    balance = float(agg['total'] or 0)

    rows = (
        qs.values('usage_period')
          .annotate(total=Coalesce(Sum('total_reward'), Value(0.0)))
    )

    items = []
    for r in rows:
        raw = r['usage_period'] or ''
        yq = _parse_quarter_label_yq(raw)
        if yq:
            label = _yq_short_label(*yq)  # вида '25-Q2'
            sort_key = (yq[0], yq[1])
        else:
            label = str(raw)
            sort_key = (label,)
        items.append((sort_key, label, float(r['total'] or 0.0)))

    items.sort(key=lambda x: x[0])  # по времени, если распарсилось; иначе по строке

    points = [{"x": label, "y": val} for _, label, val in items]

    return JsonResponse({"balance": round(balance, 2), "points": points})


@login_required(login_url='login')
def reports(request):
    """
    Раздел «Отчёты»:
    - Загружает Excel/CSV с финансовыми данными
    - ПРИНИМАЕТ обязательный текстовый ярлык периода (квартал), напр. '2 квартал 2025'
    - Сохраняет ВСЕ строки в RoyaltyStatement с единым usage_period=этот ярлык
    - Если такой период уже есть — заменяет его целиком (delete + bulk_create)
    """
    upload_report_file_form = UploadReportFileForm()
    upload_report_file_errors = []

    # Периоды для выпадашки (у staff — все, у пользователя — только доступные)
    qs = _apply_access(request, RoyaltyStatement.objects.all())
    unique_usage_period = []
    if qs is not None:
        unique_usage_period = (
            qs.values_list('usage_period', flat=True)
              .distinct()
              .order_by('-usage_period')
        )

    if request.method == 'POST':
        upload_report_file_form = UploadReportFileForm(request.POST, request.FILES)
        if not upload_report_file_form.is_valid():
            upload_report_file_errors.append(upload_report_file_form.errors)
        else:
            period_label = upload_report_file_form.cleaned_data['period_label']
            period_label = _norm_quarter_label(period_label)  # см. helper ниже
            excel_file = upload_report_file_form.cleaned_data['report_file']

            # читаем таблицу
            import pandas as pd, re
            try:
                name = (excel_file.name or '').lower()
                if name.endswith('.csv'):
                    try:
                        df = pd.read_csv(excel_file, dtype=str)
                    except UnicodeDecodeError:
                        excel_file.seek(0)
                        df = pd.read_csv(excel_file, dtype=str, encoding='cp1251')
                else:
                    df = pd.read_excel(excel_file, dtype=str)
            except Exception as e:
                upload_report_file_errors.append(f'Ошибка чтения файла: {e}')
                return render(request, "index.html", {
                    "pattern": "reports",
                    "unique_usage_period": list(unique_usage_period),
                    "upload_report_file_form": upload_report_file_form,
                    "upload_report_file_errors": upload_report_file_errors
                })

            # мягкая нормализация имён колонок
            orig_cols = list(df.columns)
            df.columns = (df.columns.astype(str).str.lower()
                          .str.replace(r'[\s\./,]+', '_', regex=True)
                          .str.strip('_'))

            def find_col(*variants):
                for v in variants:
                    if v in df.columns:
                        return v
                # поиск по регуляркам
                for v in variants:
                    try:
                        rgx = re.compile(v, re.I)
                    except re.error:
                        continue
                    for c in df.columns:
                        if rgx.search(c):
                            return c
                return None

            # маппинг колонок (рус/англ-варианты)
            c_pl   = find_col('music_platform', 'площадка', 'платформа', 'service', 'store', 'канал')
            c_rt   = find_col('rights_type', 'тип_используемых_прав', 'тип_прав')
            c_trr  = find_col('territory', 'территория', 'country')
            c_ct   = find_col('content_type', 'тип_контента')
            c_ut   = find_col('usage_type', 'вид_использования_контента', 'тип_использования')
            c_perf = find_col('performer', 'исполнитель', 'артист', 'artist')
            c_ttl  = find_col('track_title', 'название_трека', 'трек', r'^title$', 'song')
            c_alb  = find_col('album_title', 'название_альбома', 'альбом')
            c_lyr  = find_col('lyricist', 'автор_слов')
            c_comp = find_col('composer', 'автор_музыки')
            c_isrc = find_col('isrc', 'isrc_контента')
            c_upc  = find_col('album_upc', 'upc', 'upc_альбома', 'штрихкод')
            c_cnt  = find_col('usage_count', 'количество_загрузок_прослушиваний', 'количество', 'count', 'plays', 'streams')
            c_cps  = find_col('copyright_share', 'доля_авторских_прав_лицензиара')
            c_rrs  = find_col('related_rights_share', 'доля_смежных_прав_лицензиара')
            c_crw  = find_col('copyright_reward', 'вознаграждение_лицензиара_за_авторские_права_в_руб_без_ндс')
            c_rrw  = find_col('related_rights_reward', 'вознаграждение_лицензиара_за_смежные_права_в_руб_без_ндс')
            c_tot  = find_col('total_reward', 'итого_вознаграждение_лицензиара_в_руб_без_ндс', 'total')
            c_cph  = find_col('copyright_holder', 'копирайт')
            c_lic  = find_col('licensor_code', 'код_лицензиата')
            c_ctr  = find_col('contract_id', 'договор_id')
            c_n    = find_col('n', '^№$', 'номер', 'row', 'index')

            def as_int(x):
                import math
                try:
                    s = str(x).replace(' ', '').replace('\xa0', '').replace(',', '.')
                    v = int(float(s))
                    if math.isfinite(v):
                        return v
                except Exception:
                    pass
                return 0

            def as_float(x):
                try:
                    s = str(x).replace(' ', '').replace('\xa0', '').replace(',', '.')
                    return float(s)
                except Exception:
                    return 0.0

            items = []
            for i, row in df.iterrows():
                items.append(RoyaltyStatement(
                    usage_period=period_label,                          # ВАЖНО: весь файл = один квартал
                    music_platform=(row.get(c_pl)   or '') if c_pl   else '',
                    rights_type=(row.get(c_rt)      or '') if c_rt   else '',
                    territory=(row.get(c_trr)      or '') if c_trr  else '',
                    content_type=(row.get(c_ct)     or '') if c_ct   else '',
                    usage_type=(row.get(c_ut)       or '') if c_ut   else '',
                    performer=(row.get(c_perf)      or '') if c_perf else '',
                    track_title=(row.get(c_ttl)     or '') if c_ttl  else '',
                    album_title=(row.get(c_alb)     or '') if c_alb  else '',
                    lyricist=(row.get(c_lyr)        or '') if c_lyr  else '',
                    composer=(row.get(c_comp)       or '') if c_comp else '',
                    ISRC=((row.get(c_isrc) or '').replace(' ', '').upper()) if c_isrc else '',
                    album_UPC=(row.get(c_upc)       or '') if c_upc  else '',
                    usage_count=as_int(row.get(c_cnt))   if c_cnt else 0,
                    copyright_share=as_int(row.get(c_cps)) if c_cps else 0,
                    related_rights_share=as_int(row.get(c_rrs)) if c_rrs else 0,
                    copyright_reward=as_float(row.get(c_crw)) if c_crw else 0.0,
                    related_rights_reward=as_float(row.get(c_rrw)) if c_rrw else 0.0,
                    total_reward=as_float(row.get(c_tot)) if c_tot else 0.0,
                    copyright_holder=(row.get(c_cph) or '') if c_cph else '',
                    licensor_code=(row.get(c_lic) or '') if c_lic else '',
                    contract_id=as_int(row.get(c_ctr)) if c_ctr else 0,
                    n=as_int(row.get(c_n)) if c_n else (i + 1),
                ))

            if not items:
                upload_report_file_errors.append('В файле нет пригодных строк.')
            else:
                from django.db import transaction
                try:
                    with transaction.atomic():
                        # «замена корзиной» для выбранного квартала
                        RoyaltyStatement.objects.filter(usage_period=period_label).delete()
                        RoyaltyStatement.objects.bulk_create(items, batch_size=1000)
                except Exception as e:
                    upload_report_file_errors.append(f'Ошибка сохранения: {e}')
                else:
                    # обновим список периодов
                    qs = _apply_access(request, RoyaltyStatement.objects.all())
                    if qs is not None:
                        unique_usage_period = (
                            qs.values_list('usage_period', flat=True)
                              .distinct()
                              .order_by('-usage_period')
                        )
                    # очистим форму
                    upload_report_file_form = UploadReportFileForm()

    return render(request, "index.html", {
        "pattern": "reports",
        "unique_usage_period": list(unique_usage_period),
        "upload_report_file_form": upload_report_file_form,
        "upload_report_file_errors": upload_report_file_errors
    })


def export_report_to_excel(queryset):
    """
    Генерация XLSX по тем же колонкам, что и PDF-экспорт.
    Принимает queryset RoyaltyStatement.
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "Report"

    headers = [
        "N", "Период использования контента", "Площадка", "Тип используемых прав", "Территория",
        "Тип контента", "Вид использования контента", "Исполнитель", "Название трека",
        "Название альбома", "Автор слов", "Автор музыки",
        "Доля авторских прав Лицензиара", "Доля смежных прав Лицензиара",
        "ISRC контента", "UPC альбома", "Копирайт",
        "Количество загрузок/прослушиваний",
        "Вознаграждение ЛИЦЕНЗИАРА за авторские права в руб., без НДС",
        "Вознаграждение ЛИЦЕНЗИАРА за смежные права в руб., без НДС",
        "Итого вознаграждение ЛИЦЕНЗИАРА в руб., без НДС",
        "код Лицензиата", "Договор ID"
    ]
    ws.append(headers)

    for item in queryset:
        ws.append([
            item.n,
            item.usage_period,
            item.music_platform,
            item.rights_type,
            item.territory,
            item.content_type,
            item.usage_type,
            item.performer,
            item.track_title,
            item.album_title,
            item.lyricist,
            item.composer,
            item.copyright_share,
            item.related_rights_share,
            item.ISRC,
            item.album_UPC,
            item.copyright_holder,
            item.usage_count,
            item.copyright_reward,
            item.related_rights_reward,
            item.total_reward,
            item.licensor_code,
            item.contract_id,
        ])

    # заморозим шапку
    ws.freeze_panes = "A2"

    # ответ
    response = HttpResponse(
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    response["Content-Disposition"] = 'attachment; filename="report.xlsx"'
    wb.save(response)
    return response

def export_report_to_pdf(queryset):
    font_path = os.path.join(settings.BASE_DIR, 'app', 'static', 'css', 'fonts', 'Inter-Regular.ttf')
    pdfmetrics.registerFont(TTFont('Inter-Regular', font_path))

    data = [[
        "N", "Период использования контента", "Площадка", "Тип используемых прав", "Территория", "Тип контента",
        "Вид использования контента", "Исполнитель", "Название трека", "Название альбома", "Автор слов", "Автор музыки",
        "Доля авторских прав Лицензиара", "Доля смежных прав Лицензиара", "ISRC контента", "UPC альбома", "Копирайт",
        "Количество загрузок/прослушиваний", "Вознаграждение ЛИЦЕНЗИАРА за авторские права в руб., без НДС",
        "Вознаграждение ЛИЦЕНЗИАРА за смежные права в руб., без НДС", "Итого вознаграждение ЛИЦЕНЗИАРА в руб., без НДС",
        "код Лицензиата", "Договор ID"
    ]]
    for item in queryset:
        data.append([
            item.n, item.usage_period, item.music_platform, item.rights_type, item.territory, item.content_type,
            item.usage_type, item.performer, item.track_title, item.album_title, item.lyricist, item.composer,
            item.copyright_share, item.related_rights_share, item.ISRC, item.album_UPC, item.copyright_holder,
            item.usage_count, item.copyright_reward, item.related_rights_reward, item.total_reward,
            item.licensor_code, item.contract_id
        ])

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename=report.pdf'

    doc = SimpleDocTemplate(
        response, pagesize=landscape(A4), leftMargin=15, rightMargin=15, topMargin=15, bottomMargin=15
    )

    FONT_SIZE = 3
    styles = getSampleStyleSheet()

    style_normal = ParagraphStyle(
        'Normal', parent=styles['Normal'], fontName="Inter-Regular", fontSize=FONT_SIZE,
        leading=FONT_SIZE + 1, alignment=TA_CENTER, textColor=colors.black,
        spaceBefore=0, spaceAfter=0, leftIndent=0, rightIndent=0,
    )

    style_header = ParagraphStyle(
        'Header', parent=styles['Normal'], fontName="Inter-Regular", fontSize=FONT_SIZE,
        leading=FONT_SIZE + 1, alignment=TA_CENTER, textColor=colors.black,
        spaceBefore=0, spaceAfter=0, leftIndent=0, rightIndent=0,
    )

    table_data = []
    for row_idx, row in enumerate(data):
        new_row = []
        for cell in row:
            p = Paragraph(str(cell), style_header if row_idx == 0 else style_normal)
            new_row.append(p)
        table_data.append(new_row)

    table = Table(table_data, repeatRows=1, hAlign='LEFT', colWidths=None)
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), "rgb(230, 230, 230)"),
        ('FONT', (0, 0), (-1, -1), 'Inter-Regular'),
        ('FONTSIZE', (0, 0), (-1, 0), FONT_SIZE),
        ('FONTSIZE', (0, 1), (-1, -1), FONT_SIZE),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 1),
        ('RIGHTPADDING', (0, 0), (-1, -1), 1),
        ('TOPPADDING', (0, 0), (-1, -1), 1),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.black)
    ])
    table.setStyle(style)
    doc.build([table])
    return response


# =======================================================


# ================== Экспорт отчетов ====================
@login_required(login_url='login')
def export_report(request):
    if request.method != 'POST':
        return HttpResponse(status=400)

    # строим фильтры ТОЛЬКО по полям RoyaltyStatement
    mp = request.POST.getlist('music_platforms')   # площадки
    a  = request.POST.getlist('artists')           # у нас в фильтре это performer (имя)
    r  = request.POST.getlist('releases')          # список UPC
    rp = request.POST.getlist('report_periods')    # ярлыки кварталов (usage_period)

    qs = _apply_access(request, RoyaltyStatement.objects.all())
    if qs is None:
        return HttpResponse(status=204)

    if mp:
        qs = qs.filter(music_platform__in=mp)

    if a:
        # в старом фронте "artists" — это имена исполнителей
        qs = qs.filter(performer__in=a)
    else:
        # если пользователь не выбрал конкретных артистов — оставим только своих,
        # _apply_access уже сузил набор; дополнительного фильтра не требуется
        pass

    if r:
        qs = qs.filter(album_UPC__in=r)

    if rp:
        # ключевое: экспортим только выбранные кварталы (usage_period)
        qs = qs.filter(usage_period__in=rp)

    file_format = request.POST.get('file_format')

    if file_format == 'xls':
        return export_report_to_excel(qs)
    elif file_format == 'pdf':
        return export_report_to_pdf(qs)

    return HttpResponse(status=400)



# =======================================================


# ================== Страницы ===========================
def news(request):
    return render(request, "index.html", {"pattern": "news"})


def instruction(request):
    return render(request, "index.html", {"pattern": "instruction"})


# =======================================================


# ================== Promotion / плейлисты ==============
@staff_member_required
def promotion_all(request):
    cleaned_search_query = None
    global_playlists = GlobalPlaylist.objects.all().order_by('-id')[:100]
    count_global_playlists = GlobalPlaylist.objects.all().count()
    personal_playlists_id = PersonalPlaylist.objects.filter(user=request.user).values_list('global_playlist', flat=True)
    search_playlists_form = SearchPlaylistsForm()
    if request.method == "POST":
        form_name = request.POST.get('form_name')
        if form_name == 'search_playlists':
            search_playlists_form = SearchPlaylistsForm(request.POST or None)
            if search_playlists_form.is_valid():
                search_query = search_playlists_form.cleaned_data['search_query']
                cleaned_search_query = ""
                for i in search_query:
                    if (i == " " and (not cleaned_search_query or cleaned_search_query[-1] != " ")) or i != " ":
                        cleaned_search_query += i
                cleaned_search_query = cleaned_search_query.lower()

                global_playlists = GlobalPlaylist.objects.filter(
                    Q(keywords__keyword__icontains=cleaned_search_query) |
                    Q(name__icontains=cleaned_search_query)
                ).annotate(
                    match_priority=Case(
                        When(name__icontains=cleaned_search_query, then=1),
                        When(keywords__keyword__icontains=cleaned_search_query, then=2),
                        default=3,
                        output_field=IntegerField()
                    )
                ).order_by('match_priority', '-id')

                task = add_global_playlists.delay(cleaned_search_query)
                request.session['task_id'] = task.id

    return render(request, 'index.html', {
        'pattern': 'promotion_all',
        'global_playlists': global_playlists,
        'count_global_playlists': count_global_playlists,
        'personal_playlists_id': personal_playlists_id,
        'cleaned_search_query': cleaned_search_query,
        'search_playlists_form': search_playlists_form
    })


def playlists_api(request):
    list_type = request.GET.get('type')
    page_num = int(request.GET.get('page', 1))
    if list_type == 'global':
        objects = GlobalPlaylist.objects.all().order_by('-id')
    elif list_type == 'new':
        objects = GlobalPlaylist.objects.all().order_by('-id')
    else:
        return JsonResponse({'error': 'Unknown type'}, status=400)

    paginator = Paginator(objects, 100)
    page_obj = paginator.get_page(page_num)
    items = list(page_obj.object_list.values())
    return JsonResponse({
        'items': items,
        'page': page_obj.number,
        'has_next': page_obj.has_next(),
        'has_previous': page_obj.has_previous(),
    })


@staff_member_required
def delete_all_global_playlists(request):
    GlobalPlaylist.objects.all().delete()
    return JsonResponse({'status': 'All GlobalPlaylists deleted'})


def promotion_all_task_status(request, task_id):
    task = AsyncResult(task_id)
    return JsonResponse({'status': task.status})


def promotion_all_async(request):
    playlists = GlobalPlaylist.objects.filter(is_added_last=True).order_by('-id')
    data = {'new_playlists': serializers.serialize('python', playlists, use_natural_foreign_keys=True)}
    del request.session['task_id']
    return JsonResponse(data)


@csrf_exempt
@login_required
def add_global_playlists_in_personal(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            playlists_id = data.get('global_playlists_id', [])
            global_playlists = GlobalPlaylist.objects.filter(id__in=playlists_id)
            created_count = 0
            for global_playlist in global_playlists:
                if not PersonalPlaylist.objects.filter(user=request.user, global_playlist=global_playlist).exists():
                    PersonalPlaylist.objects.create(user=request.user, global_playlist=global_playlist)
                    created_count += 1
            return JsonResponse({
                'status': 'success',
                'message': f'Добавлено {created_count} global-плейлистов в personal-плейлисты'
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Неверный метод запроса'})


# =======================================================


# ================== Promotion personal =================
@staff_member_required
def promotion_personal(request, page_number=1):
    personal_playlists = PersonalPlaylist.objects.filter(user=request.user).order_by('-id')[:100]

    sort_field = request.GET.get('sort', 'id')
    sort_direction = request.GET.get('direction', 'asc')
    order_field = sort_field if sort_direction == 'asc' else f'-{sort_field}'

    playlists = Playlists.objects.all().order_by(order_field)

    if request.method == "GET":
        add_playlist_form = AddPlaylistForm()
        playlists_filter_form = PlaylistsFilterForm(request.GET or None)
        if playlists_filter_form.is_valid():
            if (playlist_name := playlists_filter_form.cleaned_data.get('p_name')):
                playlists = playlists.filter(name__icontains=playlist_name)
            if (author_link := playlists_filter_form.cleaned_data.get('a_link')):
                playlists = playlists.filter(author_link__icontains=author_link)
            if (count_auditions_6_hours := playlists_filter_form.cleaned_data.get('ca6h')):
                playlists = playlists.filter(hour6__gte=count_auditions_6_hours)
            if (count_auditions_1_day := playlists_filter_form.cleaned_data.get('ca1d')):
                playlists = playlists.filter(day1__gte=count_auditions_1_day)
            if (count_auditions_1_week := playlists_filter_form.cleaned_data.get('ca1w')):
                playlists = playlists.filter(week1__gte=count_auditions_1_week)
            if (count_auditions_1_month := playlists_filter_form.cleaned_data.get('ca1m')):
                playlists = playlists.filter(month1__gte=count_auditions_1_month)
            if (activity := playlists_filter_form.cleaned_data.get('ac')):
                playlists = playlists.filter(activity__icontains=activity)
            if (themes := playlists_filter_form.cleaned_data.get('th')):
                playlists = playlists.filter(themes__icontains=themes)
            if (is_active := playlists_filter_form.cleaned_data.get('is_a')):
                playlists = playlists.filter(is_active=is_active)

    elif request.method == "POST":
        playlists_filter_form = PlaylistsFilterForm()
        add_playlist_form = AddPlaylistForm(request.POST or None)
        if add_playlist_form.is_valid():
            Playlists.objects.create(
                playlist_link=request.POST.get('pl_link'),
                price=request.POST.get('price'),
                themes=request.POST.get('th'),
                is_active=True
            )
            add_playlist_form = AddPlaylistForm()

    paginator = Paginator(playlists, 100)
    page_obj = paginator.get_page(page_number)

    filter_params = request.GET.copy()
    for k in ('sort', 'direction', 'page'):
        if k in filter_params:
            del filter_params[k]
    filter_params_str = filter_params.urlencode()

    return render(request, 'index.html', {
        'pattern': 'promotion_admin',
        'personal_playlists': personal_playlists,
        'playlists_filter_form': playlists_filter_form,
        'add_playlist_form': add_playlist_form,
        'page_obj': page_obj,
        'filter_params': filter_params_str,
        'current_sort': sort_field,
        'current_direction': sort_direction
    })


# =======================================================


# ================== Экспорт плейлистов =================
@login_required(login_url='login')
def export_playlists(request):
    if request.method == 'POST':
        sort_field = request.POST.get('sort')
        sort_direction = request.POST.get('direction')
        order_field = sort_field if sort_direction == 'asc' else f'-{sort_field}'
        playlists = Playlists.objects.all().order_by(order_field)

        playlist_name = request.POST.get('p_name')
        author_link = request.POST.get('a_link')
        count_auditions_6_hours = request.POST.get('ca6h')
        count_auditions_1_day = request.POST.get('ca1d')
        count_auditions_1_week = request.POST.get('ca1w')
        count_auditions_1_month = request.POST.get('ca1m')
        activity = request.POST.get('ac')
        themes = request.POST.get('th')
        is_active = request.POST.get('is_a')

        if playlist_name:
            playlists = playlists.filter(name__icontains=playlist_name)
        if author_link:
            playlists = playlists.filter(author_link__icontains=author_link)
        if count_auditions_6_hours:
            playlists = playlists.filter(hour6__gte=count_auditions_6_hours)
        if count_auditions_1_day:
            playlists = playlists.filter(day1__gte=count_auditions_1_day)
        if count_auditions_1_week:
            playlists = playlists.filter(week1__gte=count_auditions_1_week)
        if count_auditions_1_month:
            playlists = playlists.filter(month1__gte=count_auditions_1_month)
        if activity:
            playlists = playlists.filter(activity__icontains=activity)
        if themes:
            playlists = playlists.filter(themes__icontains=themes)
        if is_active:
            playlists = playlists.filter(is_active=is_active)

        file_format = request.POST.get('file_format')

        if file_format == 'csv':
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="playlists.csv"'
            writer = csv.writer(response)
            writer.writerow(['id', 'name', 'author_link', 'playlist_link', 'price', 'coefficient', 'status', 'comment',
                             'hour6', 'day1', 'week1', 'month1', 'themes', 'activity', 'problems', 'is_active'])
            for playlist in playlists:
                writer.writerow([
                    playlist.id, playlist.name, playlist.author_link, playlist.playlist_link, playlist.price,
                    playlist.coefficient, playlist.status, playlist.comment,
                    playlist.hour6, playlist.day1, playlist.week1, playlist.month1,
                    playlist.themes, playlist.activity, playlist.problems, playlist.is_active
                ])
            return response

        elif file_format == 'xls':
            response = HttpResponse(content_type='application/ms-excel')
            response['Content-Disposition'] = 'attachment; filename="playlists.xlsx"'
            wb = Workbook()
            ws = wb.active
            ws.append(['id', 'name', 'author_link', 'playlist_link', 'price', 'coefficient', 'status', 'comment',
                       'hour6', 'day1', 'week1', 'month1', 'themes', 'activity', 'problems', 'is_active'])
            for playlist in playlists:
                ws.append([
                    playlist.id, playlist.name, playlist.author_link, playlist.playlist_link, playlist.price,
                    playlist.coefficient, playlist.status, playlist.comment,
                    playlist.hour6, playlist.day1, playlist.week1, playlist.month1,
                    playlist.themes, playlist.activity, playlist.problems, playlist.is_active
                ])
            wb.save(response)
            return response

    return HttpResponse(status=400)


# =======================================================


# ================== Ваши релизы / модерация ============
@login_required(login_url='login')
def your_music(request):
    user = request.user
    base_qs = Release.objects.all() if user.is_staff else Release.objects.filter(user=user)

    active = request.GET.get('status', 'approved')
    if active not in {'approved', 'draft', 'moderation', 'changes'}:
        active = 'approved'

    status_map = {
        'approved': ReleaseStatus.APPROVED,
        'draft': ReleaseStatus.DRAFT,
        'moderation': ReleaseStatus.MODERATION,
        'changes': ReleaseStatus.CHANGES,
    }
    releases = base_qs.filter(status=status_map[active])

    q = (request.GET.get('q') or '').strip()
    start = request.GET.get('start')
    end = request.GET.get('end')

    if q:
        releases = _apply_release_query_filter(releases, q)

    def parse_d(s):
        try:
            return datetime.strptime(s, '%Y-%m-%d').date()
        except Exception:
            return None

    d1, d2 = parse_d(start), parse_d(end)
    if d1 and d2:
        releases = releases.filter(
            Q(release_date__range=(d1, d2)) |
            Q(start_date__range=(d1, d2))
        )

    releases = releases.order_by('-id')

    counts = {
        'approved': base_qs.filter(status=ReleaseStatus.APPROVED).count(),
        'draft': base_qs.filter(status=ReleaseStatus.DRAFT).count(),
        'moderation': base_qs.filter(status=ReleaseStatus.MODERATION).count(),
        'changes': base_qs.filter(status=ReleaseStatus.CHANGES).count(),
    }

    return render(request, "index.html", {
        "pattern": "your_music",
        "releases": releases,
        "active_status": active,
        "counts": counts,
        "page_title": {
            'approved': 'Все релизы',
            'draft': 'Черновики',
            'moderation': 'Модерация',
            'changes': 'Требуются изменения',
        }[active],
    })


@login_required(login_url='login')
def submit_release_to_moderation(request):
    if request.method != 'POST':
        return redirect('new_release')

    rid = request.session.get('current_release_id')
    if not rid:
        return redirect(reverse('your_music') + '?status=draft')

    release = get_object_or_404(Release, id=rid, user=request.user)
    data = request.POST

    def parse_date(s):
        for fmt in ('%d.%m.%Y', '%Y-%m-%d'):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                pass
        return None

    changed = []

    def set_if(field_name, attr=None, transform=lambda v: v):
        v = data.get(field_name)
        if v not in (None, ''):
            setattr(release, attr or field_name, transform(v))
            changed.append(attr or field_name)

    set_if('language_metadata')
    set_if('album_title')
    set_if('album_subtitle')
    set_if('type_release')
    set_if('genre')
    set_if('subgenre')
    set_if('album_UPC')

    set_if('cover')
    set_if('cover', 'cover_thumbnail')

    rd = parse_date(data.get('release_date', ''))
    if rd:
        release.release_date = rd;
        changed.append('release_date')
    sd = parse_date(data.get('start_date', ''))
    if sd:
        release.start_date = sd;
        changed.append('start_date')

    if changed:
        release.save(update_fields=changed)
    release.status = ReleaseStatus.MODERATION
    release.save(update_fields=['status'])

    try:
        del request.session['current_release_id']
    except KeyError:
        pass

    return redirect(reverse('your_music') + '?status=moderation')


# --- MODERATION ENDPOINTS ---
@login_required(login_url='login')
@require_POST
@user_passes_test(is_manager)
def release_approve(request, pk: int):
    """Менеджер утверждает релиз. Опционально присваивает/подтверждает UPC."""
    release = get_object_or_404(Release, pk=pk)

    upc = (request.POST.get('album_UPC') or '').strip()
    if upc:
        if not UPC_RE.match(upc):
            return JsonResponse({"ok": False, "error": "Неверный формат UPC (нужны 8–14 цифр)."}, status=400)
        release.album_UPC = upc

    release.status = ReleaseStatus.APPROVED
    release.moderation_comment = None
    fields = ['status', 'moderation_comment'] + (['album_UPC'] if upc else [])
    release.save(update_fields=fields)

    return JsonResponse({
        "ok": True,
        "id": release.id,
        "status": release.status,
        "album_UPC": release.album_UPC or ""
    })


@login_required(login_url='login')
@require_POST
@user_passes_test(is_manager)
def release_request_changes(request, pk: int):
    """Менеджер отправляет релиз на доработку с комментарием."""
    release = get_object_or_404(Release, pk=pk)

    comment = (request.POST.get('comment') or '').strip()
    release.status = ReleaseStatus.CHANGES
    release.moderation_comment = comment or None
    release.save(update_fields=['status', 'moderation_comment'])

    return JsonResponse({
        "ok": True,
        "id": release.id,
        "status": release.status,
        "comment": release.moderation_comment or ""
    })


# --- DELETE RELEASE (owner or staff) ---
@login_required(login_url='login')
@require_POST
def release_delete(request, pk: int):
    """
    Удаление релиза: владелец может удалить свои релизы, staff — любые.
    Если нужно «мягкое» удаление — позже заменим на смену статуса.
    """
    qs = Release.objects.all()
    if not request.user.is_staff:
        qs = qs.filter(user=request.user)

    release = get_object_or_404(qs, pk=pk)
    release.delete()
    return JsonResponse({"ok": True, "id": pk})


## =================================================================================
# ====== Analytics API (ПОЛНЫЙ БЛОК) =============================================
# =================================================================================
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse, HttpResponse
from django.db import connection
from django.db.models import Q, Sum, Value, IntegerField, F, Case, When
from django.db.models.functions import Cast, Coalesce
from django.utils import timezone
from django.utils.dateparse import parse_date

from datetime import datetime, timedelta
import pandas as pd
import re

# Модели
from app.models import Artist, Release, Report, StreamFact, RoyaltyStatement



# ===== Роли =====================================================================
def is_manager(user):
    return user.is_staff or user.is_superuser


# ===== Хелперы: даты/колонки/фильтры ===========================================
# --- ДОБАВЬ где лежат хелперы для аналитики ---
def _field_name(model, candidates):
    """Возвращает ПОЛЕ МОДЕЛИ (ORM), а не имя колонки БД."""
    fields = {f.name for f in model._meta.get_fields() if hasattr(f, "attname")}
    for c in candidates:
        if c in fields:
            return c
    return None

def normalize_date_like(s):
    """К 'YYYY-MM-DD' из 'DD.MM.YYYY' / Excel-номера и т.п."""
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return None
    s = str(s).strip()
    if not s:
        return None
    try:
        dt = pd.to_datetime(s, dayfirst=True, errors='coerce')
        if not pd.isna(dt):
            return dt.strftime('%Y-%m-%d')
    except Exception:
        pass
    try:
        if re.match(r'^\d+(\.\d+)?$', s):
            num = float(s)
            dt = pd.to_datetime('1899-12-30') + pd.to_timedelta(num, unit='D')
            if pd.Timestamp('1970-01-01') < dt < pd.Timestamp('2050-01-01'):
                return dt.strftime('%Y-%m-%d')
    except Exception:
        pass
    return s


def _parse_range(request):
    """Вернёт (dt_from, dt_to, 'YYYY-MM-DD', 'YYYY-MM-DD')."""
    today = timezone.localdate()
    default_from = today - timedelta(days=30)
    dt_from_str = (request.GET.get('from') or default_from.strftime('%Y-%m-%d')).strip()
    dt_to_str = (request.GET.get('to') or today.strftime('%Y-%m-%d')).strip()

    dt_from = parse_date(dt_from_str) or default_from
    dt_to = parse_date(dt_to_str) or today
    if dt_from > dt_to:
        dt_from, dt_to = dt_to, dt_from
        dt_from_str, dt_to_str = dt_to_str, dt_from_str
    return dt_from, dt_to, dt_from_str, dt_to_str

def _date_keys_range(dt_from, dt_to):
    """
    Возвращает список строковых ключей дат на каждый день диапазона
    в обоих форматах: 'YYYY-MM-DD' и 'DD.MM.YYYY'.
    """
    keys = []
    d = dt_from
    while d <= dt_to:
        keys.append(d.strftime('%Y-%m-%d'))  # ISO
        keys.append(d.strftime('%d.%m.%Y'))  # RU
        d += timedelta(days=1)
    return keys
def _day_keys(dt_from, dt_to):
    """Вернёт два набора строк дат для фильтрации: ISO и DMY."""
    iso, dmy = [], []
    d = dt_from
    while d <= dt_to:
        iso.append(d.strftime('%Y-%m-%d'))
        dmy.append(d.strftime('%d.%m.%Y'))
        d += timedelta(days=1)
    return set(iso), set(dmy)

def _norm_date_key_to_iso(s: str) -> str | None:
    """Ставит ключ даты в канон ISO 'YYYY-MM-DD' (поддерживает 'DD.MM.YYYY')."""
    s = (s or '').strip()
    for fmt in ('%Y-%m-%d', '%d.%m.%Y'):
        try:
            return datetime.strptime(s, fmt).strftime('%Y-%m-%d')
        except Exception:
            pass
    return None
def _db_columns(model):
    """Список реальных колонок таблицы в БД (а не только в модели)."""
    try:
        with connection.cursor() as cur:
            return {c.name for c in connection.introspection.get_table_description(
                cur, model._meta.db_table
            )}
    except Exception:
        return set()


def _field_name_db(model, candidates):
    """Имя первого поля из candidates, реально существующего в БД."""
    cols = _db_columns(model)
    for c in candidates:
        if c in cols:
            return c
    return None


# ===== НОРМАЛИЗАЦИЯ ПЛОЩАДОК (исправлено) ======================================
def _platform_q(pl: str) -> Q:
    """
    Возвращает Q-фильтр по колонке music_platform, используя централизованный
    словарь PLATFORM_ALIASES для поиска по синонимам.
    """
    slug = (pl or "").strip().lower()

    if not slug or slug in {"все", "all"}:
        return Q()

    # Получаем список поисковых слов из словаря по slug'у
    # Если slug'а в словаре нет, ищем по самому slug'у на всякий случай
    search_tokens = PLATFORM_ALIASES.get(slug, [slug])

    # Строим Q-объект, который ищет по любому из синонимов
    q_filter = Q()
    for token in search_tokens:
        q_filter |= Q(music_platform__icontains=token)

    return q_filter

def _apply_access(request, qs):
    """Ограничения по правам: артисты/UPC конкретного пользователя."""
    if request.user.is_staff or request.user.is_superuser:
        return qs
    my_artists = list(Artist.objects.filter(user=request.user).values_list('name', flat=True))
    my_upcs = [u for u in Release.objects.filter(user=request.user).values_list('album_UPC', flat=True) if u]
    cond = Q()
    if my_artists:
        cond |= Q(performer__in=my_artists)
    if my_upcs:
        cond |= Q(album_UPC__in=my_upcs)
    if not cond:
        return None  # нет доступа ни к чему
    return qs.filter(cond)


def _apply_search_and_platform(qs, platform: str, query: str):
    """
    Накладывает текстовый поиск (по артисту/трекам/кодам) и фильтр по площадке.
    """
    # Поиск
    if (query or '').strip():
        qs = qs.filter(
            Q(performer__icontains=query) |
            Q(track_title__icontains=query) |
            Q(album_title__icontains=query) |
            Q(ISRC__icontains=query) |
            Q(album_UPC__icontains=query)
        )

    # Фильтр по площадке — всегда через единый нормализатор
    p = (platform or '').strip().lower()
    if p and p not in {'все', 'all'}:
        qs = qs.filter(_platform_q(platform))

    return qs


def _ts_ms(d):
    return int(datetime(d.year, d.month, d.day, tzinfo=timezone.utc).timestamp() * 1000)


# ===== СВОДКА (все прослушивания + >30 сек) ====================================
@login_required(login_url='login')
@require_http_methods(["GET"])
def analytics_summary(request):
    """
    Сводный график (all vs >30 сек) теперь берёт данные из StreamFact.
    """
    # — отладка, как и раньше —
    platform_from_request = request.GET.get('platform', 'НЕ ПОЛУЧЕНО')
    print(f"--- DEBUG ANALYTICS --- Получена платформа: '{platform_from_request}'")

    # Диапазон дат и базовые параметры
    dt_from, dt_to, dt_from_str, dt_to_str = _parse_range(request)
    query    = (request.GET.get('q') or '').strip()
    platform = (request.GET.get('platform') or '').strip()

    # Доступ на уровне пользователя (по артистам/UPC)
    qs = _apply_access(request, StreamFact.objects.all())
    if qs is None:
        return HttpResponse(status=204)

    # Фильтр по датам: по day (DateField) ИЛИ по строковым ключам usage_period
    date_keys = _date_keys_range(dt_from, dt_to)
    base = qs.filter(
        Q(day__range=(dt_from, dt_to)) | Q(usage_period__in=date_keys)
    )

    # Поиск (артист/трек/альбом/ISRC/UPC) + площадка
    base = _apply_search_and_platform(base, platform, query)

    # Агрегаты: отдельно all и отдельно >30 (gt30/paid_30)
    sall_qs = base.filter(usage_type='all').values('day', 'usage_period').annotate(
        v=Sum(Cast(Coalesce('usage_count', Value(0)), IntegerField()))
    )
    s30_qs = base.filter(usage_type__in=['gt30', 'paid_30']).values('day', 'usage_period').annotate(
        v=Sum(Cast(Coalesce('usage_count', Value(0)), IntegerField()))
    )

    # Перегоняем в "карты" дата(YYYY-MM-DD) -> значение
    def rows_to_map(rows):
        m = {}
        for r in rows:
            day = r.get('day')
            if day:
                key = day.strftime('%Y-%m-%d')
            else:
                key = _norm_date_key_to_iso(r.get('usage_period') or '')
                if not key:
                    continue
            m[key] = int(r.get('v') or 0)
        return m

    m_all = rows_to_map(sall_qs)
    m_30  = rows_to_map(s30_qs)

    # Ровная ось X по каждому дню диапазона
    d = dt_from
    s_all, s_gt, t_all, t_30 = [], [], 0, 0
    while d <= dt_to:
        key = d.strftime('%Y-%m-%d')
        ts  = _ts_ms(d)
        y_all = int(m_all.get(key, 0))
        y_30  = int(m_30.get(key, 0))
        s_all.append({"x": ts, "y": y_all})
        s_gt.append({"x": ts, "y": y_30})
        t_all += y_all
        t_30  += y_30
        d += timedelta(days=1)

    if not (t_all or t_30):
        return HttpResponse(status=204)

    return JsonResponse({
        "series": [
            {"name": ">30 сек", "data": s_gt},
            {"name": "Все прослушивания", "data": s_all},
        ],
        "totals": {"s30": t_30, "sall": t_all}
    })



# ===== ИМПОРТ/ЗАМЕНА ДАННЫХ =====================================================
# ===== ИМПОРТ/ЗАМЕНА ДАННЫХ =====================================================
@login_required(login_url='login')
@user_passes_test(is_manager)
@require_http_methods(["POST"])
def analytics_upload_streams(request):
    """
    Импорт прослушиваний в StreamFact.
    Поддерживает CSV/Excel. Ищет колонки (любые разумные синонимы):
      дата/период, платформа, артист, альбом, UPC, трек, ISRC,
      все_прослушивания, платные(>30), пол, возраст, ОС, устройство, страна.

    Алгоритм:
      1) читаем файл в DataFrame, нормализуем имена колонок
      2) для каждой строки определяем ключ даты (ISO 'YYYY-MM-DD'), плюс параллельно day (date)
      3) копим по ключу агрегаты all / paid
      4) в транзакции удаляем старые StreamFact по этим датам и bulk_create новых
    """
    # 1) файл
    f = request.FILES.get('file') or request.FILES.get('report_file')
    if not f:
        return JsonResponse({"ok": False, "error": "Не загружен файл."}, status=400)

    name = (f.name or "").lower()
    try:
        if name.endswith(".csv"):
            try:
                df = pd.read_csv(f, dtype=str)
            except UnicodeDecodeError:
                f.seek(0)
                df = pd.read_csv(f, dtype=str, encoding='cp1251')
        else:
            df = pd.read_excel(f, dtype=str)
    except Exception as e:
        return JsonResponse({"ok": False, "error": f"Ошибка чтения файла: {e}"}, status=400)

    original_cols = list(df.columns)
    df.columns = (
        df.columns.astype(str).str.strip().str.lower()
          .str.replace(r'[\s\./,]+', '_', regex=True).str.strip('_')
    )

    # 2) поиски колонок
    def find_col(regexes):
        for c in df.columns:
            for rg in regexes:
                if re.search(rg, c, flags=re.IGNORECASE):
                    return c
        return None

    def parse_int(v):
        if pd.isna(v) or v is None:
            return 0
        try:
            s = str(v).replace(' ', '').replace('\u00A0', '').replace(',', '.')
            return int(float(s))
        except Exception:
            return 0

    col_date   = find_col([r'^(дата|date|day|день|data|дата_отчета|дата_прослушиваний)$'])
    col_period = find_col([r'^(период|usage_period|period|период_использования_контента|месяц|month)$'])
    if not (col_date or col_period):
        return JsonResponse({"ok": False, "error": "Не найдена колонка даты/периода.",
                             "columns_found": list(df.columns), "columns_original": original_cols}, status=400)

    cols = set(df.columns)
    col_all = ('все_прослушивания' if 'все_прослушивания' in cols else None) \
              or find_col([r'^(все_?прослушивания|total_?streams?|all_?streams?|total_?plays?|all_?plays?)$'])
    col_paid = ('платные_прослушивания' if 'платные_прослушивания' in cols else None) \
               or find_col([r'(?:^|_)(?:>|gt|over|more|greater)?_?30(?:_?sec|_?сек)?',
                            r'(?:^|.*)(30|>_?30).*сек', r'paid_?streams?', r'streams?_?30'])
    if not (col_all or col_paid):
        col_all = find_col([r'^(все_?прослушивания|прослушивания|usage_count|count|streams?|plays?)$'])
    if not (col_all or col_paid):
        return JsonResponse({"ok": False, "error": "Нет колонок с прослушиваниями (all/paid)."}, status=400)

    col_plat   = ('площадка' if 'площадка' in cols else None) \
                 or find_col([r'^(music_?platform|platform|платформа|сервис|store|service|канал)$'])
    col_artist = find_col([r'^(артист|исполнитель|artist|performer)$'])
    col_album  = find_col([r'^(альбом|album|release|release_title)$'])
    col_upc    = find_col([r'^(upc|album_?upc|штрихкод|баркод)$'])
    col_track  = find_col([r'^(название|трек|track(_?title)?|title|song)$'])
    col_isrc   = find_col([r'^isrc$'])

    col_gender  = find_col([r'^(пол|gender|sex)$'])
    col_age     = find_col([r'^(возраст|age|age_group|age_range)$'])
    col_os      = find_col([r'^(операционная_система|os|operating_system|os_name)$'])
    col_device  = find_col([r'^(тип_устройства|device|device_type|client_device)$'])
    col_country = find_col([r'^(страна|территория|country|country_name|geo|region)$'])

    # 3) агрегируем по ключу (дата+атрибуты)
    per_key   = {}
    seen_iso  = set()

    for _, row in df.iterrows():
        # дата в ISO (используем normalize_date_like из этого же блока Analytics API)
        dkey = None
        if col_date and pd.notna(row.get(col_date)):
            dkey = normalize_date_like(row.get(col_date))   # -> 'YYYY-MM-DD' если удачно
        if not dkey and col_period and pd.notna(row.get(col_period)):
            dkey = normalize_date_like(row.get(col_period))
        if not dkey:
            continue
        dkey = str(dkey).strip()
        if not dkey:
            continue
        seen_iso.add(dkey)

        platform = (str(row.get(col_plat))   if col_plat   and pd.notna(row.get(col_plat))   else '').strip()
        artist   = (str(row.get(col_artist)) if col_artist and pd.notna(row.get(col_artist)) else '').strip()
        album    = (str(row.get(col_album))  if col_album  and pd.notna(row.get(col_album))  else '').strip()
        upc      = (str(row.get(col_upc))    if col_upc    and pd.notna(row.get(col_upc))    else '').strip()
        track    = (str(row.get(col_track))  if col_track  and pd.notna(row.get(col_track))  else '').strip()
        isrc_val = (str(row.get(col_isrc))   if col_isrc   and pd.notna(row.get(col_isrc))   else '').strip()
        if isrc_val.endswith('.0'):
            isrc_val = isrc_val[:-2]
        isrc_val = isrc_val.replace(' ', '').upper()

        gender  = (str(row.get(col_gender))  if col_gender  and pd.notna(row.get(col_gender))  else '').strip()
        age     = (str(row.get(col_age))     if col_age     and pd.notna(row.get(col_age))     else '').strip()
        osname  = (str(row.get(col_os))      if col_os      and pd.notna(row.get(col_os))      else '').strip()
        device  = (str(row.get(col_device))  if col_device  and pd.notna(row.get(col_device))  else '').strip()
        country = (str(row.get(col_country)) if col_country and pd.notna(row.get(col_country)) else '').strip()

        v_all  = parse_int(row.get(col_all))  if col_all  else 0
        v_paid = parse_int(row.get(col_paid)) if col_paid else 0
        if v_paid > v_all and v_all > 0:
            v_paid = v_all
        if v_all <= 0 and v_paid <= 0:
            continue

        key = (dkey, platform, artist, album, upc, track, isrc_val, gender, age, osname, device, country)
        bucket = per_key.setdefault(key, {'all': 0, 'paid': 0})
        bucket['all']  += max(v_all, 0)
        bucket['paid'] += max(min(v_paid, v_all), 0)

    if not per_key:
        return JsonResponse({"ok": False, "error": "В файле нет пригодных строк."}, status=400)

    # 4) формируем объекты StreamFact
    to_create = []
    for (iso, platform, artist, album, upc, track, isrc_val, gender, age, osname, device, country), vals in per_key.items():
        d_obj = parse_date(iso)  # date | None — в StreamFact.day можно null, но лучше дата
        base = dict(
            day=d_obj,
            usage_period=iso,
            music_platform=platform,
            performer=artist,
            track_title=track,
            album_title=album,
            album_UPC=upc,
            ISRC=isrc_val,
            gender=gender,
            age_group=age,
            os_name=osname,
            device_type=device,
            territory=country,
        )
        if vals['all'] > 0:
            to_create.append(StreamFact(usage_type='all',  usage_count=int(vals['all']),  **base))
        if vals['paid'] > 0:
            to_create.append(StreamFact(usage_type='gt30', usage_count=int(vals['paid']), **base))  # >30 сек

    if not to_create:
        return JsonResponse({"ok": False, "error": "После агрегации — пусто."}, status=400)

    # 5) атомарная замена: удаляем StreamFact за эти даты и вставляем новые
    try:
        iso_list  = sorted(seen_iso)
        day_list  = [parse_date(x) for x in iso_list if parse_date(x)]

        from django.db.models import Q
        with transaction.atomic():
            StreamFact.objects.filter(Q(usage_period__in=iso_list) | Q(day__in=day_list)).delete()

            BATCH = 1000
            for i in range(0, len(to_create), BATCH):
                StreamFact.objects.bulk_create(to_create[i:i + BATCH], batch_size=BATCH)

        return JsonResponse({
            "ok": True,
            "inserted": len(to_create),
            "replaced_dates": iso_list,
        }, status=201)

    except Exception as e:
        return JsonResponse({"ok": False, "error": f"Ошибка сохранения: {e}"}, status=500)



# ===== ПЛАТНЫЕ ПО ПЛОЩАДКАМ (>30 сек) ==========================================
@login_required(login_url='login')
@require_http_methods(["GET"])
def analytics_platforms_paid(request):
    """
    Сравнение площадок по дням (берём только платные/ >30 сек) из StreamFact.
    ВНИМАНИЕ: как и раньше, здесь нарочно НЕ фильтруем по ?platform= —
    график сравнивает площадки между собой.
    """
    dt_from, dt_to, _, _ = _parse_range(request)

    qs = _apply_access(request, StreamFact.objects.all())
    if qs is None:
        return HttpResponse(status=204)

    date_keys = _date_keys_range(dt_from, dt_to)
    base = qs.filter(
        Q(day__range=(dt_from, dt_to)) | Q(usage_period__in=date_keys),
        usage_type__in=['gt30', 'paid_30']
    )

    raw = (
        base.values("music_platform", "day", "usage_period")
            .annotate(total=Sum(Cast(Coalesce("usage_count", Value(0)), IntegerField())))
    )

    # нормализация названий площадок (оставил как было)
    def norm_pl(name: str) -> str:
        t = (name or '').strip()
        tl = t.lower()
        if 'apple' in tl or 'itunes' in tl:   return 'Apple Music'
        if 'spotify' in tl:                   return 'Spotify'
        if 'deezer' in tl:                    return 'Deezer'
        if 'яндекс' in tl or 'yandex' in tl:  return 'Яндекс.Музыка'
        if 'vk' in tl or 'вк' in tl or 'вконтакт' in tl:
            return 'ВКонтакте'
        if 'сбер' in tl or 'звук' in tl or 'zvuk' in tl:
            return 'СберЗвук'
        if 'однокласс' in tl or tl == 'ok':   return 'Одноклассники'
        if 'мтс' in tl or 'mts' in tl:        return 'МТС Музыка'
        return t or 'Другое'

    # копим: {platform: {iso_day: value}}
    per_pl, totals = {}, {}
    for r in raw:
        day = r.get("day")
        if day:
            dkey = day.strftime('%Y-%m-%d')
        else:
            # запасной ключ из usage_period
            dkey = _norm_date_key_to_iso(r.get("usage_period") or '')
            if not dkey:
                continue
        pl = norm_pl(r.get("music_platform") or '')
        val = int(r.get("total") or 0)
        per_pl.setdefault(pl, {}).setdefault(dkey, 0)
        per_pl[pl][dkey] += val
        totals[pl] = totals.get(pl, 0) + val

    if not per_pl:
        return HttpResponse(status=204)

    # топ-8 площадок
    top_names = [name for name, _ in sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:8]]

    # ось дат и серии
    series = []
    d = dt_from
    dates = []
    while d <= dt_to:
        dates.append(d.strftime('%Y-%m-%d'))
        d += timedelta(days=1)

    for name in top_names:
        daymap = per_pl.get(name, {})
        pts = []
        for k in dates:
            y = int(daymap.get(k, 0))
            ymd = datetime.strptime(k, "%Y-%m-%d")
            pts.append({"x": _ts_ms(ymd), "y": y})
        series.append({"name": name, "data": pts})

    return JsonResponse({"series": series})



# ===== SEGMENTS API (>30 сек) ===================================================
@login_required(login_url='login')
@require_http_methods(["GET"])
def analytics_segments_paid(request):
    """
    Демография/ОС/устройства/гео для платных (>30 сек) из StreamFact.
    Поддерживает ?from, ?to, ?platform, ?q (поиск).
    """
    dt_from, dt_to, _, _ = _parse_range(request)
    platform = (request.GET.get('platform') or '').strip()
    query    = (request.GET.get('q') or '').strip()

    qs = _apply_access(request, StreamFact.objects.all())
    if qs is None:
        return HttpResponse(status=204)

    date_keys = _date_keys_range(dt_from, dt_to)
    qs = qs.filter(Q(day__range=(dt_from, dt_to)) | Q(usage_period__in=date_keys))
    qs = _apply_search_and_platform(qs, platform, query)
    qs = qs.filter(usage_type__in=['gt30', 'paid_30'])

    rows = (
        qs.values('age_group', 'gender', 'os_name', 'device_type', 'territory')
          .annotate(total=Sum(Cast(Coalesce('usage_count', Value(0)), IntegerField())))
    )

    # накопители
    cnt_age, cnt_os, cnt_device, cnt_geo = {}, {}, {}, {}
    cnt_gender = {"male": 0, "female": 0, "unknown": 0}

    def _norm_age_bucket(val):
        if not val: return "Неизвестно"
        s = str(val).strip().replace('—', '-').replace('–', '-')
        known = {
            '18-24':'18–24','25-34':'25–34','35-44':'35–44','45-54':'45–54',
            '55-64':'55–64','65+':'65+','<18':'<18','0-17':'<18'
        }
        return known.get(s, s)

    def _norm_gender(val):
        s = (str(val or '').strip().lower())
        if s in {"m","male","м","муж","мужчина","мужчины"}:   return "male"
        if s in {"f","female","ж","жен","женщина","женщины"}: return "female"
        return "unknown"

    def _norm_os(val):
        s = str(val or "").strip().lower()
        if "ios" in s or "iphone" in s or "ipad" in s: return "iOS"
        if "android" in s:                              return "Android"
        if "windows" in s or s.startswith("win"):       return "Windows"
        if "web" in s or "browser" in s or "брауз" in s:return "Веб-браузер"
        if "mac" in s:                                  return "MacOS"
        if "linux" in s:                                return "Linux"
        return "Остальные"

    def _norm_device(val):
        s = str(val or "").strip().lower()
        if "mobile" in s or "phone" in s or "смартф" in s or "моб" in s: return "Мобильное устройство"
        if "desktop" in s or "pc" in s or "computer" in s or "ноут" in s: return "Настольный ПК"
        if "tablet" in s or "планш" in s or "ipad" in s:                  return "Планшет"
        return "Остальное"

    def _topn_with_other(counter_dict, top=8, other_name="Прочее"):
        items = sorted(counter_dict.items(), key=lambda kv: kv[1], reverse=True)
        head = items[:top]
        tail = sum(v for _, v in items[top:])
        if tail > 0: head.append((other_name, tail))
        return head

    for r in rows:
        v = int(r.get("total") or 0)
        if v <= 0:
            continue
        ag = _norm_age_bucket(r.get('age_group'));    cnt_age[ag] = cnt_age.get(ag, 0) + v
        gn = _norm_gender(r.get('gender'));           cnt_gender[gn] = cnt_gender.get(gn, 0) + v
        os = _norm_os(r.get('os_name'));              cnt_os[os] = cnt_os.get(os, 0) + v
        dv = _norm_device(r.get('device_type'));      cnt_device[dv] = cnt_device.get(dv, 0) + v
        geo = (r.get('territory') or "Прочее").strip() or "Прочее"
        cnt_geo[geo] = cnt_geo.get(geo, 0) + v

    if not any((cnt_age, cnt_os, cnt_device, cnt_geo, cnt_gender)):
        return HttpResponse(status=204)

    # Возраст
    age_order = ["Неизвестно","<18","18–24","25–34","35–44","45–54","55–64","65+"]
    age_categories = [a for a in age_order if a in cnt_age] + [a for a in cnt_age.keys() if a not in age_order]
    age_data = [int(cnt_age.get(a, 0)) for a in age_categories]

    # Пол — доли
    total_paid = (sum(cnt_age.values()) if cnt_age else 0) or sum(cnt_gender.values()) or 0
    gender_share = {"male": 0, "female": 0, "unknown": 0}
    if total_paid > 0:
        gender_share = {
            "male": round(cnt_gender.get("male", 0) / total_paid, 3),
            "female": round(cnt_gender.get("female", 0) / total_paid, 3),
            "unknown": round(cnt_gender.get("unknown", 0) / total_paid, 3),
        }

    # ОС
    os_order = ["iOS","Android","Windows","Веб-браузер","MacOS","Linux","Остальные"]
    os_categories = [o for o in os_order if o in cnt_os] + [o for o in cnt_os.keys() if o not in os_order]
    os_data = [int(cnt_os.get(o, 0)) for o in os_categories]

    # Устройства
    device_order = ["Мобильное устройство","Настольный ПК","Планшет","Остальное"]
    device_labels = [d for d in device_order if d in cnt_device] + [d for d in cnt_device.keys() if d not in device_order]
    device_data = [int(cnt_device.get(d, 0)) for d in device_labels]

    # Гео
    geo_top = _topn_with_other(cnt_geo, top=8, other_name="Прочее")
    geo_categories = [k for k, _ in geo_top]
    geo_data = [int(v) for _, v in geo_top]

    return JsonResponse({
        "demography": {"categories": age_categories, "data": age_data, "gender": gender_share},
        "os": {"categories": os_categories, "data": os_data},
        "devices": {"labels": device_labels, "data": device_data},
        "geo": {"categories": geo_categories, "data": geo_data},
    })





# ===== РЕЛИЗЫ/ТРЕКИ (таблица) ===================================================
# GET /api/analytics/releases?from=YYYY-MM-DD&to=YYYY-MM-DD&platform=&q=&page=1&page_size=10
#     &order=s30|sall|title|artist&dir=asc|desc&mode=album|track
from django.db.models import Q, Sum, Value, IntegerField, F  # <- F добавлен


@login_required(login_url='login')
@require_http_methods(["GET"])
def analytics_releases(request):
    """
    Таблица «Релизы/Треки» из StreamFact.
    Параметры:
      from, to, page, page_size, order(s30|sall|title|artist), dir(asc|desc),
      platform ("Все" = без фильтра), q (поиск), mode("album"|"track")
    """
    from_iso = request.GET.get("from") or ""
    to_iso   = request.GET.get("to") or ""
    page     = max(int(request.GET.get("page", 1)), 1)
    page_sz  = max(min(int(request.GET.get("page_size", 10)), 200), 1)
    order    = (request.GET.get("order") or "s30").strip()
    platform = (request.GET.get("platform") or "").strip()
    q        = (request.GET.get("q") or "").strip()
    mode     = (request.GET.get("mode") or "album").lower()
    sort_dir = (request.GET.get("dir", "desc") or "desc").lower()
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"
    if order == "name":  # обратная совместимость
        order = "title"
    if mode not in ("album", "track"):
        mode = "album"

    qs = _apply_access(request, StreamFact.objects.all())
    if qs is None:
        return JsonResponse({"ok": True, "mode": mode, "page": 1, "page_size": page_sz, "total": 0, "rows": []})

    dt_from = parse_date(from_iso) if from_iso else None
    dt_to   = parse_date(to_iso)   if to_iso   else None
    if not dt_from or not dt_to or dt_from > dt_to:
        dt_from, dt_to, _, _ = _parse_range(request)

    date_keys = _date_keys_range(dt_from, dt_to)
    qs = qs.filter(Q(day__range=(dt_from, dt_to)) | Q(usage_period__in=date_keys))
    qs = _apply_search_and_platform(qs, platform, q)

    agg_s30  = Coalesce(Sum("usage_count", filter=Q(usage_type__in=["gt30", "paid_30"])), Value(0))
    agg_sall = Coalesce(Sum("usage_count", filter=Q(usage_type="all")), Value(0))

    if mode == "track":
        group = ["performer", "track_title", "ISRC"]
        title_field = "track_title"
    else:
        group = ["performer", "album_title", "album_UPC"]
        title_field = "album_title"

    qs = qs.values(*group).annotate(s30=agg_s30, sall=agg_sall)

    sort_map = {"title": title_field, "artist": "performer", "s30": "s30", "sall": "sall"}
    sort_key = sort_map.get(order, "s30")
    prefix = "" if sort_dir == "asc" else "-"

    if sort_key in ("s30", "sall"):
        other_metric = "sall" if sort_key == "s30" else "s30"
        qs = qs.order_by(prefix + sort_key, "-" + other_metric, title_field, "performer")
    else:
        qs = qs.order_by(prefix + sort_key, "performer", "-s30", "-sall")

    total = qs.count()
    start = (page - 1) * page_sz
    rows_qs = qs[start:start + page_sz]

    rows = []
    for r in rows_qs:
        rows.append({
            "performer":   r.get("performer") or "",
            "album":       r.get("album_title") or "",
            "upc":         r.get("album_UPC") or "",
            "track_title": r.get("track_title") or "",
            "isrc":        r.get("ISRC") or "",
            "s30":         int(r.get("s30") or 0),
            "sall":        int(r.get("sall") or 0),
        })

    return JsonResponse({"ok": True, "mode": mode, "page": page, "page_size": page_sz, "total": total, "rows": rows})



from django.db.models import Sum, Q  # эти импорты у вас уже есть выше; если нет — добавьте

@login_required(login_url='login')
def get_reports_table(request):
    """
    Таблица на странице Отчёты:
    - агрегируем RoyaltyStatement по релизам (album_UPC, album_title, performer)
    - считаем сумму прослушиваний (usage_count) и сумму заработка (total_reward)
    - применяем фильтры из querystring
    - поддерживаем постраничную загрузку
    Ответ:
      {
        "rows": [
          { "album_title": "...", "artist_name": "...", "total_streams": 123, "total_earnings": 456.78, "upc": "..." },
          ...
        ],
        "has_more": true|false
      }
    """
    # --- helpers ---
    def _list(name: str):
        vals = request.GET.getlist(name) or []
        # убираем пустые и служебное "Нет данных"
        return [v for v in vals if v and v != "Нет данных"]

    # пэйджинг
    try:
        page = max(1, int(request.GET.get("page", "1") or 1))
    except ValueError:
        page = 1
    try:
        page_size = int(request.GET.get("page_size", "20") or 20)
    except ValueError:
        page_size = 20
    page_size = max(1, min(100, page_size))
    offset = (page - 1) * page_size

    # базовый queryset с проверкой доступа
    qs = _apply_access(request, RoyaltyStatement.objects.all())
    if qs is None:
        return JsonResponse({"rows": [], "has_more": False})

    # --- фильтры из selectize ---
    music_platforms = _list("music_platforms")
    artists        = _list("artists")
    releases       = _list("releases")          # список UPC
    periods        = _list("report_periods")    # список usage_period

    if music_platforms:
        qs = qs.filter(music_platform__in=music_platforms)
    if artists:
        qs = qs.filter(performer__in=artists)
    if releases:
        qs = qs.filter(album_UPC__in=releases)
    if periods:
        qs = qs.filter(usage_period__in=periods)

    # --- агрегация по релизам ---
    grouped = (
        qs.values("album_UPC", "album_title", "performer")
          .annotate(
              total_streams=Sum("usage_count"),
              total_earnings=Sum("total_reward"),
          )
          .order_by("-total_earnings", "-total_streams", "album_title")
    )

    total_rows = grouped.count()
    slice_rows = list(grouped[offset:offset + page_size])

    # приведение типов для JSON
    rows = []
    for r in slice_rows:
        rows.append({
            "album_title":   r.get("album_title") or "",
            "artist_name":   r.get("performer") or "",
            "total_streams": int(r.get("total_streams") or 0),
            "total_earnings": float(r.get("total_earnings") or 0),
            "upc":           r.get("album_UPC") or "",
        })

    # сколько всего страниц
    total_pages = max(1, math.ceil(total_rows / page_size)) if total_rows else 1

    return JsonResponse({
        "rows": rows,
        "page": page,
        "page_size": page_size,
        "total": total_rows,
        "total_pages": total_pages,
        # оставим флаг для совместимости
        "has_more": page < total_pages,
    })

@transaction.atomic
def _sync_people_to_db(release, people):
    # people — список dict'ов: {"name", "role", "share", "ipi", "isni", "notes"}
    seen = set()
    for p in people:
        key = (p["name"].strip(), p["role"])
        seen.add(key)
        obj, _ = ReleasePerson.objects.update_or_create(
            release=release, name=key[0], role=key[1],
            defaults={
                "share": p.get("share"),
                "ipi": p.get("ipi") or "",
                "isni": p.get("isni") or "",
                "notes": p.get("notes") or "",
            },
        )
    # удалить то, чего больше нет на клиенте
    qs = ReleasePerson.objects.filter(release=release)
    for row in qs:
        if (row.name, row.role) not in seen:
            row.delete()
