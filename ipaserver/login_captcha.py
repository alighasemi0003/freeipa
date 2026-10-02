#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Offline SVG CAPTCHA for FreeIPA Web password login.

Challenges are generated and verified locally with the Python standard
library only. No external CAPTCHA services, CDNs, or network calls.
"""

from __future__ import absolute_import

import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
import time
import xml.sax.saxutils

from ipalib.constants import DEFAULT_CONFIG
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

_DEFAULTS = dict(DEFAULT_CONFIG)

ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
DEFAULT_TTL = int(_DEFAULTS.get('login_captcha_ttl', 120))
DEFAULT_LENGTH = int(_DEFAULTS.get('login_captcha_length', 6))
DEFAULT_ENABLED = bool(_DEFAULTS.get('login_captcha_enabled', True))

TTL_MIN = 30
TTL_MAX = 600
LENGTH_MIN = 4
LENGTH_MAX = 8
MAX_CHALLENGES_PER_IP = 20


def resolve_enabled(value=None):
    if value is None:
        return DEFAULT_ENABLED
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ('1', 'true', 'yes', 'on'):
        return True
    if text in ('0', 'false', 'no', 'off'):
        return False
    return DEFAULT_ENABLED


def resolve_ttl(value=None):
    if value is None:
        value = DEFAULT_TTL
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        ttl = DEFAULT_TTL
    if ttl < TTL_MIN:
        return TTL_MIN
    if ttl > TTL_MAX:
        return TTL_MAX
    return ttl


def resolve_length(value=None):
    if value is None:
        value = DEFAULT_LENGTH
    try:
        length = int(value)
    except (TypeError, ValueError):
        length = DEFAULT_LENGTH
    if length < LENGTH_MIN:
        return LENGTH_MIN
    if length > LENGTH_MAX:
        return LENGTH_MAX
    return length


def _registry_dir():
    return getattr(paths, 'IPA_LOGIN_CAPTCHA', '/run/ipa/login_captcha')


def _key_path():
    return getattr(
        paths, 'IPA_LOGIN_CAPTCHA_KEY',
        '/run/ipa/login_captcha/hmac.key')


def ensure_registry_dir():
    directory = _registry_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    return directory


def _get_hmac_key():
    """Load or create a dedicated CAPTCHA HMAC key (mode 0600)."""
    path = _key_path()
    try:
        with open(path, 'rb') as f:
            key = f.read()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.debug('Unable to read CAPTCHA key %s: %s', path, e)

    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as e:
        logger.debug('Unable to create CAPTCHA key dir: %s', e)
        # Fallback ephemeral key (survives only this process); still CSPRNG.
        return secrets.token_bytes(32)

    key = secrets.token_bytes(32)
    fd, tmp = tempfile.mkstemp(prefix='.captcha_key_', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(key)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.rename(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return key


def normalize_answer(answer):
    if answer is None:
        return ''
    return str(answer).strip().upper()


def answer_verifier(answer, key=None):
    if key is None:
        key = _get_hmac_key()
    digest = hmac.new(
        key,
        normalize_answer(answer).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    return digest


def _path_for_id(challenge_id):
    # token_urlsafe uses A-Za-z0-9_- ; reject anything else.
    if (not challenge_id or
            not all(c.isalnum() or c in '-_' for c in challenge_id)):
        raise ValueError('invalid challenge id')
    if len(challenge_id) > 128:
        raise ValueError('invalid challenge id')
    return os.path.join(_registry_dir(), '{}.json'.format(challenge_id))


def _atomic_write(path, data):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.captcha_', dir=directory)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, separators=(',', ':'), sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.rename(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read(path):
    with open(path, 'r') as f:
        return json.load(f)


def _delete(challenge_id):
    try:
        os.unlink(_path_for_id(challenge_id))
    except (OSError, ValueError):
        pass


def cleanup_expired(now=None):
    """Remove expired challenge files. Returns number removed."""
    if now is None:
        now = int(time.time())
    directory = _registry_dir()
    if not os.path.isdir(directory):
        return 0
    removed = 0
    try:
        names = os.listdir(directory)
    except OSError:
        return 0
    for name in names:
        if not name.endswith('.json'):
            continue
        path = os.path.join(directory, name)
        try:
            record = _read(path)
            if int(record.get('expires', 0)) <= now:
                os.unlink(path)
                removed += 1
        except (OSError, ValueError, TypeError, KeyError):
            try:
                os.unlink(path)
                removed += 1
            except OSError:
                pass
    return removed


def _count_active_for_ip(client_ip, now=None):
    if now is None:
        now = int(time.time())
    directory = _registry_dir()
    if not os.path.isdir(directory):
        return 0
    count = 0
    try:
        names = os.listdir(directory)
    except OSError:
        return 0
    for name in names:
        if not name.endswith('.json'):
            continue
        path = os.path.join(directory, name)
        try:
            record = _read(path)
        except (OSError, ValueError, TypeError):
            continue
        if int(record.get('expires', 0)) <= now:
            continue
        if (record.get('client_ip') or '') == (client_ip or ''):
            count += 1
    return count


def generate_answer(length=None):
    length = resolve_length(length)
    return ''.join(secrets.choice(ALPHABET) for _ in range(length))


def render_svg(answer):
    """Render a noisy SVG CAPTCHA. Never embeds the answer as metadata."""
    width = 220
    height = 72
    # Background
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" '
        'viewBox="0 0 {} {}">'.format(width, height, width, height),
        '<rect width="100%" height="100%" fill="#f4f4f4"/>',
    ]
    # Noise lines
    for _ in range(8):
        x1 = secrets.randbelow(width)
        y1 = secrets.randbelow(height)
        x2 = secrets.randbelow(width)
        y2 = secrets.randbelow(height)
        color = '#{:02x}{:02x}{:02x}'.format(
            80 + secrets.randbelow(120),
            80 + secrets.randbelow(120),
            80 + secrets.randbelow(120),
        )
        parts.append(
            '<line x1="{}" y1="{}" x2="{}" y2="{}" '
            'stroke="{}" stroke-width="1"/>'.format(x1, y1, x2, y2, color)
        )
    # Noise dots
    for _ in range(40):
        cx = secrets.randbelow(width)
        cy = secrets.randbelow(height)
        r = 1 + secrets.randbelow(2)
        color = '#{:02x}{:02x}{:02x}'.format(
            secrets.randbelow(200),
            secrets.randbelow(200),
            secrets.randbelow(200),
        )
        parts.append(
            '<circle cx="{}" cy="{}" r="{}" fill="{}"/>'.format(
                cx, cy, r, color)
        )
    # Characters as simple stroked glyphs via text with random transform.
    # Use only generic family names (no external fonts/URLs).
    n = len(answer)
    margin = 18
    usable = width - 2 * margin
    for i, ch in enumerate(answer):
        # Escape for XML text content (answer chars are alphanumeric only)
        safe = xml.sax.saxutils.escape(ch)
        x = margin + int((i + 0.5) * usable / max(n, 1)) + secrets.randbelow(7) - 3
        y = 40 + secrets.randbelow(13) - 6
        rot = secrets.randbelow(41) - 20
        size = 26 + secrets.randbelow(8)
        color = '#{:02x}{:02x}{:02x}'.format(
            secrets.randbelow(80),
            secrets.randbelow(80),
            secrets.randbelow(80),
        )
        parts.append(
            '<text x="{}" y="{}" fill="{}" font-size="{}" '
            'font-family="monospace, sans-serif" font-weight="bold" '
            'text-anchor="middle" '
            'transform="rotate({} {} {})">{}</text>'.format(
                x, y, color, size, rot, x, y, safe)
        )
    parts.append('</svg>')
    return ''.join(parts)


def create_challenge(client_ip, ttl=None, length=None):
    """Create a CAPTCHA challenge. Returns public dict (no answer/HMAC)."""
    ensure_registry_dir()
    cleanup_expired()
    ttl = resolve_ttl(ttl)
    length = resolve_length(length)
    client_ip = client_ip or ''

    if _count_active_for_ip(client_ip) >= MAX_CHALLENGES_PER_IP:
        cleanup_expired()
        if _count_active_for_ip(client_ip) >= MAX_CHALLENGES_PER_IP:
            raise RuntimeError('too many captcha challenges')

    challenge_id = secrets.token_urlsafe(24)
    answer = generate_answer(length)
    now = int(time.time())
    record = {
        'id': challenge_id,
        'verifier': answer_verifier(answer),
        'created': now,
        'expires': now + ttl,
        'used': False,
        'client_ip': client_ip,
    }
    _atomic_write(_path_for_id(challenge_id), record)
    svg = render_svg(answer)
    # Drop plaintext answer from process ASAP (GC).
    del answer
    return {
        'id': challenge_id,
        'image': svg,
        'expires_in': ttl,
    }


# Safe CAPTCHA failure reason categories for security audit logs (no secrets).
CAPTCHA_REASON_MISSING = 'missing'
CAPTCHA_REASON_INVALID = 'invalid'
CAPTCHA_REASON_EXPIRED = 'expired'
CAPTCHA_REASON_REUSED = 'reused'
CAPTCHA_REASON_IP_MISMATCH = 'ip_mismatch'


def verify_and_consume_result(challenge_id, answer, client_ip):
    """Verify CAPTCHA and always consume the challenge.

    Returns ``(True, None)`` on success, or ``(False, reason)`` where reason is
    one of the CAPTCHA_REASON_* categories. Never returns answers or verifiers.
    """
    client_ip = client_ip or ''
    if not challenge_id or answer is None:
        return False, CAPTCHA_REASON_MISSING

    answer_norm = normalize_answer(answer)
    try:
        path = _path_for_id(challenge_id)
    except ValueError:
        return False, CAPTCHA_REASON_INVALID

    try:
        record = _read(path)
    except (OSError, ValueError, TypeError):
        return False, CAPTCHA_REASON_INVALID

    # Always consume (success, failure, expiry, IP mismatch).
    _delete(challenge_id)

    if record.get('used'):
        return False, CAPTCHA_REASON_REUSED
    now = int(time.time())
    try:
        expires = int(record.get('expires', 0))
    except (TypeError, ValueError):
        return False, CAPTCHA_REASON_INVALID
    if expires <= now:
        return False, CAPTCHA_REASON_EXPIRED
    if (record.get('client_ip') or '') != client_ip:
        return False, CAPTCHA_REASON_IP_MISMATCH
    if not answer_norm:
        return False, CAPTCHA_REASON_INVALID

    expected = record.get('verifier') or ''
    actual = answer_verifier(answer_norm)
    if hmac.compare_digest(str(expected), str(actual)):
        return True, None
    return False, CAPTCHA_REASON_INVALID


def verify_and_consume(challenge_id, answer, client_ip):
    """Verify CAPTCHA and always consume the challenge.

    Returns True only on exact match with fresh unused challenge from same IP.
    """
    ok, _reason = verify_and_consume_result(challenge_id, answer, client_ip)
    return ok


def svg_contains_answer_leak(svg, answer):
    """Heuristic test helper: answer must not appear outside glyph text nodes.

    Returns True if a leak is suspected in metadata-like constructs.
    """
    if not svg or not answer:
        return False
    lower = svg.lower()
    for marker in ('<title', '<desc', 'aria-label', '<!--'):
        if marker in lower and normalize_answer(answer) in normalize_answer(svg):
            # Further check: answer in comment/title/desc/aria
            import re
            if re.search(
                    r'(<!--.*?{0}.*?-->|<title[^>]*>.*?{0}.*?</title>|'
                    r'<desc[^>]*>.*?{0}.*?</desc>|aria-label=["\'].*?{0})'.format(
                        re.escape(normalize_answer(answer))),
                    svg,
                    re.IGNORECASE | re.DOTALL):
                return True
    return False
