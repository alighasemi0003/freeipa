#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Minimal server-side registry for FreeIPA Web UI/API sessions.

Stores metadata only (no cookies, tokens, ticket material, or passwords).
Used for admin listing, forced logout, idle-timeout, concurrency limits, and
optional client-IP binding of Web sessions.
"""

from __future__ import absolute_import

import hashlib
import json
import logging
import os
import tempfile
import time

from ipalib.constants import DEFAULT_CONFIG
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

STATUS_ACTIVE = 'active'
STATUS_REVOKED = 'revoked'

_DEFAULTS = dict(DEFAULT_CONFIG)

# Default idle timeout in seconds (from ipalib.constants.DEFAULT_CONFIG).
DEFAULT_IDLE_TIMEOUT = _DEFAULTS.get('web_session_idle_timeout', 1800)
DEFAULT_MAX_PER_USER = _DEFAULTS.get('web_session_max_per_user', 1)
DEFAULT_BIND_IP = _DEFAULTS.get('web_session_bind_ip', True)


def _registry_dir():
    return getattr(paths, 'IPA_WEB_SESSIONS', '/run/ipa/web_sessions')


def normalize_ccache_path(ccache_name):
    """Return filesystem path for a KRB5CCNAME value."""
    if not ccache_name:
        return None
    name = ccache_name
    if name.startswith('FILE:'):
        name = name[5:]
    return os.path.abspath(name)


def session_id_from_cookie(session_cookie):
    """Stable public session id derived from the opaque session cookie."""
    if isinstance(session_cookie, bytes):
        session_cookie = session_cookie.decode('utf-8')
    digest = hashlib.sha256(session_cookie.encode('utf-8')).hexdigest()
    return digest


def ensure_registry_dir():
    directory = _registry_dir()
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as e:
        logger.debug('Unable to create web session registry dir %s: %s',
                     directory, e)
        raise
    return directory


def _path_for_id(session_id):
    # Only accept hex ids to avoid path traversal.
    if not session_id or not all(c in '0123456789abcdef' for c in session_id):
        raise ValueError('invalid session id')
    return os.path.join(_registry_dir(), '{}.json'.format(session_id))


def _atomic_write(path, data):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.sess_', dir=directory)
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


def register_web_session(session_cookie, principal, ccache_name,
                         client_ip=None, max_per_user=None):
    """Create/update an active web session registry entry.

    After registration, enforces ``web_session_max_per_user`` by revoking the
    oldest excess active sessions for the same username (new login always
    succeeds).
    """
    ensure_registry_dir()
    session_id = session_id_from_cookie(session_cookie)
    ccache_path = normalize_ccache_path(ccache_name)
    now = int(time.time())
    username = str(principal).split('@', 1)[0]
    if '/' in username:
        # Host/service principals are not Web UI user sessions.
        logger.debug('Skipping web session registry for non-user principal %s',
                     principal)
        return None

    record = {
        'id': session_id,
        'principal': str(principal),
        'username': username,
        'ccache_path': ccache_path,
        'created': now,
        'last_activity': now,
        'last_reauth_at': None,
        'client_ip': client_ip or '',
        'status': STATUS_ACTIVE,
    }
    _atomic_write(_path_for_id(session_id), record)
    logger.debug('Registered web session %s for %s', session_id[:12], username)
    enforce_max_sessions_for_user(
        username, keep_session_id=session_id, max_per_user=max_per_user)
    return session_id


def list_active_sessions_for_user(username):
    """Return active sessions for ``username``, oldest first."""
    sessions = [
        s for s in list_web_sessions(include_revoked=False)
        if s.get('username') == username
    ]
    sessions.sort(
        key=lambda r: (int(r.get('created', 0) or 0), r.get('id') or ''))
    return sessions


def resolve_max_per_user(max_per_user=None):
    """Normalize max concurrent sessions; ``0`` means unlimited."""
    if max_per_user is None:
        return int(DEFAULT_MAX_PER_USER)
    try:
        value = int(max_per_user)
    except (TypeError, ValueError):
        logger.debug(
            'Invalid web_session_max_per_user %r, using default %s',
            max_per_user, DEFAULT_MAX_PER_USER)
        return int(DEFAULT_MAX_PER_USER)
    if value < 0:
        return int(DEFAULT_MAX_PER_USER)
    return value


def enforce_max_sessions_for_user(username, keep_session_id=None,
                                  max_per_user=None):
    """Revoke oldest excess active sessions for ``username``.

    Keeps the newest ``max_per_user`` sessions, always retaining
    ``keep_session_id`` when provided (the newly registered session).
    Returns list of revoked session ids.
    """
    max_n = resolve_max_per_user(max_per_user)
    if max_n == 0:
        return []

    sessions = list_active_sessions_for_user(username)
    if len(sessions) <= max_n:
        return []

    # Always retain the newly registered session, then fill with newest.
    keep_ids = set()
    if keep_session_id:
        keep_ids.add(keep_session_id)
    for s in reversed(sessions):
        if len(keep_ids) >= max_n:
            break
        keep_ids.add(s['id'])

    revoked_ids = []
    for s in sessions:
        sid = s['id']
        if sid in keep_ids:
            continue
        if revoke_session(sid):
            revoked_ids.append(sid)
            logger.info(
                'Revoked excess web session %s for user %s '
                '(max_per_user=%s)',
                sid[:12], username, max_n)
    return revoked_ids


def get_session_by_id(session_id):
    try:
        path = _path_for_id(session_id)
    except ValueError:
        return None
    if not os.path.isfile(path):
        return None
    try:
        return _read(path)
    except (OSError, ValueError, TypeError) as e:
        logger.debug('Failed reading session %s: %s', session_id[:12], e)
        return None


def get_session_by_ccache(ccache_name):
    ccache_path = normalize_ccache_path(ccache_name)
    if not ccache_path:
        return None
    directory = _registry_dir()
    if not os.path.isdir(directory):
        return None
    try:
        names = os.listdir(directory)
    except OSError:
        return None
    for name in names:
        if not name.endswith('.json'):
            continue
        path = os.path.join(directory, name)
        try:
            record = _read(path)
        except (OSError, ValueError, TypeError):
            continue
        if record.get('ccache_path') == ccache_path:
            return record
    return None


def touch_session_activity(session_id):
    record = get_session_by_id(session_id)
    if not record or record.get('status') != STATUS_ACTIVE:
        return
    record['last_activity'] = int(time.time())
    try:
        _atomic_write(_path_for_id(session_id), record)
    except OSError as e:
        logger.debug('Failed updating session activity: %s', e)


def mark_session_reauth(session_id, now=None):
    """Record successful credential verification for step-up auth."""
    record = get_session_by_id(session_id)
    if not record or record.get('status') != STATUS_ACTIVE:
        return False
    if now is None:
        now = int(time.time())
    record['last_reauth_at'] = int(now)
    record['last_activity'] = int(now)
    try:
        _atomic_write(_path_for_id(session_id), record)
    except OSError as e:
        logger.debug('Failed updating session reauth: %s', e)
        return False
    return True


def consume_reauth_credit(session_id):
    """Clear last_reauth_at after a one-shot (timeout=0) sensitive allow."""
    record = get_session_by_id(session_id)
    if not record or record.get('status') != STATUS_ACTIVE:
        return False
    if record.get('last_reauth_at') is None:
        return True
    record['last_reauth_at'] = None
    try:
        _atomic_write(_path_for_id(session_id), record)
    except OSError as e:
        logger.debug('Failed consuming reauth credit: %s', e)
        return False
    return True


def list_web_sessions(include_revoked=False):
    directory = _registry_dir()
    if not os.path.isdir(directory):
        return []
    results = []
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    for name in names:
        if not name.endswith('.json'):
            continue
        path = os.path.join(directory, name)
        try:
            record = _read(path)
        except (OSError, ValueError, TypeError):
            continue
        if not include_revoked and record.get('status') != STATUS_ACTIVE:
            continue
        results.append(record)
    results.sort(key=lambda r: r.get('created', 0), reverse=True)
    return results


def public_session_view(record):
    """Metadata safe for API output (no ccache path / cookies / tokens)."""
    if not record:
        return None
    return {
        'id': record.get('id'),
        'username': record.get('username'),
        'principal': record.get('principal'),
        'created': record.get('created'),
        'last_activity': record.get('last_activity'),
        'client_ip': record.get('client_ip') or '',
        'status': record.get('status'),
    }


def _remove_ccache_file(ccache_path):
    if not ccache_path:
        return
    # Only delete files under the configured IPA ccache directory.
    ccache_dir = os.path.abspath(paths.IPA_CCACHES)
    path = os.path.abspath(ccache_path)
    if path != ccache_dir and not path.startswith(ccache_dir + os.sep):
        logger.warning(
            'Refusing to delete ccache outside IPA_CCACHES: %s', path)
        return
    try:
        os.unlink(path)
        logger.debug('Removed delegated ccache %s', path)
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.debug('Unable to remove ccache %s: %s', path, e)


def revoke_session(session_id):
    """Mark session revoked and remove its delegated ccache."""
    record = get_session_by_id(session_id)
    if record is None:
        return False
    ccache_path = record.get('ccache_path')
    record['status'] = STATUS_REVOKED
    record['last_activity'] = int(time.time())
    try:
        _atomic_write(_path_for_id(session_id), record)
    except OSError as e:
        logger.debug('Failed writing revoked session: %s', e)
        return False
    _remove_ccache_file(ccache_path)
    return True


def revoke_session_by_ccache(ccache_name):
    record = get_session_by_ccache(ccache_name)
    if record is None:
        return False
    return revoke_session(record['id'])


def is_session_revoked_for_ccache(ccache_name):
    record = get_session_by_ccache(ccache_name)
    if record is None:
        return False
    return record.get('status') == STATUS_REVOKED


def resolve_idle_timeout(idle_timeout=None):
    """Normalize idle timeout to int seconds.

    ``None`` uses the built-in default. ``0`` disables idle enforcement.
    """
    if idle_timeout is None:
        return int(DEFAULT_IDLE_TIMEOUT)
    try:
        value = int(idle_timeout)
    except (TypeError, ValueError):
        logger.debug(
            'Invalid web_session_idle_timeout %r, using default %s',
            idle_timeout, DEFAULT_IDLE_TIMEOUT)
        return int(DEFAULT_IDLE_TIMEOUT)
    if value < 0:
        return int(DEFAULT_IDLE_TIMEOUT)
    return value


def is_session_idle(record, idle_timeout=None, now=None):
    """Return True if an active session has exceeded the idle timeout."""
    timeout = resolve_idle_timeout(idle_timeout)
    if timeout == 0:
        return False
    if not record or record.get('status') != STATUS_ACTIVE:
        return False
    last_activity = record.get('last_activity')
    if last_activity is None:
        last_activity = record.get('created', 0)
    try:
        last_activity = int(last_activity)
    except (TypeError, ValueError):
        last_activity = 0
    if now is None:
        now = int(time.time())
    return (now - last_activity) > timeout


def enforce_idle_timeout(ccache_name, idle_timeout=None, now=None):
    """Revoke session if idle timeout exceeded.

    Returns True if the session was revoked due to idle timeout.
    """
    record = get_session_by_ccache(ccache_name)
    if not is_session_idle(record, idle_timeout=idle_timeout, now=now):
        return False
    logger.info(
        'Web session %s idle timeout exceeded; revoking',
        record.get('id', '')[:12])
    return revoke_session(record['id'])


def resolve_bind_ip(bind_ip=None):
    """Normalize web_session_bind_ip to a boolean."""
    if bind_ip is None:
        return bool(DEFAULT_BIND_IP)
    if isinstance(bind_ip, bool):
        return bind_ip
    if isinstance(bind_ip, (int, float)):
        return bool(bind_ip)
    text = str(bind_ip).strip().lower()
    if text in ('1', 'true', 'yes', 'on'):
        return True
    if text in ('0', 'false', 'no', 'off'):
        return False
    logger.debug(
        'Invalid web_session_bind_ip %r, using default %s',
        bind_ip, DEFAULT_BIND_IP)
    return bool(DEFAULT_BIND_IP)


def session_ip_allows(record, client_ip, bind_ip=None):
    """Return True if IP binding permits access for ``record``.

    When binding is enabled, missing stored IP, missing request IP, or any
    mismatch fails. Does not revoke; caller decides.
    """
    if not resolve_bind_ip(bind_ip):
        return True
    stored = (record or {}).get('client_ip') or ''
    current = client_ip or ''
    if not stored or not current:
        return False
    return stored == current


def session_allows_access(ccache_name, idle_timeout=None, now=None,
                          client_ip=None, bind_ip=None):
    """Return True if the web session may continue for this ccache.

    Order:
    - No registry record: allow (cannot enforce without metadata).
    - Already revoked: deny.
    - IP binding enabled and IP missing/mismatched: revoke and deny.
    - Idle past timeout: revoke and deny.
    - Otherwise: allow.
    """
    record = get_session_by_ccache(ccache_name)
    if record is None:
        return True
    if record.get('status') == STATUS_REVOKED:
        return False
    if not session_ip_allows(record, client_ip, bind_ip=bind_ip):
        logger.info(
            'Web session %s IP binding failed '
            '(stored=%r current=%r); revoking',
            (record.get('id') or '')[:12],
            record.get('client_ip') or '',
            client_ip or '')
        revoke_session(record['id'])
        return False
    if is_session_idle(record, idle_timeout=idle_timeout, now=now):
        enforce_idle_timeout(
            ccache_name, idle_timeout=idle_timeout, now=now)
        return False
    return True
