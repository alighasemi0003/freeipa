#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Sensitive-action reauthentication policy for FreeIPA Web sessions.

Configuration (``/etc/ipa/default.conf`` ``[global]``) is loaded once at
IPA process startup. Changing it requires an httpd/IPA service restart.
"""

from __future__ import absolute_import

import logging
import re

from ipalib import errors
from ipalib.constants import DEFAULT_CONFIG
from ipalib.request import context

logger = logging.getLogger(__name__)

_DEFAULTS = dict(DEFAULT_CONFIG)

DEFAULT_POLICY = 'default'
DEFAULT_TIMEOUT = int(_DEFAULTS.get('sensitive_action_reauth_timeout', 300))
# Short grace so UI can retry once after verify when timeout is 0.
ZERO_TIMEOUT_GRACE_SECONDS = 5

# Built-in mutating / high-impact commands (no *_find / *_show).
BUILTIN_SENSITIVE_COMMANDS = frozenset((
    'user_del',
    'user_disable',
    'user_enable',
    'user_unlock',
    'passwd',
    'otptoken_add',
    'otptoken_del',
    'otptoken_mod',
    'otptoken_add_managedby',
    'otptoken_remove_managedby',
    'role_add',
    'role_del',
    'role_mod',
    'role_add_member',
    'role_remove_member',
    'role_add_privilege',
    'role_remove_privilege',
    'privilege_add',
    'privilege_del',
    'privilege_mod',
    'privilege_add_member',
    'privilege_remove_member',
    'privilege_add_permission',
    'privilege_remove_permission',
    'permission_add',
    'permission_del',
    'permission_mod',
    'permission_add_member',
    'permission_remove_member',
    'pwpolicy_add',
    'pwpolicy_del',
    'pwpolicy_mod',
    'session_kill',
    'cert_request',
    'cert_revoke',
    'cert_remove_hold',
    'ca_add',
    'ca_del',
    'ca_mod',
    'ca_disable',
    'ca_enable',
))

_VALID_POLICIES = frozenset(('default', 'custom', 'disabled'))

# Process-local cache filled after API finalize / first use.
_resolved_commands = None
_resolved_policy = None
_resolved_timeout = None


def resolve_policy(value=None):
    if value is None:
        value = DEFAULT_POLICY
    text = str(value).strip().lower()
    if text in _VALID_POLICIES:
        return text
    logger.warning(
        'Invalid sensitive_action_reauth_policy %r; using default', value)
    return DEFAULT_POLICY


def resolve_timeout(value=None):
    if value is None:
        return DEFAULT_TIMEOUT
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        logger.warning(
            'Invalid sensitive_action_reauth_timeout %r; using %s',
            value, DEFAULT_TIMEOUT)
        return DEFAULT_TIMEOUT
    if timeout < 0:
        logger.warning(
            'Negative sensitive_action_reauth_timeout %r; using %s',
            value, DEFAULT_TIMEOUT)
        return DEFAULT_TIMEOUT
    return timeout


def parse_command_list(value):
    """Parse CSV command names: trim, drop empties, dedupe (order preserved)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        raw_items = [str(x) for x in value]
    else:
        text = str(value).strip()
        if not text:
            return []
        raw_items = re.split(r'\s*,\s*', text)
    seen = set()
    result = []
    for item in raw_items:
        name = item.strip()
        if not name:
            continue
        if name in seen:
            continue
        seen.add(name)
        result.append(name)
    return result


def filter_known_commands(names, api=None):
    """Keep only names present in api.Command; warn about unknowns."""
    if api is None:
        return list(names)
    known = []
    for name in names:
        try:
            if name in api.Command:
                known.append(name)
            else:
                logger.warning(
                    'Ignoring unknown sensitive_action_reauth command %r',
                    name)
        except Exception:
            logger.warning(
                'Ignoring unknown sensitive_action_reauth command %r',
                name)
    return known


def resolve_sensitive_commands(policy=None, commands=None, api=None):
    """Return frozenset of sensitive command names for the active policy."""
    policy = resolve_policy(policy)
    if policy == 'disabled':
        return frozenset()
    if policy == 'default':
        return BUILTIN_SENSITIVE_COMMANDS

    # custom
    parsed = parse_command_list(commands)
    filtered = filter_known_commands(parsed, api=api)
    if not filtered:
        logger.warning(
            'sensitive_action_reauth_commands empty or invalid under '
            'custom policy; falling back to built-in default set')
        return BUILTIN_SENSITIVE_COMMANDS
    return frozenset(filtered)


def reset_cache():
    """Test helper: clear process-local policy cache."""
    global _resolved_commands, _resolved_policy, _resolved_timeout
    _resolved_commands = None
    _resolved_policy = None
    _resolved_timeout = None


def _load_from_env(api):
    global _resolved_commands, _resolved_policy, _resolved_timeout
    env = api.env
    policy = resolve_policy(
        getattr(env, 'sensitive_action_reauth_policy', None))
    timeout = resolve_timeout(
        getattr(env, 'sensitive_action_reauth_timeout', None))
    commands = resolve_sensitive_commands(
        policy=policy,
        commands=getattr(env, 'sensitive_action_reauth_commands', None),
        api=api,
    )
    _resolved_policy = policy
    _resolved_timeout = timeout
    _resolved_commands = commands
    return policy, timeout, commands


def get_effective_policy(api):
    if _resolved_policy is None:
        return _load_from_env(api)
    return _resolved_policy, _resolved_timeout, _resolved_commands


def is_self_passwd(command_name, params, session_principal):
    """True when passwd targets the authenticated principal (self-service)."""
    if command_name != 'passwd':
        return False
    if not session_principal:
        return False
    target = params.get('principal') if isinstance(params, dict) else None
    if target is None:
        return True  # default_from is the caller
    try:
        from ipaserver.plugins.baseuser import normalize_user_principal
        target_n = unicode(normalize_user_principal(target))
        session_n = unicode(normalize_user_principal(session_principal))
        return target_n == session_n
    except Exception:
        return str(target).lower() == str(session_principal).lower()


# Py2/3 unicode helper
try:
    unicode
except NameError:  # pragma: no cover
    unicode = str  # pylint: disable=redefined-builtin


def _web_session_record(ccache_name):
    if not ccache_name:
        return None
    try:
        from ipaserver import session_registry
        record = session_registry.get_session_by_ccache(ccache_name)
        if not record or record.get('status') != session_registry.STATUS_ACTIVE:
            return None
        return record
    except Exception as e:
        logger.debug('sensitive reauth: session lookup failed: %s', e)
        return None


def is_reauth_fresh(record, timeout, now=None):
    """Return True if last_reauth_at satisfies the freshness window."""
    if not record:
        return False
    last = record.get('last_reauth_at')
    if last is None:
        return False
    try:
        last = int(last)
    except (TypeError, ValueError):
        return False
    if now is None:
        import time
        now = int(time.time())
    age = now - last
    if age < 0:
        return False
    if timeout == 0:
        return age <= ZERO_TIMEOUT_GRACE_SECONDS
    return age <= int(timeout)


def enforce_if_needed(command, params):
    """Raise ReauthRequired when a Web-session sensitive command is stale.

    No-op for non-Web (CLI/Kerberos without registry) and when policy disabled.
    """
    api = command.api
    if not getattr(api.env, 'in_server', False):
        return

    ccache_name = getattr(context, 'ccache_name', None)
    record = _web_session_record(ccache_name)
    if record is None:
        # CLI / non-registry path — do not enforce Web step-up.
        return

    policy, timeout, sensitive = get_effective_policy(api)
    if policy == 'disabled' or not sensitive:
        return

    name = command.name
    if name not in sensitive:
        return

    session_principal = (
        getattr(context, 'principal', None) or record.get('principal'))
    if is_self_passwd(name, params, session_principal):
        return

    if is_reauth_fresh(record, timeout):
        if timeout == 0:
            # Consume one-shot credit after allowing this sensitive op.
            try:
                from ipaserver import session_registry
                session_registry.consume_reauth_credit(record['id'])
            except Exception as e:
                logger.debug('consume_reauth_credit failed: %s', e)
        return

    raise errors.ReauthRequired()
