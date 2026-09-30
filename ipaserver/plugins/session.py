#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import logging

import six

from ipalib import Command, errors, output
from ipalib.parameters import Str
from ipalib.request import context
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipaserver import session_registry

if six.PY3:
    unicode = str

__doc__ = _("""
Session Support for IPA

Web UI/API sessions can be listed and force-terminated by administrators.
Self logout remains available via session-logout.
""")

logger = logging.getLogger(__name__)

register = Registry()


def _require_web_session_admin(api):
    """Allow only members of the admins group to manage web sessions."""
    principal = getattr(context, 'principal', None)
    if principal is None:
        raise errors.ACIError(info=_('not authenticated'))

    principal = str(principal)
    username = principal.split('@', 1)[0]
    if '/' in username:
        raise errors.ACIError(
            info=_('not allowed to manage web sessions'))

    user_dn = DN(('uid', username), api.env.container_user, api.env.basedn)
    admins_dn = DN(('cn', 'admins'), api.env.container_group, api.env.basedn)
    try:
        entry = api.Backend.ldap2.get_entry(user_dn, ['memberof'])
    except errors.NotFound:
        raise errors.ACIError(
            info=_('not allowed to manage web sessions'))

    members = entry.get('memberof', [])
    for member in members:
        try:
            if DN(member) == admins_dn:
                return
        except Exception:
            continue
    raise errors.ACIError(
        info=_('not allowed to manage web sessions'))


@register()
class session_logout(Command):
    __doc__ = _('RPC command used to log the current user out of their'
                ' session.')
    NO_CLI = True

    def execute(self, *args, **options):
        ccache_name = getattr(context, 'ccache_name', None)
        if ccache_name is None:
            logger.debug('session logout command: no ccache_name found')
        else:
            try:
                session_registry.revoke_session_by_ccache(ccache_name)
            except Exception as e:
                logger.debug('session logout registry cleanup failed: %s', e)
            delattr(context, 'ccache_name')

        setattr(context, 'logout_cookie', 'MagBearerToken=')

        return dict(result=None)


@register()
class session_find(Command):
    __doc__ = _('Search for active FreeIPA Web UI/API sessions.')

    takes_options = (
        Str(
            'user?',
            cli_name='user',
            label=_('User login'),
            doc=_('Limit results to sessions for this user'),
        ),
    )

    has_output = (
        output.ListOfEntries('result'),
        output.Output('count', int, _('Number of entries returned')),
        output.Output('truncated', bool,
                      _('True if not all results were returned')),
        output.Output('summary', (unicode, type(None)),
                      _('User-friendly description of action performed')),
    )

    def execute(self, *args, **options):
        _require_web_session_admin(self.api)

        user_filter = options.get('user')
        sessions = session_registry.list_web_sessions(include_revoked=False)
        results = []
        for record in sessions:
            if user_filter and record.get('username') != user_filter:
                continue
            view = session_registry.public_session_view(record)
            if view:
                results.append(view)

        return dict(
            result=results,
            count=len(results),
            truncated=False,
            summary=unicode(_('%(count)d Web session(s) matched') %
                            {'count': len(results)}),
        )


@register()
class session_kill(Command):
    __doc__ = _('Force logout a FreeIPA Web UI/API session.')

    takes_args = (
        Str(
            'id',
            cli_name='id',
            label=_('Session ID'),
            doc=_('Session identifier from session-find'),
        ),
    )

    has_output = (
        output.Output('result', dict, _('Result of kill operation')),
        output.Output('value', unicode, _('Session ID'), ['no_display']),
        output.Output('summary', (unicode, type(None)),
                      _('User-friendly description of action performed')),
    )

    def execute(self, id, **options):
        _require_web_session_admin(self.api)

        record = session_registry.get_session_by_id(id)
        if (record is None or
                record.get('status') != session_registry.STATUS_ACTIVE):
            raise errors.NotFound(
                reason=_('Web session not found: %(id)s') % {'id': id})

        if not session_registry.revoke_session(id):
            raise errors.ExecutionError(
                message=_('Failed to kill Web session %(id)s') % {'id': id})

        return dict(
            result=session_registry.public_session_view(
                session_registry.get_session_by_id(id)),
            value=unicode(id),
            summary=unicode(_('Killed Web session %(id)s') % {'id': id}),
        )
