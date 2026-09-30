# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""Unit tests for Web session registry and admin session commands."""

from __future__ import absolute_import

import os
import time
from unittest import mock

import pytest

from ipalib import errors
from ipalib.request import context
from ipaserver import session_registry
from ipaserver.plugins import session as session_plugin


@pytest.fixture
def registry_dir(tmp_path, monkeypatch):
    path = str(tmp_path / 'web_sessions')
    os.makedirs(path, mode=0o700)
    monkeypatch.setattr(session_registry.paths, 'IPA_WEB_SESSIONS', path)
    ccache_dir = str(tmp_path / 'ccaches')
    os.makedirs(ccache_dir, mode=0o700)
    monkeypatch.setattr(session_registry.paths, 'IPA_CCACHES', ccache_dir)
    return path, ccache_dir


def _make_ccache(ccache_dir, name='krb5cc_test'):
    path = os.path.join(ccache_dir, name)
    with open(path, 'wb') as f:
        f.write(b'fake-ccache')
    return path


@pytest.mark.tier0
class TestSessionRegistry:
    def test_register_and_list(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=abc',
            'user1@IPA.TEST',
            'FILE:' + ccache,
            client_ip='203.0.113.10',
        )
        assert sid
        sessions = session_registry.list_web_sessions()
        assert len(sessions) == 1
        view = session_registry.public_session_view(sessions[0])
        assert view['username'] == 'user1'
        assert view['client_ip'] == '203.0.113.10'
        assert view['status'] == 'active'
        assert 'ccache_path' not in view
        assert 'cookie' not in view

    def test_revoke_removes_ccache_and_blocks(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=xyz',
            'user1@IPA.TEST',
            ccache,
            client_ip='127.0.0.1',
        )
        assert os.path.isfile(ccache)
        assert session_registry.revoke_session(sid) is True
        assert not os.path.isfile(ccache)
        assert session_registry.is_session_revoked_for_ccache(ccache) is True
        assert session_registry.list_web_sessions() == []

    def test_self_logout_by_ccache(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        session_registry.register_web_session(
            'MagBearerToken=self',
            'user1@IPA.TEST',
            ccache,
        )
        assert session_registry.revoke_session_by_ccache(ccache) is True
        assert session_registry.is_session_revoked_for_ccache(ccache) is True


@pytest.mark.tier0
class TestSessionIdleTimeout:
    def test_within_timeout_remains_valid(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        session_registry.register_web_session(
            'MagBearerToken=idle-ok', 'user1@IPA.TEST', ccache)
        assert session_registry.session_allows_access(
            ccache, idle_timeout=1800) is True
        assert os.path.isfile(ccache)
        assert session_registry.is_session_revoked_for_ccache(ccache) is False

    def test_exceeding_timeout_is_revoked(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=idle-out', 'user1@IPA.TEST', ccache)
        record = session_registry.get_session_by_id(sid)
        # Simulate last activity far in the past
        record['last_activity'] = int(time.time()) - 3600
        session_registry._atomic_write(
            session_registry._path_for_id(sid), record)

        assert session_registry.is_session_idle(record, idle_timeout=1800)
        assert session_registry.enforce_idle_timeout(
            ccache, idle_timeout=1800) is True
        assert not os.path.isfile(ccache)
        assert session_registry.is_session_revoked_for_ccache(ccache) is True

    def test_revoked_idle_session_cannot_authenticate(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=idle-deny', 'user1@IPA.TEST', ccache)
        record = session_registry.get_session_by_id(sid)
        record['last_activity'] = int(time.time()) - 7200
        session_registry._atomic_write(
            session_registry._path_for_id(sid), record)

        assert session_registry.session_allows_access(
            ccache, idle_timeout=60) is False
        # Still denied on subsequent checks
        assert session_registry.session_allows_access(
            ccache, idle_timeout=60) is False

    def test_activity_updates_last_activity(self, registry_dir, monkeypatch):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=touch', 'user1@IPA.TEST', ccache)
        record = session_registry.get_session_by_id(sid)
        record['last_activity'] = 1_000_000
        session_registry._atomic_write(
            session_registry._path_for_id(sid), record)
        monkeypatch.setattr(session_registry.time, 'time', lambda: 1_000_042)
        session_registry.touch_session_activity(sid)
        after = session_registry.get_session_by_id(sid)['last_activity']
        assert after == 1_000_042

    def test_idle_timeout_zero_disables_enforcement(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=idle-off', 'user1@IPA.TEST', ccache)
        record = session_registry.get_session_by_id(sid)
        record['last_activity'] = int(time.time()) - 99999
        session_registry._atomic_write(
            session_registry._path_for_id(sid), record)
        assert session_registry.is_session_idle(record, idle_timeout=0) is False
        assert session_registry.session_allows_access(
            ccache, idle_timeout=0) is True
        assert os.path.isfile(ccache)


@pytest.mark.tier0
class TestSessionCommands:
    def _cmd(self, cls):
        api = mock.MagicMock()
        api.env.basedn = 'dc=ipa,dc=test'
        api.env.container_user = 'cn=users,cn=accounts'
        api.env.container_group = 'cn=groups,cn=accounts'
        return cls(api)

    def test_session_find_requires_admin(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        session_registry.register_web_session(
            'MagBearerToken=a', 'user1@IPA.TEST', ccache)

        cmd = self._cmd(session_plugin.session_find)
        context.principal = 'user1@IPA.TEST'
        # Non-admin: not member of admins
        entry = mock.MagicMock()
        entry.get.return_value = []
        cmd.api.Backend.ldap2.get_entry.return_value = entry
        with pytest.raises(errors.ACIError):
            cmd.execute()

    def test_session_find_admin_lists(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        session_registry.register_web_session(
            'MagBearerToken=a', 'user1@IPA.TEST', ccache,
            client_ip='198.51.100.5')

        cmd = self._cmd(session_plugin.session_find)
        context.principal = 'admin@IPA.TEST'
        entry = mock.MagicMock()
        entry.get.return_value = [
            'cn=admins,cn=groups,cn=accounts,dc=ipa,dc=test'
        ]
        cmd.api.Backend.ldap2.get_entry.return_value = entry
        result = cmd.execute()
        assert result['count'] == 1
        assert result['result'][0]['username'] == 'user1'
        assert 'ccache_path' not in result['result'][0]

    def test_session_kill_admin(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=killme', 'user1@IPA.TEST', ccache)

        cmd = self._cmd(session_plugin.session_kill)
        context.principal = 'admin@IPA.TEST'
        entry = mock.MagicMock()
        entry.get.return_value = [
            'cn=admins,cn=groups,cn=accounts,dc=ipa,dc=test'
        ]
        cmd.api.Backend.ldap2.get_entry.return_value = entry
        result = cmd.execute(sid)
        assert result['value'] == sid
        assert result['result']['status'] == 'revoked'
        assert not os.path.isfile(ccache)

    def test_session_logout_revokes_current(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        session_registry.register_web_session(
            'MagBearerToken=logout', 'user1@IPA.TEST', ccache)

        cmd = self._cmd(session_plugin.session_logout)
        context.ccache_name = ccache
        out = cmd.execute()
        assert out == dict(result=None)
        assert getattr(context, 'logout_cookie') == 'MagBearerToken='
        assert session_registry.is_session_revoked_for_ccache(ccache) is True
