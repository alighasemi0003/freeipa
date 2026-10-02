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
            'MagBearerToken=idle-ok', 'user1@IPA.TEST', ccache,
            client_ip='203.0.113.1', max_per_user=0)
        assert session_registry.session_allows_access(
            ccache, idle_timeout=1800, client_ip='203.0.113.1',
            bind_ip=True) is True
        assert os.path.isfile(ccache)
        assert session_registry.is_session_revoked_for_ccache(ccache) is False

    def test_exceeding_timeout_is_revoked(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=idle-out', 'user1@IPA.TEST', ccache,
            client_ip='203.0.113.1', max_per_user=0)
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
            'MagBearerToken=idle-deny', 'user1@IPA.TEST', ccache,
            client_ip='203.0.113.1', max_per_user=0)
        record = session_registry.get_session_by_id(sid)
        record['last_activity'] = int(time.time()) - 7200
        session_registry._atomic_write(
            session_registry._path_for_id(sid), record)

        assert session_registry.session_allows_access(
            ccache, idle_timeout=60, client_ip='203.0.113.1',
            bind_ip=True) is False
        # Still denied on subsequent checks
        assert session_registry.session_allows_access(
            ccache, idle_timeout=60, client_ip='203.0.113.1',
            bind_ip=True) is False

    def test_activity_updates_last_activity(self, registry_dir, monkeypatch):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=touch', 'user1@IPA.TEST', ccache,
            max_per_user=0)
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
            'MagBearerToken=idle-off', 'user1@IPA.TEST', ccache,
            client_ip='203.0.113.1', max_per_user=0)
        record = session_registry.get_session_by_id(sid)
        record['last_activity'] = int(time.time()) - 99999
        session_registry._atomic_write(
            session_registry._path_for_id(sid), record)
        assert session_registry.is_session_idle(record, idle_timeout=0) is False
        assert session_registry.session_allows_access(
            ccache, idle_timeout=0, client_ip='203.0.113.1',
            bind_ip=True) is True
        assert os.path.isfile(ccache)

    def test_bind_session_ccache_does_not_touch_last_activity(
            self, registry_dir):
        _reg, ccache_dir = registry_dir
        stale = _make_ccache(ccache_dir, 'kinit_1')
        live = _make_ccache(ccache_dir, 'user1@IPA.TEST-abc')
        cookie = 'MagBearerToken=rebind'
        sid = session_registry.register_web_session(
            cookie, 'user1@IPA.TEST', stale,
            client_ip='203.0.113.1', max_per_user=0)
        record = session_registry.get_session_by_id(sid)
        record['last_activity'] = 1_111_111
        session_registry._atomic_write(
            session_registry._path_for_id(sid), record)

        assert session_registry.bind_session_ccache(cookie, live) is True
        after = session_registry.get_session_by_id(sid)
        assert after['ccache_path'] == live
        assert after['last_activity'] == 1_111_111
        # Lookup by live path now works; stale path does not.
        assert session_registry.get_session_by_ccache(live)['id'] == sid
        assert session_registry.get_session_by_ccache(stale) is None

    def test_expired_check_does_not_require_activity_touch(
            self, registry_dir, monkeypatch):
        """Idle deny must use previous last_activity; revoke may stamp now.

        Mirrors get_environ_creds order: bind -> allows_access -> (no touch).
        """
        _reg, ccache_dir = registry_dir
        stale = _make_ccache(ccache_dir, 'kinit_old')
        live = _make_ccache(ccache_dir, 'user1@IPA.TEST-live')
        cookie = 'MagBearerToken=no-touch'
        sid = session_registry.register_web_session(
            cookie, 'user1@IPA.TEST', stale,
            client_ip='203.0.113.1', max_per_user=0)
        record = session_registry.get_session_by_id(sid)
        old_activity = int(time.time()) - 120
        record['last_activity'] = old_activity
        session_registry._atomic_write(
            session_registry._path_for_id(sid), record)

        monkeypatch.setattr(session_registry.time, 'time', lambda: 2_000_000)
        assert session_registry.bind_session_ccache(cookie, live) is True
        # Bind must not advance activity.
        assert session_registry.get_session_by_id(sid)['last_activity'] == (
            old_activity)
        assert session_registry.session_allows_access(
            live, idle_timeout=60, client_ip='203.0.113.1',
            bind_ip=True) is False
        revoked = session_registry.get_session_by_id(sid)
        assert revoked['status'] == 'revoked'
        # Revoke stamps last_activity; success-path touch must not have run.
        assert revoked['last_activity'] == 2_000_000
        assert not os.path.isfile(live)


@pytest.mark.tier0
class TestSessionConcurrency:
    def test_max_one_revokes_oldest(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ca = _make_ccache(ccache_dir, 'ca')
        cb = _make_ccache(ccache_dir, 'cb')
        sid_a = session_registry.register_web_session(
            'MagBearerToken=A', 'user1@IPA.TEST', ca,
            client_ip='203.0.113.1', max_per_user=1)
        time.sleep(0.01)
        sid_b = session_registry.register_web_session(
            'MagBearerToken=B', 'user1@IPA.TEST', cb,
            client_ip='203.0.113.2', max_per_user=1)
        assert sid_a != sid_b
        assert session_registry.get_session_by_id(sid_a)['status'] == 'revoked'
        assert session_registry.get_session_by_id(sid_b)['status'] == 'active'
        assert not os.path.isfile(ca)
        assert os.path.isfile(cb)

    def test_max_two_keeps_newest(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ca = _make_ccache(ccache_dir, 'ca')
        cb = _make_ccache(ccache_dir, 'cb')
        cc = _make_ccache(ccache_dir, 'cc')
        sid_a = session_registry.register_web_session(
            'MagBearerToken=A2', 'user1@IPA.TEST', ca, max_per_user=2)
        time.sleep(0.01)
        sid_b = session_registry.register_web_session(
            'MagBearerToken=B2', 'user1@IPA.TEST', cb, max_per_user=2)
        time.sleep(0.01)
        sid_c = session_registry.register_web_session(
            'MagBearerToken=C2', 'user1@IPA.TEST', cc, max_per_user=2)
        assert session_registry.get_session_by_id(sid_a)['status'] == 'revoked'
        assert session_registry.get_session_by_id(sid_b)['status'] == 'active'
        assert session_registry.get_session_by_id(sid_c)['status'] == 'active'
        assert not os.path.isfile(ca)
        assert os.path.isfile(cb)
        assert os.path.isfile(cc)

    def test_max_zero_unlimited(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ids = []
        for i in range(3):
            ccache = _make_ccache(ccache_dir, 'u%d' % i)
            sid = session_registry.register_web_session(
                'MagBearerToken=U%d' % i, 'user1@IPA.TEST', ccache,
                max_per_user=0)
            ids.append(sid)
            time.sleep(0.01)
        active = session_registry.list_web_sessions()
        assert len(active) == 3
        for sid in ids:
            assert session_registry.get_session_by_id(sid)['status'] == 'active'

    def test_other_user_not_revoked(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ca = _make_ccache(ccache_dir, 'alice')
        cb = _make_ccache(ccache_dir, 'bob')
        sid_a = session_registry.register_web_session(
            'MagBearerToken=alice', 'alice@IPA.TEST', ca, max_per_user=1)
        sid_b = session_registry.register_web_session(
            'MagBearerToken=bob', 'bob@IPA.TEST', cb, max_per_user=1)
        assert session_registry.get_session_by_id(sid_a)['status'] == 'active'
        assert session_registry.get_session_by_id(sid_b)['status'] == 'active'


@pytest.mark.tier0
class TestSessionIpBinding:
    def test_same_ip_allowed(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        session_registry.register_web_session(
            'MagBearerToken=ip-ok', 'user1@IPA.TEST', ccache,
            client_ip='203.0.113.10', max_per_user=0)
        assert session_registry.session_allows_access(
            ccache, client_ip='203.0.113.10', bind_ip=True,
            idle_timeout=0) is True
        assert os.path.isfile(ccache)

    def test_changed_ip_revokes_and_denies(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=ip-bad', 'user1@IPA.TEST', ccache,
            client_ip='203.0.113.10', max_per_user=0)
        assert session_registry.session_allows_access(
            ccache, client_ip='198.51.100.20', bind_ip=True,
            idle_timeout=0) is False
        assert session_registry.get_session_by_id(sid)['status'] == 'revoked'
        assert not os.path.isfile(ccache)
        assert session_registry.session_allows_access(
            ccache, client_ip='203.0.113.10', bind_ip=True,
            idle_timeout=0) is False

    def test_bind_disabled_allows_ip_change(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        session_registry.register_web_session(
            'MagBearerToken=ip-off', 'user1@IPA.TEST', ccache,
            client_ip='203.0.113.10', max_per_user=0)
        assert session_registry.session_allows_access(
            ccache, client_ip='198.51.100.20', bind_ip=False,
            idle_timeout=0) is True
        assert os.path.isfile(ccache)

    def test_missing_stored_ip_denied(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=ip-miss', 'user1@IPA.TEST', ccache,
            client_ip='', max_per_user=0)
        assert session_registry.session_allows_access(
            ccache, client_ip='203.0.113.10', bind_ip=True,
            idle_timeout=0) is False
        assert session_registry.get_session_by_id(sid)['status'] == 'revoked'

    def test_missing_request_ip_denied(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        sid = session_registry.register_web_session(
            'MagBearerToken=ip-noreq', 'user1@IPA.TEST', ccache,
            client_ip='203.0.113.10', max_per_user=0)
        assert session_registry.session_allows_access(
            ccache, client_ip=None, bind_ip=True, idle_timeout=0) is False
        assert session_registry.get_session_by_id(sid)['status'] == 'revoked'


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

    def test_session_kill_by_user_revokes_all(self, registry_dir):
        _reg, ccache_dir = registry_dir
        c1 = _make_ccache(ccache_dir, name='c1')
        c2 = _make_ccache(ccache_dir, name='c2')
        sid1 = session_registry.register_web_session(
            'MagBearerToken=u1a', 'ali2@IPA.TEST', c1, max_per_user=0)
        sid2 = session_registry.register_web_session(
            'MagBearerToken=u1b', 'ali2@IPA.TEST', c2, max_per_user=0)
        other = _make_ccache(ccache_dir, name='c3')
        session_registry.register_web_session(
            'MagBearerToken=other', 'other@IPA.TEST', other, max_per_user=0)

        cmd = self._cmd(session_plugin.session_kill)
        context.principal = 'admin@IPA.TEST'
        entry = mock.MagicMock()
        entry.get.return_value = [
            'cn=admins,cn=groups,cn=accounts,dc=ipa,dc=test'
        ]
        cmd.api.Backend.ldap2.get_entry.return_value = entry
        result = cmd.execute(user='ali2')
        assert result['value'] == 'ali2'
        assert result['result']['revoked_count'] == 2
        assert session_registry.get_session_by_id(sid1)['status'] == 'revoked'
        assert session_registry.get_session_by_id(sid2)['status'] == 'revoked'
        assert not os.path.isfile(c1)
        assert not os.path.isfile(c2)
        assert os.path.isfile(other)

    def test_session_kill_by_user_noop(self, registry_dir):
        _reg, _ccache_dir = registry_dir
        cmd = self._cmd(session_plugin.session_kill)
        context.principal = 'admin@IPA.TEST'
        entry = mock.MagicMock()
        entry.get.return_value = [
            'cn=admins,cn=groups,cn=accounts,dc=ipa,dc=test'
        ]
        cmd.api.Backend.ldap2.get_entry.return_value = entry
        result = cmd.execute(user='nobody')
        assert result['result']['revoked_count'] == 0
        assert 'No active web sessions' in result['summary']

    def test_session_kill_user_requires_admin(self, registry_dir):
        _reg, ccache_dir = registry_dir
        ccache = _make_ccache(ccache_dir)
        session_registry.register_web_session(
            'MagBearerToken=x', 'ali2@IPA.TEST', ccache)
        cmd = self._cmd(session_plugin.session_kill)
        context.principal = 'ali2@IPA.TEST'
        entry = mock.MagicMock()
        entry.get.return_value = []
        cmd.api.Backend.ldap2.get_entry.return_value = entry
        with pytest.raises(errors.ACIError):
            cmd.execute(user='ali2')

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
