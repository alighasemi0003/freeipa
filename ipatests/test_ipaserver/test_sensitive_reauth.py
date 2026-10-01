# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""Unit tests for sensitive-action reauthentication policy and session state."""

from __future__ import absolute_import

import os
import time
from unittest import mock

import pytest

from ipalib import errors
from ipaserver import sensitive_reauth
from ipaserver import session_registry


@pytest.fixture(autouse=True)
def _reset_reauth_cache():
    sensitive_reauth.reset_cache()
    yield
    sensitive_reauth.reset_cache()


@pytest.fixture
def sess_dirs(tmp_path, monkeypatch):
    directory = str(tmp_path / 'web_sessions')
    os.makedirs(directory, mode=0o700)
    monkeypatch.setattr(session_registry.paths, 'IPA_WEB_SESSIONS', directory)
    monkeypatch.setattr(session_registry.paths, 'IPA_CCACHES', str(tmp_path))
    return directory


class FakeApi:
    def __init__(self, policy='default', timeout=300, commands=None,
                 in_server=True):
        self.env = mock.MagicMock()
        self.env.in_server = in_server
        self.env.sensitive_action_reauth_policy = policy
        self.env.sensitive_action_reauth_timeout = timeout
        self.env.sensitive_action_reauth_commands = commands
        self.Command = FakeCommands()


class FakeCommands:
    def __contains__(self, name):
        return name in sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS or name in (
            'user_show', 'ping', 'user_add',
        )


@pytest.mark.tier0
class TestSensitiveReauthPolicy:
    def test_default_policy_resolves_builtin(self):
        cmds = sensitive_reauth.resolve_sensitive_commands('default')
        assert 'user_del' in cmds
        assert 'session_kill' in cmds
        assert 'user_show' not in cmds
        assert cmds == sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS

    def test_custom_parses_csv_trims_dedupes(self):
        api = FakeApi()
        cmds = sensitive_reauth.resolve_sensitive_commands(
            'custom',
            ' user_del , user_disable,user_del, session_kill ',
            api=api,
        )
        assert cmds == frozenset(
            ('user_del', 'user_disable', 'session_kill'))

    def test_unknown_commands_skipped(self):
        api = FakeApi()
        cmds = sensitive_reauth.resolve_sensitive_commands(
            'custom', 'user_del,not_a_real_cmd,session_kill', api=api)
        assert 'not_a_real_cmd' not in cmds
        assert cmds == frozenset(('user_del', 'session_kill'))

    def test_all_invalid_custom_falls_back_to_builtin(self):
        api = FakeApi()
        cmds = sensitive_reauth.resolve_sensitive_commands(
            'custom', 'nope1,nope2', api=api)
        assert cmds == sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS

    def test_empty_custom_falls_back(self):
        api = FakeApi()
        cmds = sensitive_reauth.resolve_sensitive_commands(
            'custom', None, api=api)
        assert cmds == sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS

    def test_missing_invalid_policy_default(self):
        assert sensitive_reauth.resolve_policy(None) == 'default'
        assert sensitive_reauth.resolve_policy('bogus') == 'default'

    def test_timeout_default_and_invalid(self):
        assert sensitive_reauth.resolve_timeout(None) == 300
        assert sensitive_reauth.resolve_timeout('x') == 300
        assert sensitive_reauth.resolve_timeout(-1) == 300
        assert sensitive_reauth.resolve_timeout(0) == 0
        assert sensitive_reauth.resolve_timeout(120) == 120

    def test_disabled_policy_empty_set(self):
        assert sensitive_reauth.resolve_sensitive_commands('disabled') == frozenset()


@pytest.mark.tier0
class TestSensitiveReauthGate:
    def _cmd(self, name, api):
        cmd = mock.MagicMock()
        cmd.name = name
        cmd.api = api
        return cmd

    def test_disabled_policy_no_gate(self, sess_dirs, monkeypatch):
        api = FakeApi(policy='disabled')
        monkeypatch.setattr(
            sensitive_reauth, 'get_effective_policy',
            lambda a: ('disabled', 300, frozenset()))
        cookie = 'sesscookieA'
        sid = session_registry.register_web_session(
            cookie, 'admin@IPA.TEST', '/tmp/cc')
        from ipalib.request import context
        context.ccache_name = '/tmp/cc'
        context.principal = 'admin@IPA.TEST'
        # Point ccache path in record
        rec = session_registry.get_session_by_id(sid)
        rec['ccache_path'] = session_registry.normalize_ccache_path('/tmp/cc')
        session_registry._atomic_write(
            session_registry._path_for_id(sid), rec)
        monkeypatch.setattr(
            sensitive_reauth, '_web_session_record',
            lambda c: session_registry.get_session_by_id(sid))
        sensitive_reauth.enforce_if_needed(
            self._cmd('user_del', api), {'uid': 'bob'})

    def test_normal_command_no_reauth(self, sess_dirs, monkeypatch):
        api = FakeApi()
        sensitive_reauth.reset_cache()
        monkeypatch.setattr(
            sensitive_reauth, 'get_effective_policy',
            lambda a: ('default', 300, sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS))
        monkeypatch.setattr(
            sensitive_reauth, '_web_session_record',
            lambda c: {'id': 'abc', 'status': 'active',
                       'principal': 'admin@IPA.TEST',
                       'last_reauth_at': None})
        from ipalib.request import context
        context.ccache_name = 'FILE:/tmp/cc'
        context.principal = 'admin@IPA.TEST'
        sensitive_reauth.enforce_if_needed(
            self._cmd('user_show', api), {'uid': 'bob'})

    def test_sensitive_without_reauth_raises(self, monkeypatch):
        api = FakeApi()
        monkeypatch.setattr(
            sensitive_reauth, 'get_effective_policy',
            lambda a: ('default', 300, sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS))
        monkeypatch.setattr(
            sensitive_reauth, '_web_session_record',
            lambda c: {'id': 'abc', 'status': 'active',
                       'principal': 'admin@IPA.TEST',
                       'last_reauth_at': None})
        from ipalib.request import context
        context.ccache_name = 'FILE:/tmp/cc'
        context.principal = 'admin@IPA.TEST'
        with pytest.raises(errors.ReauthRequired):
            sensitive_reauth.enforce_if_needed(
                self._cmd('user_del', api), {'uid': 'bob'})

    def test_fresh_reauth_allows(self, monkeypatch):
        api = FakeApi()
        now = int(time.time())
        monkeypatch.setattr(
            sensitive_reauth, 'get_effective_policy',
            lambda a: ('default', 300, sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS))
        monkeypatch.setattr(
            sensitive_reauth, '_web_session_record',
            lambda c: {'id': 'abc', 'status': 'active',
                       'principal': 'admin@IPA.TEST',
                       'last_reauth_at': now})
        from ipalib.request import context
        context.ccache_name = 'FILE:/tmp/cc'
        context.principal = 'admin@IPA.TEST'
        sensitive_reauth.enforce_if_needed(
            self._cmd('session_kill', api), {'id': 'x'})

    def test_expired_reauth_raises(self, monkeypatch):
        api = FakeApi()
        monkeypatch.setattr(
            sensitive_reauth, 'get_effective_policy',
            lambda a: ('default', 300, sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS))
        monkeypatch.setattr(
            sensitive_reauth, '_web_session_record',
            lambda c: {'id': 'abc', 'status': 'active',
                       'principal': 'admin@IPA.TEST',
                       'last_reauth_at': int(time.time()) - 999})
        from ipalib.request import context
        context.ccache_name = 'FILE:/tmp/cc'
        context.principal = 'admin@IPA.TEST'
        with pytest.raises(errors.ReauthRequired):
            sensitive_reauth.enforce_if_needed(
                self._cmd('user_disable', api), {'uid': 'bob'})

    def test_timeout_zero_grace_then_consume(self, sess_dirs, monkeypatch):
        api = FakeApi(timeout=0)
        now = int(time.time())
        sid = 'a' * 64
        path = session_registry._path_for_id(sid)
        session_registry.ensure_registry_dir()
        session_registry._atomic_write(path, {
            'id': sid,
            'principal': 'admin@IPA.TEST',
            'username': 'admin',
            'ccache_path': '/tmp/cc',
            'created': now,
            'last_activity': now,
            'last_reauth_at': now,
            'client_ip': '127.0.0.1',
            'status': 'active',
        })
        monkeypatch.setattr(
            sensitive_reauth, 'get_effective_policy',
            lambda a: ('default', 0, sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS))
        monkeypatch.setattr(
            sensitive_reauth, '_web_session_record',
            lambda c: session_registry.get_session_by_id(sid))
        from ipalib.request import context
        context.ccache_name = 'FILE:/tmp/cc'
        context.principal = 'admin@IPA.TEST'
        sensitive_reauth.enforce_if_needed(
            self._cmd('user_del', api), {'uid': 'bob'})
        rec = session_registry.get_session_by_id(sid)
        assert rec.get('last_reauth_at') is None
        with pytest.raises(errors.ReauthRequired):
            sensitive_reauth.enforce_if_needed(
                self._cmd('user_del', api), {'uid': 'bob'})

    def test_self_passwd_exempt(self, monkeypatch):
        api = FakeApi()
        monkeypatch.setattr(
            sensitive_reauth, 'get_effective_policy',
            lambda a: ('default', 300, sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS))
        monkeypatch.setattr(
            sensitive_reauth, '_web_session_record',
            lambda c: {'id': 'abc', 'status': 'active',
                       'principal': 'admin@IPA.TEST',
                       'last_reauth_at': None})
        from ipalib.request import context
        context.ccache_name = 'FILE:/tmp/cc'
        context.principal = 'admin@IPA.TEST'
        # Avoid LDAP normalizer dependency
        monkeypatch.setattr(
            sensitive_reauth, 'is_self_passwd',
            lambda name, params, prin: True)
        sensitive_reauth.enforce_if_needed(
            self._cmd('passwd', api), {'principal': 'admin@IPA.TEST'})

    def test_admin_passwd_gated(self, monkeypatch):
        api = FakeApi()
        monkeypatch.setattr(
            sensitive_reauth, 'get_effective_policy',
            lambda a: ('default', 300, sensitive_reauth.BUILTIN_SENSITIVE_COMMANDS))
        monkeypatch.setattr(
            sensitive_reauth, '_web_session_record',
            lambda c: {'id': 'abc', 'status': 'active',
                       'principal': 'admin@IPA.TEST',
                       'last_reauth_at': None})
        monkeypatch.setattr(
            sensitive_reauth, 'is_self_passwd',
            lambda name, params, prin: False)
        from ipalib.request import context
        context.ccache_name = 'FILE:/tmp/cc'
        context.principal = 'admin@IPA.TEST'
        with pytest.raises(errors.ReauthRequired):
            sensitive_reauth.enforce_if_needed(
                self._cmd('passwd', api), {'principal': 'bob@IPA.TEST'})

    def test_cli_no_web_session_skipped(self, monkeypatch):
        api = FakeApi()
        monkeypatch.setattr(
            sensitive_reauth, '_web_session_record', lambda c: None)
        from ipalib.request import context
        context.ccache_name = 'FILE:/tmp/cli'
        context.principal = 'admin@IPA.TEST'
        sensitive_reauth.enforce_if_needed(
            self._cmd('user_del', api), {'uid': 'bob'})


@pytest.mark.tier0
class TestSessionReauthState:
    def test_mark_and_freshness(self, sess_dirs):
        sid = session_registry.register_web_session(
            'cookie-value-xyz', 'admin@IPA.TEST', '/tmp/cc1',
            client_ip='203.0.113.10')
        rec = session_registry.get_session_by_id(sid)
        assert rec.get('last_reauth_at') is None
        assert session_registry.mark_session_reauth(sid)
        rec = session_registry.get_session_by_id(sid)
        assert rec.get('last_reauth_at')
        assert sensitive_reauth.is_reauth_fresh(rec, 300)
        assert not sensitive_reauth.is_reauth_fresh(
            {'last_reauth_at': int(time.time()) - 10}, 0)

    def test_same_session_id_after_mark(self, sess_dirs):
        sid = session_registry.register_web_session(
            'cookie-stable', 'admin@IPA.TEST', '/tmp/cc2')
        assert session_registry.mark_session_reauth(sid)
        rec = session_registry.get_session_by_id(sid)
        assert rec['id'] == sid
