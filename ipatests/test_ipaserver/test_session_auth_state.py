# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""Unit tests for anonymous Web UI auth_state bootstrap probe."""

from __future__ import absolute_import

import io
import json
import os
import time
from unittest import mock

import pytest

from ipaserver import session_registry
from ipaserver import rpcserver


@pytest.fixture
def sess_dirs(tmp_path, monkeypatch):
    directory = str(tmp_path / 'web_sessions')
    os.makedirs(directory, mode=0o700)
    monkeypatch.setattr(session_registry.paths, 'IPA_WEB_SESSIONS', directory)
    monkeypatch.setattr(session_registry.paths, 'IPA_CCACHES', str(tmp_path))
    return directory


@pytest.mark.tier0
class TestWebSessionCookieIsActive:
    def test_missing_cookie_false(self, sess_dirs):
        assert session_registry.web_session_cookie_is_active(None) is False
        assert session_registry.web_session_cookie_is_active('') is False

    def test_active_cookie_true(self, sess_dirs, tmp_path):
        ccache = str(tmp_path / 'cc')
        open(ccache, 'w').write('x')
        sid = session_registry.register_web_session(
            'MagBearerToken=abc123sessioncookie',
            'user1@IPA.TEST',
            ccache,
            client_ip='203.0.113.10',
            max_per_user=0)
        assert sid
        assert session_registry.web_session_cookie_is_active(
            'MagBearerToken=abc123sessioncookie',
            client_ip='203.0.113.10',
            idle_timeout=1800,
            bind_ip=True) is True

    def test_does_not_expose_or_require_touch(self, sess_dirs, tmp_path):
        ccache = str(tmp_path / 'cc')
        open(ccache, 'w').write('x')
        cookie = 'MagBearerToken=xyz'
        session_registry.register_web_session(
            cookie, 'user1@IPA.TEST', ccache,
            client_ip='203.0.113.10', max_per_user=0)
        rec = session_registry.get_session_by_id(
            session_registry.session_id_from_cookie(cookie))
        before = rec['last_activity']
        time.sleep(1)
        assert session_registry.web_session_cookie_is_active(
            cookie, client_ip='203.0.113.10', idle_timeout=1800,
            bind_ip=True) is True
        rec2 = session_registry.get_session_by_id(rec['id'])
        assert rec2['last_activity'] == before


@pytest.mark.tier0
class TestSessionAuthStateEndpoint:
    def _app(self, monkeypatch, authenticated, auto_krb=False):
        api = mock.MagicMock()
        api.env.web_session_idle_timeout = 1800
        api.env.web_session_bind_ip = True
        api.env.webui_auto_kerberos_login = auto_krb
        app = rpcserver.session_auth_state(api)
        monkeypatch.setattr(
            session_registry, 'web_session_cookie_is_active',
            mock.MagicMock(return_value=authenticated))
        return app

    def test_get_unauthenticated_no_negotiate(self, monkeypatch):
        from ipatests.test_ipaserver.test_rpcserver import StartResponse
        app = self._app(monkeypatch, False, auto_krb=False)
        environ = {
            'REQUEST_METHOD': 'GET',
            'REMOTE_ADDR': '203.0.113.1',
            'HTTP_COOKIE': '',
        }
        sr = StartResponse()
        body = b''.join(app(environ, sr))
        assert sr.status.startswith('200')
        assert not any(h[0].lower() == 'www-authenticate' for h in sr.headers)
        data = json.loads(body.decode('utf-8'))
        assert data == {
            'authenticated': False,
            'kerberos_auto_login': False,
        }
        assert 'principal' not in data
        assert 'username' not in data
        assert 'session' not in data

    def test_get_authenticated_minimal(self, monkeypatch):
        from ipatests.test_ipaserver.test_rpcserver import StartResponse
        app = self._app(monkeypatch, True, auto_krb=True)
        environ = {
            'REQUEST_METHOD': 'GET',
            'REMOTE_ADDR': '203.0.113.1',
            'HTTP_COOKIE': 'ipa_session=MagBearerToken=secretvalue',
        }
        sr = StartResponse()
        body = b''.join(app(environ, sr))
        assert sr.status.startswith('200')
        data = json.loads(body.decode('utf-8'))
        assert data['authenticated'] is True
        assert data['kerberos_auto_login'] is True
        assert 'secretvalue' not in body.decode('utf-8')

    def test_put_rejected(self, monkeypatch):
        from ipatests.test_ipaserver.test_rpcserver import StartResponse
        app = self._app(monkeypatch, False)
        environ = {'REQUEST_METHOD': 'PUT', 'REMOTE_ADDR': '127.0.0.1'}
        sr = StartResponse()
        list(app(environ, sr))
        assert sr.status.startswith('405')
