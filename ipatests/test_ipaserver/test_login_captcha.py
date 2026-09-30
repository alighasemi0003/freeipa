# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""Unit tests for offline login CAPTCHA."""

from __future__ import absolute_import

import os
import time
from unittest import mock

import pytest

from ipaserver import login_captcha


@pytest.fixture
def captcha_dirs(tmp_path, monkeypatch):
    challenges = str(tmp_path / 'login_captcha')
    keyfile = str(tmp_path / 'login_captcha.key')
    os.makedirs(challenges, mode=0o700)
    monkeypatch.setattr(login_captcha.paths, 'IPA_LOGIN_CAPTCHA', challenges)
    monkeypatch.setattr(login_captcha.paths, 'IPA_LOGIN_CAPTCHA_KEY', keyfile)
    return challenges, keyfile


@pytest.mark.tier0
class TestLoginCaptcha:
    def test_challenge_id_not_trivial(self, captcha_dirs):
        a = login_captcha.create_challenge('203.0.113.10', ttl=120, length=6)
        b = login_captcha.create_challenge('203.0.113.10', ttl=120, length=6)
        assert a['id'] != b['id']
        assert len(a['id']) >= 16
        assert a['id'].isalnum() or '-' in a['id'] or '_' in a['id']

    def test_answer_not_returned_to_client(self, captcha_dirs):
        public = login_captcha.create_challenge('203.0.113.10')
        assert 'answer' not in public
        assert 'verifier' not in public
        assert 'image' in public and public['image'].startswith('<?xml')
        assert 'id' in public

    def test_correct_answer_passes(self, captcha_dirs):
        public = login_captcha.create_challenge('203.0.113.10', length=6)
        path = login_captcha._path_for_id(public['id'])
        # Recover answer by brute of alphabet for test length-6 is hard;
        # instead create with known answer path: write verifier for known ans.
        answer = 'ABCD23'
        record = {
            'id': public['id'],
            'verifier': login_captcha.answer_verifier(answer),
            'created': int(time.time()),
            'expires': int(time.time()) + 120,
            'used': False,
            'client_ip': '203.0.113.10',
        }
        login_captcha._atomic_write(path, record)
        assert login_captcha.verify_and_consume(
            public['id'], answer, '203.0.113.10') is True

    def test_wrong_answer_fails_and_consumes(self, captcha_dirs):
        public = login_captcha.create_challenge('203.0.113.10')
        path = login_captcha._path_for_id(public['id'])
        assert os.path.isfile(path)
        assert login_captcha.verify_and_consume(
            public['id'], 'WRONG1', '203.0.113.10') is False
        assert not os.path.isfile(path)
        # replay
        assert login_captcha.verify_and_consume(
            public['id'], 'WRONG1', '203.0.113.10') is False

    def test_replay_fails(self, captcha_dirs):
        cid = 'replayTestToken_abc123'
        path = login_captcha._path_for_id(cid)
        login_captcha.ensure_registry_dir()
        answer = 'TEST23'
        login_captcha._atomic_write(path, {
            'id': cid,
            'verifier': login_captcha.answer_verifier(answer),
            'created': int(time.time()),
            'expires': int(time.time()) + 120,
            'used': False,
            'client_ip': '203.0.113.10',
        })
        assert login_captcha.verify_and_consume(
            cid, answer, '203.0.113.10') is True
        assert login_captcha.verify_and_consume(
            cid, answer, '203.0.113.10') is False

    def test_expired_fails(self, captcha_dirs):
        cid = 'expiredToken_xyz'
        login_captcha.ensure_registry_dir()
        login_captcha._atomic_write(login_captcha._path_for_id(cid), {
            'id': cid,
            'verifier': login_captcha.answer_verifier('ABCD23'),
            'created': int(time.time()) - 1000,
            'expires': int(time.time()) - 10,
            'used': False,
            'client_ip': '203.0.113.10',
        })
        assert login_captcha.verify_and_consume(
            cid, 'ABCD23', '203.0.113.10') is False

    def test_different_ip_fails(self, captcha_dirs):
        cid = 'ipBindToken_xyz'
        login_captcha.ensure_registry_dir()
        login_captcha._atomic_write(login_captcha._path_for_id(cid), {
            'id': cid,
            'verifier': login_captcha.answer_verifier('ABCD23'),
            'created': int(time.time()),
            'expires': int(time.time()) + 120,
            'used': False,
            'client_ip': '203.0.113.10',
        })
        assert login_captcha.verify_and_consume(
            cid, 'ABCD23', '198.51.100.20') is False

    def test_svg_has_no_answer_metadata(self, captcha_dirs):
        answer = 'AB2CD3'
        svg = login_captcha.render_svg(answer)
        assert '<title' not in svg.lower()
        assert '<desc' not in svg.lower()
        assert 'aria-label' not in svg.lower()
        assert '<!--' not in svg
        assert login_captcha.svg_contains_answer_leak(svg, answer) is False

    def test_unsafe_challenge_id_rejected(self, captcha_dirs):
        assert login_captcha.verify_and_consume(
            '../etc/passwd', 'x', '127.0.0.1') is False
        assert login_captcha.verify_and_consume(
            'a' * 200, 'x', '127.0.0.1') is False

    def test_disabled_resolve(self):
        assert login_captcha.resolve_enabled(False) is False
        assert login_captcha.resolve_enabled('false') is False
        assert login_captcha.resolve_enabled(True) is True

    def test_ttl_and_length_clamped(self):
        assert login_captcha.resolve_ttl(5) == login_captcha.TTL_MIN
        assert login_captcha.resolve_ttl(99999) == login_captcha.TTL_MAX
        assert login_captcha.resolve_length(1) == login_captcha.LENGTH_MIN
        assert login_captcha.resolve_length(99) == login_captcha.LENGTH_MAX


@pytest.mark.tier0
class TestLoginPasswordCaptchaGate:
    def test_captcha_failure_does_not_call_kinit(self, captcha_dirs, monkeypatch):
        from ipaserver.rpcserver import login_password
        from ipatests.test_ipaserver.test_rpcserver import StartResponse

        api = mock.MagicMock()
        api.env.login_captcha_enabled = True
        api.env.kinit_lifetime = None
        app = login_password(api)
        app.check_referer = mock.MagicMock(return_value=True)

        kinit_called = []

        def boom(*a, **k):
            kinit_called.append(True)
            raise AssertionError('kinit must not run')

        monkeypatch.setattr(app, 'kinit', boom)

        body = 'user=somebody&password=Secret123'
        environ = {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'CONTENT_LENGTH': str(len(body)),
            'REMOTE_ADDR': '203.0.113.10',
            'wsgi.input': __import__('io').BytesIO(body.encode('utf-8')),
        }
        sr = StartResponse()
        # Missing captcha
        list(app(environ, sr))
        assert sr.status.startswith('401')
        assert any(
            h[0] == 'X-IPA-Rejection-Reason' and h[1] == 'invalid-captcha'
            for h in sr.headers
        )
        assert kinit_called == []
