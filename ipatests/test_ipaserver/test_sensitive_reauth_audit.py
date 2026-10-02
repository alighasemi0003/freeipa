# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""Unit tests for sensitive reauth security audit logging."""

from __future__ import absolute_import

import io
from unittest import mock

import pytest

from ipaserver import rpcserver


@pytest.mark.tier0
class TestSensitiveReauthAuditLogging:
    def _make_app(self, monkeypatch, record, kinit_side_effect=None):
        api = mock.MagicMock()
        app = rpcserver.session_verify_credentials(api)
        app.check_referer = mock.MagicMock(return_value=True)
        app.get_environ_creds = mock.MagicMock(return_value='/tmp/fake.ccache')

        monkeypatch.setattr(
            'ipaserver.session_registry.get_session_by_ccache',
            mock.MagicMock(return_value=record))
        monkeypatch.setattr(
            'ipaserver.session_registry.mark_session_reauth',
            mock.MagicMock(return_value=True))
        monkeypatch.setattr(rpcserver, 'kinit_armor', mock.MagicMock())
        if kinit_side_effect is None:
            monkeypatch.setattr(rpcserver, 'kinit_password', mock.MagicMock())
        else:
            monkeypatch.setattr(
                rpcserver, 'kinit_password',
                mock.MagicMock(side_effect=kinit_side_effect))
        return app

    def test_reauth_success_info_audit_no_secrets(self, monkeypatch):
        from ipatests.test_ipaserver.test_rpcserver import StartResponse

        record = {
            'id': 'a' * 64,
            'status': 'active',
            'principal': 'user1@IPA.TEST',
        }
        app = self._make_app(monkeypatch, record)
        info_msgs = []

        def capture_info(msg, *args, **kwargs):
            info_msgs.append(msg % args if args else msg)

        monkeypatch.setattr(rpcserver.logger, 'info', capture_info)

        body = 'password=Secret123&otp=123456'
        environ = {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'CONTENT_LENGTH': str(len(body)),
            'REMOTE_ADDR': '203.0.113.50',
            'GSS_NAME': 'user1@IPA.TEST',
            'wsgi.input': io.BytesIO(body.encode('utf-8')),
        }
        sr = StartResponse()
        out = list(app(environ, sr))
        assert sr.status.startswith('200')
        assert b''.join(out) == b'ok'
        joined = '\n'.join(info_msgs)
        assert 'sensitive_reauth verification succeeded' in joined
        assert 'result=success' in joined
        assert 'principal=user1' in joined
        assert 'remote_addr=203.0.113.50' in joined
        assert 'Secret123' not in joined
        assert '123456' not in joined
        assert 'a' * 64 not in joined

    def test_reauth_failure_info_audit_no_secrets(self, monkeypatch):
        from ipatests.test_ipaserver.test_rpcserver import StartResponse

        record = {
            'id': 'b' * 64,
            'status': 'active',
            'principal': 'user1@IPA.TEST',
        }
        app = self._make_app(
            monkeypatch, record,
            kinit_side_effect=Exception('Password incorrect'))
        info_msgs = []

        def capture_info(msg, *args, **kwargs):
            info_msgs.append(msg % args if args else msg)

        monkeypatch.setattr(rpcserver.logger, 'info', capture_info)

        body = 'password=WrongPass1!'
        environ = {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'CONTENT_LENGTH': str(len(body)),
            'REMOTE_ADDR': '203.0.113.50',
            'GSS_NAME': 'user1@IPA.TEST',
            'wsgi.input': io.BytesIO(body.encode('utf-8')),
        }
        sr = StartResponse()
        list(app(environ, sr))
        assert sr.status.startswith('401')
        joined = '\n'.join(info_msgs)
        assert 'sensitive_reauth verification failed' in joined
        assert 'result=failure' in joined
        assert 'WrongPass1!' not in joined
        assert 'b' * 64 not in joined
