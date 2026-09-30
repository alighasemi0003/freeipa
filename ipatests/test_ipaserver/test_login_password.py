# Copyright (C) 2023  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import urllib.parse
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest
import uuid

from ipatests.test_ipaserver.httptest import Unauthorized_HTTP_test
from ipatests.test_ipaserver.test_rpcserver import StartResponse
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.util import assert_equal
from ipalib import api, errors
from ipapython.ipautil import run
from ipaserver import rpcserver

testuser = u'tuser'
password = u'password'

GENERIC_LOGIN_FAILURE = (
    'The password or username you entered is incorrect'
)


@pytest.mark.tier1
class test_login_password(XMLRPC_test, Unauthorized_HTTP_test):
    app_uri = '/ipa/session/login_password'

    @pytest.fixture(autouse=True)
    def login_setup(self, request):
        ccache = os.path.join('/tmp', str(uuid.uuid4()))
        try:
            api.Command['user_add'](uid=testuser, givenname=u'Test', sn=u'User')
            api.Command['passwd'](testuser, password=password)
            run(['kinit', testuser], stdin='{0}\n{0}\n{0}\n'.format(password),
                env={"KRB5CCNAME": ccache})
        except errors.ExecutionError as e:
            pytest.skip(
                'Cannot set up test user: %s' % e
            )

        def fin():
            try:
                api.Command['user_del']([testuser])
            except errors.NotFound:
                pass
            os.unlink(ccache)

        request.addfinalizer(fin)

    def _login(self, user, password, host=None):
        return self.send_request(params={'user': str(user),
                                 'password' : str(password)},
                                 host=host)

    def test_bad_options(self):
        for params in (
            None,                             # no params
            {"user": "foo"},                  # missing options
            {"user": "foo", "password": ""},  # empty option
        ):
            response = self.send_request(params=params)
            assert_equal(response.status, 400)
            assert_equal(response.reason, 'Bad Request')

    def test_invalid_auth(self):
        response = self._login(testuser, 'wrongpassword')

        assert_equal(response.status, 401)
        assert_equal(response.getheader('X-IPA-Rejection-Reason'),
                     'invalid-password')
        body = response.read().decode('utf-8')
        assert GENERIC_LOGIN_FAILURE in body
        assert 'not found in Kerberos database' not in body
        assert 'kinit:' not in body

    def test_invalid_referer(self):
        response = self._login(testuser, password, 'attacker.test')

        assert_equal(response.status, 400)

    def test_success(self):
        response = self._login(testuser, password)

        assert_equal(response.status, 200)
        assert response.getheader('X-IPA-Rejection-Reason') is None


@pytest.mark.tier0
class test_login_password_failure_messages:
    """Unit tests for unauthenticated login_password failure translation."""

    def _handler(self):
        mock_api = MagicMock()
        mock_api.env.host = 'ipa.example.test'
        mock_api.env.in_tree = True
        mock_api.env.kinit_lifetime = None
        return rpcserver.login_password(mock_api)

    def _environ(self, user='testuser', password='badpassword'):
        body = urllib.parse.urlencode(
            {'user': user, 'password': password}
        ).encode('utf-8')
        return {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'CONTENT_LENGTH': str(len(body)),
            'wsgi.input': BytesIO(body),
            'HTTP_REFERER': 'https://ipa.example.test/ipa/ui/',
        }

    def _assert_generic_invalid_password(self, status, headers, body):
        assert status == '401 Unauthorized'
        assert ('X-IPA-Rejection-Reason', 'invalid-password') in headers
        assert GENERIC_LOGIN_FAILURE in body
        assert 'not found in Kerberos database' not in body
        assert 'credentials have been revoked' not in body
        assert 'has expired while getting initial credentials' not in body
        assert 'kinit:' not in body

    def _call_with_kinit_error(self, exc):
        handler = self._handler()
        start_response = StartResponse()
        with patch.object(handler, 'check_referer', return_value=True):
            with patch.object(handler, 'kinit', side_effect=exc):
                output = handler(self._environ(), start_response)
        body = b''.join(output).decode('utf-8')
        return start_response.status, start_response.headers, body

    def test_nonexistent_principal_maps_to_generic_invalid_password(self):
        exc = errors.InvalidSessionPassword(
            principal='missing',
            message=(
                "kinit: Client 'missing' not found in Kerberos database "
                "while getting initial credentials"
            ),
        )
        status, headers, body = self._call_with_kinit_error(exc)
        self._assert_generic_invalid_password(status, headers, body)

    def test_invalid_password_maps_to_generic_invalid_password(self):
        exc = errors.InvalidSessionPassword(
            principal='testuser',
            message=(
                "kinit: Preauthentication failed while getting "
                "initial credentials"
            ),
        )
        status, headers, body = self._call_with_kinit_error(exc)
        self._assert_generic_invalid_password(status, headers, body)

    def test_user_locked_maps_to_generic_invalid_password(self):
        exc = errors.UserLocked(
            principal='testuser',
            message=(
                "kinit: Client's credentials have been revoked "
                "while getting initial credentials"
            ),
        )
        status, headers, body = self._call_with_kinit_error(exc)
        self._assert_generic_invalid_password(status, headers, body)

    def test_krbprincipal_expired_maps_to_generic_invalid_password(self):
        exc = errors.KrbPrincipalExpired(
            principal='testuser',
            message=(
                "kinit: Client's entry in database has expired "
                "while getting initial credentials"
            ),
        )
        status, headers, body = self._call_with_kinit_error(exc)
        self._assert_generic_invalid_password(status, headers, body)

    def test_password_expired_preserves_rejection_reason(self):
        exc = errors.PasswordExpired(
            principal='testuser',
            message=(
                "kinit: Cannot read password while getting "
                "initial credentials"
            ),
        )
        status, headers, body = self._call_with_kinit_error(exc)
        assert status == '401 Unauthorized'
        assert ('X-IPA-Rejection-Reason', 'password-expired') in headers
        # Must remain distinguishable for the change-password UI flow.
        assert ('X-IPA-Rejection-Reason', 'invalid-password') not in headers
        assert GENERIC_LOGIN_FAILURE not in body
