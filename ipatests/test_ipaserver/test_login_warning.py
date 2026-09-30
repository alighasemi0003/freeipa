# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""Unit tests for configurable pre-auth login warning banner."""

from __future__ import absolute_import

from types import SimpleNamespace

import pytest

from ipalib.constants import DEFAULT_CONFIG
from ipaserver.plugins.internal import get_login_warning, i18n_messages


@pytest.mark.tier0
class TestGetLoginWarning:
    def test_missing_returns_empty(self):
        assert get_login_warning(None) == u''
        assert get_login_warning(SimpleNamespace()) == u''

    def test_empty_or_whitespace_returns_empty(self):
        assert get_login_warning(SimpleNamespace(login_warning='')) == u''
        assert get_login_warning(SimpleNamespace(login_warning='   ')) == u''
        assert get_login_warning(SimpleNamespace(login_warning=None)) == u''

    def test_configured_text_returned(self):
        text = u'Authorized use only. Activity may be monitored.'
        assert get_login_warning(SimpleNamespace(login_warning=text)) == text

    def test_html_like_input_returned_as_plain_text(self):
        payload = u'<script>alert(1)</script>'
        result = get_login_warning(SimpleNamespace(login_warning=payload))
        assert result == payload
        assert '<script>' in result


@pytest.mark.tier0
class TestLoginWarningDefaultConfig:
    def test_default_config_key_present_and_empty(self):
        config = dict(DEFAULT_CONFIG)
        assert 'login_warning' in config
        assert config['login_warning'] == ''


@pytest.mark.tier0
class TestI18nMessagesLoginWarning:
    def test_execute_includes_login_warning(self):
        env = SimpleNamespace(login_warning=u'Authorized use only.')
        api = SimpleNamespace(env=env)
        result = i18n_messages(api).execute()
        assert result['login_warning'] == u'Authorized use only.'
        assert 'texts' in result

    def test_execute_empty_when_unset(self):
        api = SimpleNamespace(env=SimpleNamespace())
        result = i18n_messages(api).execute()
        assert result['login_warning'] == u''

    def test_execute_html_like_not_stripped_of_tags(self):
        """Tags remain in the string; UIs must render as text, not HTML."""
        payload = u'<script>alert(1)</script>'
        api = SimpleNamespace(env=SimpleNamespace(login_warning=payload))
        result = i18n_messages(api).execute()
        assert result['login_warning'] == payload
