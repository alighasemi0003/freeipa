# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""Static checks for FreeIPA Apache HTTP method restrictions."""

from __future__ import absolute_import

import os
import re

import pytest


def _template_path():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, '..', '..'))
    return os.path.join(repo, 'install', 'share', 'ipa.conf.template')


def _read_template():
    path = _template_path()
    assert os.path.isfile(path)
    return open(path, encoding='utf-8').read()


def _location_ipa_block(text):
    """Return the body of the main <Location \"/ipa\"> section."""
    match = re.search(
        r'<Location\s+"/ipa"\s*>(.*?)</Location>',
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    assert match is not None, 'main <Location "/ipa"> not found'
    return match.group(1)


@pytest.mark.tier0
class TestIpaConfHttpMethods:
    def test_allowmethods_get_post_on_ipa_location(self):
        block = _location_ipa_block(_read_template())
        # Tolerate flexible whitespace; require exact method set.
        am = re.search(
            r'AllowMethods\s+(.+?)(?:\n|$)',
            block,
            flags=re.IGNORECASE,
        )
        assert am is not None, 'AllowMethods missing under Location "/ipa"'
        methods = [m.upper() for m in am.group(1).split()]
        assert methods == ['GET', 'POST']

    def test_disallowed_methods_not_in_allowlist(self):
        block = _location_ipa_block(_read_template())
        am = re.search(
            r'AllowMethods\s+(.+?)(?:\n|$)',
            block,
            flags=re.IGNORECASE,
        )
        assert am is not None
        methods = {m.upper() for m in am.group(1).split()}
        for forbidden in ('PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE',
                          'CONNECT', 'HEAD'):
            assert forbidden not in methods

    def test_no_nested_allowmethods_override(self):
        text = _read_template()
        # Nested Location/Directory must not reset or widen methods.
        for match in re.finditer(
                r'AllowMethods\s+(.+?)(?:\n|$)',
                text,
                flags=re.IGNORECASE):
            methods = [m.upper() for m in match.group(1).split()]
            assert methods == ['GET', 'POST'], (
                'unexpected AllowMethods: %s' % methods
            )
        assert 'AllowMethods reset' not in text

    def test_trace_remains_disabled(self):
        text = _read_template()
        assert re.search(
            r'(?im)^\s*TraceEnable\s+Off\s*$', text
        ), 'TraceEnable Off must remain'

    def test_security_headers_preserved(self):
        text = _read_template()
        assert 'Strict-Transport-Security' in text
        assert 'max-age=31536000' in text
        assert 'Header always append X-Frame-Options DENY' in text
        assert 'Header always set X-Content-Type-Options "nosniff"' in text
        assert (
            'Header always set Referrer-Policy '
            '"strict-origin-when-cross-origin"'
        ) in text
        assert 'Content-Security-Policy' in text
        assert "frame-ancestors 'none'" in text

    def test_rewrite_method_gate_in_ssl_vhost_template(self):
        """Satisfy Any bypasses AllowMethods; rewrite gate must remain."""
        here = os.path.dirname(os.path.abspath(__file__))
        repo = os.path.abspath(os.path.join(here, '..', '..'))
        path = os.path.join(
            repo, 'install', 'share', 'ipa-rewrite.conf.template')
        assert os.path.isfile(path)
        text = open(path, encoding='utf-8').read()
        assert 'RewriteCond %{REQUEST_URI} ^/ipa(/|$)' in text
        assert (
            'RewriteCond %{REQUEST_METHOD} !^(GET|POST|HEAD)$' in text
        )
        assert re.search(
            r'(?m)^\s*RewriteRule\s+\^\s+-\s+\[R=405,L\]\s*$', text
        ), 'R=405 rewrite method gate missing'
        # VERSION line must be bumped when rewrite semantics change
        assert re.search(r'(?m)^# VERSION \d+', text)
