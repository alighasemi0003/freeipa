# Copyright (C) 2026  FreeIPA Contributors see COPYING for license

"""Static checks for FreeIPA Apache security headers in ipa.conf.template."""

from __future__ import absolute_import

import os

import pytest


def _template_path():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, '..', '..'))
    return os.path.join(repo, 'install', 'share', 'ipa.conf.template')


@pytest.mark.tier0
class TestIpaConfSecurityHeaders:
    def test_hsts_present_https_only(self):
        path = _template_path()
        assert os.path.isfile(path)
        text = open(path, encoding='utf-8').read()
        assert 'Strict-Transport-Security' in text
        line = [
            ln for ln in text.splitlines()
            if 'Strict-Transport-Security' in ln
        ][0]
        assert 'max-age=31536000' in line
        assert 'includeSubDomains' not in line
        assert 'preload' not in line
        assert 'env=HTTPS' in line

    def test_existing_security_headers_preserved(self):
        text = open(_template_path(), encoding='utf-8').read()
        assert 'Header always append X-Frame-Options DENY' in text
        assert 'Header always set X-Content-Type-Options "nosniff"' in text
        assert (
            'Header always set Referrer-Policy '
            '"strict-origin-when-cross-origin"'
        ) in text
        assert "frame-ancestors 'none'" in text
        assert "'unsafe-inline'" in text
        assert "'unsafe-eval'" in text
