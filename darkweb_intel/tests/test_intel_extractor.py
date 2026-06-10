"""
Unit tests for IntelExtractor — no Tor or network required.
"""

import pytest
from darkweb_intel.intel_extractor import IntelExtractor


SAMPLE_HTML = """
<html><body>
<p>Contact us: admin@acmecorp.com or support@acmecorp.com</p>
<p>Leaked dump: user@victim.org:P@ssw0rd123</p>
<p>BTC wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf8 for payment.</p>
<p>ETH address: 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe</p>
<p>This forum discusses AcmeCorp and acmecorp.com services.</p>
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2
mQENBFakeKeyBCAC...
-----END PGP PUBLIC KEY BLOCK-----
</body></html>
"""


@pytest.fixture
def extractor():
    return IntelExtractor(target_keywords=["AcmeCorp", "acmecorp.com"])


def test_emails_extracted(extractor):
    record = extractor.extract("http://test.onion", SAMPLE_HTML)
    assert "admin@acmecorp.com" in record.emails
    assert "support@acmecorp.com" in record.emails


def test_credentials_extracted(extractor):
    record = extractor.extract("http://test.onion", SAMPLE_HTML)
    assert any(c["user"] == "user@victim.org" for c in record.credentials)


def test_btc_wallet_extracted(extractor):
    record = extractor.extract("http://test.onion", SAMPLE_HTML)
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf8" in record.btc_wallets


def test_eth_wallet_extracted(extractor):
    record = extractor.extract("http://test.onion", SAMPLE_HTML)
    assert "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe" in record.eth_wallets


def test_keyword_hits(extractor):
    record = extractor.extract("http://test.onion", SAMPLE_HTML)
    assert "AcmeCorp" in record.keyword_hits or "acmecorp.com" in record.keyword_hits


def test_pgp_key_extracted(extractor):
    record = extractor.extract("http://test.onion", SAMPLE_HTML)
    assert len(record.pgp_keys) == 1
    assert "BEGIN PGP PUBLIC KEY BLOCK" in record.pgp_keys[0]


def test_has_findings(extractor):
    record = extractor.extract("http://test.onion", SAMPLE_HTML)
    assert record.has_findings


def test_no_findings_on_empty_html(extractor):
    record = extractor.extract("http://test.onion", "<html><body></body></html>")
    assert not record.has_findings
