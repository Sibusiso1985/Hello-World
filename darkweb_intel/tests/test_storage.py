"""
Unit tests for IntelStorage — uses an in-memory SQLite database.
"""

import pytest
from darkweb_intel.intel_extractor import IntelRecord
from darkweb_intel.storage import IntelStorage


@pytest.fixture
def storage(tmp_path):
    return IntelStorage(db_path=tmp_path / "test.db")


def _sample_record(url: str = "http://test.onion/page") -> IntelRecord:
    record = IntelRecord(source_url=url)
    record.emails = ["victim@corp.com"]
    record.credentials = [{"user": "victim@corp.com", "pass": "hunter2"}]
    record.btc_wallets = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf8"]
    record.keyword_hits = {"corp.com": ["...mentioned corp.com here..."]}
    return record


def test_save_and_retrieve(storage):
    record = _sample_record()
    row_id = storage.save(record)
    assert row_id >= 1

    findings = storage.all_findings()
    assert len(findings) == 1
    assert findings[0]["source_url"] == "http://test.onion/page"
    assert "victim@corp.com" in findings[0]["emails"]


def test_multiple_records(storage):
    storage.save(_sample_record("http://site1.onion/"))
    storage.save(_sample_record("http://site2.onion/"))
    assert len(storage.all_findings()) == 2


def test_findings_for_url(storage):
    storage.save(_sample_record("http://target.onion/"))
    storage.save(_sample_record("http://other.onion/"))
    results = storage.findings_for_url("http://target.onion/")
    assert len(results) == 1
