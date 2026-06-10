"""
SQLite-backed persistence for threat-intelligence findings.

Uses SQLAlchemy Core (no ORM) so the schema stays transparent and easy to
query with standard SQL tooling after the fact.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    insert,
    select,
)
from sqlalchemy.engine import Engine

from .intel_extractor import IntelRecord

log = logging.getLogger(__name__)

metadata = MetaData()

findings_table = Table(
    "findings",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("collected_at", DateTime, nullable=False),
    Column("source_url", String(2048), nullable=False),
    Column("emails", Text),           # JSON array
    Column("credentials", Text),      # JSON array of {user, pass}
    Column("btc_wallets", Text),      # JSON array
    Column("eth_wallets", Text),      # JSON array
    Column("xmr_wallets", Text),      # JSON array
    Column("pgp_keys", Text),         # JSON array of key blocks
    Column("keyword_hits", Text),     # JSON object {keyword: [snippets]}
)


class IntelStorage:
    """
    Persist and retrieve :class:`~intel_extractor.IntelRecord` objects.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  Created automatically if absent.
    """

    def __init__(self, db_path: str | Path = "intel.db") -> None:
        self.db_path = Path(db_path)
        self.engine: Engine = create_engine(f"sqlite:///{self.db_path}")
        metadata.create_all(self.engine)
        log.info("Intelligence database at %s", self.db_path.resolve())

    def save(self, record: IntelRecord) -> int:
        """Persist one record and return its row ID."""
        with self.engine.begin() as conn:
            result = conn.execute(
                insert(findings_table).values(
                    collected_at=datetime.now(timezone.utc),
                    source_url=record.source_url,
                    emails=json.dumps(record.emails),
                    credentials=json.dumps(record.credentials),
                    btc_wallets=json.dumps(record.btc_wallets),
                    eth_wallets=json.dumps(record.eth_wallets),
                    xmr_wallets=json.dumps(record.xmr_wallets),
                    pgp_keys=json.dumps(record.pgp_keys),
                    keyword_hits=json.dumps(record.keyword_hits),
                )
            )
        row_id: int = result.inserted_primary_key[0]  # type: ignore[index]
        log.debug("Saved finding id=%d from %s", row_id, record.source_url)
        return row_id

    def all_findings(self) -> list[dict]:
        """Return every stored finding as a plain dict."""
        with self.engine.connect() as conn:
            rows = conn.execute(select(findings_table)).mappings().all()
        return [
            {
                **dict(row),
                "emails": json.loads(row["emails"] or "[]"),
                "credentials": json.loads(row["credentials"] or "[]"),
                "btc_wallets": json.loads(row["btc_wallets"] or "[]"),
                "eth_wallets": json.loads(row["eth_wallets"] or "[]"),
                "xmr_wallets": json.loads(row["xmr_wallets"] or "[]"),
                "pgp_keys": json.loads(row["pgp_keys"] or "[]"),
                "keyword_hits": json.loads(row["keyword_hits"] or "{}"),
            }
            for row in rows
        ]

    def findings_for_url(self, url: str) -> list[dict]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(findings_table).where(findings_table.c.source_url == url)
            ).mappings().all()
        return [
            {
                **dict(row),
                "emails": json.loads(row["emails"] or "[]"),
                "credentials": json.loads(row["credentials"] or "[]"),
            }
            for row in rows
        ]
