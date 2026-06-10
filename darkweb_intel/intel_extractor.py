"""
Threat-intelligence extractor.

Parses raw HTML from crawled pages and surfaces artefacts relevant to
defensive security:
  - email addresses and credential pairs
  - mentions of target domain / organisation names
  - cryptocurrency wallet addresses (BTC, ETH, Monero)
  - PGP public key blocks
  - threat actor keywords (configurable)

All extraction is purely regex / heuristic — no ML required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

from bs4 import BeautifulSoup

# --------------------------------------------------------------------------- #
# Compiled patterns
# --------------------------------------------------------------------------- #

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

# username:password or email:password pairs (common in leaked credential dumps)
_CREDENTIAL_RE = re.compile(
    r"(?P<user>[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"
    r"[:|](?P<pass>[^\s]{6,})"
)

_BTC_RE = re.compile(r"\b(bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

_PGP_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #

@dataclass
class IntelRecord:
    source_url: str
    emails: list[str] = field(default_factory=list)
    credentials: list[dict[str, str]] = field(default_factory=list)
    btc_wallets: list[str] = field(default_factory=list)
    eth_wallets: list[str] = field(default_factory=list)
    xmr_wallets: list[str] = field(default_factory=list)
    pgp_keys: list[str] = field(default_factory=list)
    keyword_hits: dict[str, list[str]] = field(default_factory=dict)

    @property
    def has_findings(self) -> bool:
        return any([
            self.emails,
            self.credentials,
            self.btc_wallets,
            self.eth_wallets,
            self.xmr_wallets,
            self.pgp_keys,
            any(self.keyword_hits.values()),
        ])


# --------------------------------------------------------------------------- #
# Extractor
# --------------------------------------------------------------------------- #

class IntelExtractor:
    """
    Extract threat-intelligence artefacts from crawled HTML.

    Parameters
    ----------
    target_keywords:
        Organisation names, domain names, or other strings whose presence on
        a dark-web page is itself a signal of interest (e.g. the client's
        company name during a pentesting engagement).
    """

    def __init__(self, target_keywords: Sequence[str] = ()) -> None:
        self._keyword_patterns = {
            kw: re.compile(re.escape(kw), re.IGNORECASE)
            for kw in target_keywords
        }

    def extract(self, url: str, html: str) -> IntelRecord:
        """Parse *html* retrieved from *url* and return an :class:`IntelRecord`."""
        text = self._html_to_text(html)
        record = IntelRecord(source_url=url)

        record.emails = list(dict.fromkeys(_EMAIL_RE.findall(text)))

        record.credentials = [
            {"user": m.group("user"), "pass": m.group("pass")}
            for m in _CREDENTIAL_RE.finditer(text)
        ]

        record.btc_wallets = list(dict.fromkeys(_BTC_RE.findall(text)))
        record.eth_wallets = list(dict.fromkeys(_ETH_RE.findall(text)))
        record.xmr_wallets = list(dict.fromkeys(_XMR_RE.findall(text)))

        record.pgp_keys = _PGP_RE.findall(text)

        for keyword, pattern in self._keyword_patterns.items():
            hits = [m.group(0) for m in pattern.finditer(text)]
            if hits:
                # Return surrounding context (50 chars each side) instead of
                # every raw match to make reports more actionable.
                record.keyword_hits[keyword] = [
                    self._context_snippet(text, m.start(), m.end())
                    for m in pattern.finditer(text)
                ]

        return record

    # ---------------------------------------------------------------------- #
    # Internal helpers
    # ---------------------------------------------------------------------- #

    @staticmethod
    def _html_to_text(html: str) -> str:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style"]):
            tag.decompose()
        return soup.get_text(separator=" ", strip=True)

    @staticmethod
    def _context_snippet(text: str, start: int, end: int, window: int = 50) -> str:
        left = max(0, start - window)
        right = min(len(text), end + window)
        snippet = text[left:right].replace("\n", " ")
        if left > 0:
            snippet = "..." + snippet
        if right < len(text):
            snippet = snippet + "..."
        return snippet
