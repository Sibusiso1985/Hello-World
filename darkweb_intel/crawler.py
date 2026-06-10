"""
Responsible dark-web crawler.

Designed for *targeted* threat-intelligence collection against a pre-approved
list of .onion URLs.  It enforces rate limiting, maximum page depth, and
domain allowlisting so the tool cannot be trivially repurposed for mass
crawling.

Only use this against services you are authorised to access.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .tor_connector import TorSession

log = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    url: str
    status_code: int
    html: str = ""
    error: str = ""
    depth: int = 0
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status_code == 200 and not self.error


@dataclass
class CrawlerConfig:
    """Tuneable parameters for :class:`DarkWebCrawler`."""

    # Seconds to wait between requests (be a polite guest)
    rate_limit_secs: float = 3.0

    # How many links deep to follow from a seed URL (0 = seed only)
    max_depth: int = 2

    # Hard cap on total pages fetched per run
    max_pages: int = 100

    # Only follow links whose netloc ends with one of these strings.
    # Populated automatically from the seed URLs unless overridden.
    allowed_domains: list[str] = field(default_factory=list)

    # HTTP response codes to treat as fetchable
    ok_status_codes: tuple[int, ...] = (200,)


class DarkWebCrawler:
    """
    Targeted crawler that routes all traffic through a :class:`TorSession`.

    Parameters
    ----------
    session:
        An open :class:`TorSession`.
    config:
        Crawl behaviour settings.
    """

    def __init__(self, session: TorSession, config: CrawlerConfig | None = None) -> None:
        self.session = session
        self.config = config or CrawlerConfig()
        self._visited: set[str] = set()

    # ---------------------------------------------------------------------- #
    # Public API
    # ---------------------------------------------------------------------- #

    def crawl(self, seeds: Iterable[str]) -> list[CrawlResult]:
        """
        Crawl a list of seed URLs and follow links up to *max_depth*.

        Returns a flat list of :class:`CrawlResult` objects.
        """
        seeds = list(seeds)
        if not self.config.allowed_domains:
            self.config.allowed_domains = [
                urlparse(u).netloc for u in seeds if urlparse(u).netloc
            ]
            log.info(
                "Allowlisted domains derived from seeds: %s",
                self.config.allowed_domains,
            )

        results: list[CrawlResult] = []
        queue: list[tuple[str, int]] = [(u, 0) for u in seeds]

        while queue and len(results) < self.config.max_pages:
            url, depth = queue.pop(0)
            if url in self._visited:
                continue
            self._visited.add(url)

            result = self._fetch(url, depth)
            results.append(result)
            log.info(
                "[depth=%d] %s  →  %d (%.0f ms)",
                depth,
                url,
                result.status_code,
                result.elapsed_ms,
            )

            if result.ok and depth < self.config.max_depth:
                for link in self._extract_links(result.html, url):
                    if link not in self._visited and self._is_allowed(link):
                        queue.append((link, depth + 1))

            time.sleep(self.config.rate_limit_secs)

        return results

    # ---------------------------------------------------------------------- #
    # Internal helpers
    # ---------------------------------------------------------------------- #

    def _fetch(self, url: str, depth: int) -> CrawlResult:
        start = time.monotonic()
        try:
            resp = self.session.get(url)
            elapsed = (time.monotonic() - start) * 1000
            html = resp.text if resp.status_code in self.config.ok_status_codes else ""
            return CrawlResult(
                url=url,
                status_code=resp.status_code,
                html=html,
                depth=depth,
                elapsed_ms=elapsed,
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.monotonic() - start) * 1000
            log.warning("Failed to fetch %s: %s", url, exc)
            return CrawlResult(
                url=url,
                status_code=0,
                error=str(exc),
                depth=depth,
                elapsed_ms=elapsed,
            )

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        links: list[str] = []
        for tag in soup.find_all("a", href=True):
            href: str = tag["href"].strip()
            if href.startswith(("#", "javascript:", "mailto:")):
                continue
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme in ("http", "https"):
                links.append(absolute)
        return links

    def _is_allowed(self, url: str) -> bool:
        netloc = urlparse(url).netloc
        return any(netloc.endswith(d) for d in self.config.allowed_domains)
