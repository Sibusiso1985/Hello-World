"""
CLI entry point.

Usage examples
--------------
# Crawl two seeds, flag any mention of "acmecorp.com", store results
python -m darkweb_intel crawl \
    http://example3g2uux453.onion \
    http://anotherxyz123.onion \
    --keyword acmecorp.com \
    --keyword "Acme Corp" \
    --depth 2 \
    --db intel.db

# Print a summary report of everything collected so far
python -m darkweb_intel report --db intel.db
"""

from __future__ import annotations

import logging
import sys

import click
from rich.console import Console
from rich.table import Table

from .crawler import CrawlerConfig, DarkWebCrawler
from .intel_extractor import IntelExtractor
from .storage import IntelStorage
from .tor_connector import TorConnectionError, TorSession

console = Console()
log = logging.getLogger(__name__)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=level,
        stream=sys.stderr,
    )


@click.group()
def cli() -> None:
    """Dark-web threat-intelligence toolkit (authorised use only)."""


@cli.command()
@click.argument("seeds", nargs=-1, required=True)
@click.option("--keyword", "-k", multiple=True, help="Target keyword/domain to watch for.")
@click.option("--depth", "-d", default=2, show_default=True, help="Max link depth.")
@click.option("--max-pages", default=100, show_default=True, help="Page cap per run.")
@click.option("--rate", default=3.0, show_default=True, help="Seconds between requests.")
@click.option("--db", default="intel.db", show_default=True, help="SQLite output path.")
@click.option("--rotate-every", default=0, help="Rotate Tor circuit every N pages (0=never).")
@click.option("--verbose", "-v", is_flag=True)
def crawl(
    seeds: tuple[str, ...],
    keyword: tuple[str, ...],
    depth: int,
    max_pages: int,
    rate: float,
    db: str,
    rotate_every: int,
    verbose: bool,
) -> None:
    """Crawl one or more .onion seed URLs and extract threat intelligence."""
    _setup_logging(verbose)

    storage = IntelStorage(db)
    extractor = IntelExtractor(target_keywords=list(keyword))
    config = CrawlerConfig(rate_limit_secs=rate, max_depth=depth, max_pages=max_pages)

    console.rule("[bold red]Dark Web Intel Crawler[/bold red]")
    console.print(f"Seeds      : {', '.join(seeds)}")
    console.print(f"Keywords   : {', '.join(keyword) or '(none)'}")
    console.print(f"Max depth  : {depth}   Max pages: {max_pages}   Rate: {rate}s")
    console.print(f"Database   : {db}")
    console.rule()

    try:
        session = TorSession()
        session.open()
    except TorConnectionError as exc:
        console.print(f"[bold red]Tor connection failed:[/bold red] {exc}")
        sys.exit(1)

    crawler = DarkWebCrawler(session, config)
    pages_fetched = 0

    try:
        results = crawler.crawl(seeds)
        for result in results:
            pages_fetched += 1

            if rotate_every and pages_fetched % rotate_every == 0:
                console.print(f"[yellow]Rotating Tor circuit after {pages_fetched} pages...[/yellow]")
                try:
                    session.rotate_circuit()
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[yellow]Circuit rotation failed (continuing): {exc}[/yellow]")

            if not result.ok:
                console.print(f"[dim]SKIP {result.url}  ({result.error or result.status_code})[/dim]")
                continue

            record = extractor.extract(result.url, result.html)
            if record.has_findings:
                storage.save(record)
                console.print(f"[green]FOUND[/green] {result.url}  "
                               f"(emails={len(record.emails)} creds={len(record.credentials)} "
                               f"keywords={sum(len(v) for v in record.keyword_hits.values())})")
            else:
                console.print(f"[dim]CLEAN {result.url}[/dim]")
    finally:
        session.close()

    console.rule()
    console.print(f"[bold]Done.[/bold] {pages_fetched} pages crawled. "
                   f"Results stored in [cyan]{db}[/cyan].")


@cli.command()
@click.option("--db", default="intel.db", show_default=True)
@click.option("--verbose", "-v", is_flag=True)
def report(db: str, verbose: bool) -> None:
    """Print a summary of all collected intelligence."""
    _setup_logging(verbose)
    storage = IntelStorage(db)
    findings = storage.all_findings()

    if not findings:
        console.print("No findings stored yet.")
        return

    table = Table(title=f"Threat Intelligence Report — {db}", show_lines=True)
    table.add_column("ID", style="dim", width=5)
    table.add_column("Collected At", width=20)
    table.add_column("Source URL", style="cyan", overflow="fold")
    table.add_column("Emails", justify="right")
    table.add_column("Creds", justify="right")
    table.add_column("Wallets (BTC/ETH/XMR)", justify="right")
    table.add_column("Keywords hit", justify="right")

    for f in findings:
        wallets = f"{len(f['btc_wallets'])}/{len(f['eth_wallets'])}/{len(f['xmr_wallets'])}"
        kw_hits = sum(len(v) for v in f["keyword_hits"].values())
        table.add_row(
            str(f["id"]),
            str(f["collected_at"])[:19],
            f["source_url"],
            str(len(f["emails"])),
            str(len(f["credentials"])),
            wallets,
            str(kw_hits),
        )

    console.print(table)
