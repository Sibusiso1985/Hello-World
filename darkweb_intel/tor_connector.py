"""
Tor connection manager.

Manages a SOCKS5 session through a locally running Tor daemon and supports
circuit rotation via the Tor control port so successive requests appear to
originate from different exit nodes.

Prerequisites
-------------
* Tor must be installed and running:  sudo apt install tor && tor
* (Optional) Set ControlPort 9051 + HashedControlPassword in /etc/tor/torrc
  to enable circuit rotation.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from typing import Generator

import requests
from dotenv import load_dotenv

try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:  # stem is optional for read-only sessions
    STEM_AVAILABLE = False

load_dotenv()

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Defaults (override via environment variables or .env)
# --------------------------------------------------------------------------- #
TOR_SOCKS_HOST = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))
TOR_CONTROL_HOST = os.getenv("TOR_CONTROL_HOST", "127.0.0.1")
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", "9051"))
TOR_CONTROL_PASSWORD = os.getenv("TOR_CONTROL_PASSWORD", "")

DEFAULT_TIMEOUT = int(os.getenv("TOR_REQUEST_TIMEOUT", "30"))
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Accept-Language": "en-US,en;q=0.5",
}


class TorConnectionError(RuntimeError):
    """Raised when Tor connectivity cannot be established."""


class TorSession:
    """
    Thin wrapper around a :class:`requests.Session` pre-configured to route
    all traffic through the local Tor SOCKS5 proxy.
    """

    def __init__(
        self,
        socks_host: str = TOR_SOCKS_HOST,
        socks_port: int = TOR_SOCKS_PORT,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.timeout = timeout
        self._session: requests.Session | None = None

    # ---------------------------------------------------------------------- #
    # Session lifecycle
    # ---------------------------------------------------------------------- #

    def open(self) -> None:
        """Create and verify the Tor-backed requests session."""
        session = requests.Session()
        proxy_url = f"socks5h://{self.socks_host}:{self.socks_port}"
        session.proxies = {"http": proxy_url, "https": proxy_url}
        session.headers.update(DEFAULT_HEADERS)
        self._session = session
        self._verify_connectivity()

    def close(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self) -> "TorSession":
        self.open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ---------------------------------------------------------------------- #
    # Request helpers
    # ---------------------------------------------------------------------- #

    def get(self, url: str, **kwargs: object) -> requests.Response:
        self._require_open()
        kwargs.setdefault("timeout", self.timeout)
        return self._session.get(url, **kwargs)  # type: ignore[union-attr]

    def post(self, url: str, **kwargs: object) -> requests.Response:
        self._require_open()
        kwargs.setdefault("timeout", self.timeout)
        return self._session.post(url, **kwargs)  # type: ignore[union-attr]

    # ---------------------------------------------------------------------- #
    # Circuit management
    # ---------------------------------------------------------------------- #

    def rotate_circuit(
        self,
        control_host: str = TOR_CONTROL_HOST,
        control_port: int = TOR_CONTROL_PORT,
        password: str = TOR_CONTROL_PASSWORD,
        wait: float = 5.0,
    ) -> None:
        """
        Signal the Tor daemon to build a new circuit (new exit node).

        Requires stem and a reachable control port with authentication.
        """
        if not STEM_AVAILABLE:
            raise TorConnectionError(
                "stem is not installed — run: pip install stem"
            )
        with Controller.from_port(address=control_host, port=control_port) as ctrl:
            ctrl.authenticate(password=password)
            ctrl.signal(Signal.NEWNYM)  # type: ignore[attr-defined]
        log.info("Circuit rotation requested; waiting %.1fs for new circuit.", wait)
        time.sleep(wait)  # Tor needs a moment to establish the new circuit

    # ---------------------------------------------------------------------- #
    # Internal helpers
    # ---------------------------------------------------------------------- #

    def _require_open(self) -> None:
        if self._session is None:
            raise TorConnectionError("Session is not open. Call open() first.")

    def _verify_connectivity(self) -> None:
        """Confirm traffic is routed through Tor by checking the exit IP."""
        try:
            resp = self._session.get(  # type: ignore[union-attr]
                "https://check.torproject.org/api/ip",
                timeout=self.timeout,
            )
            data = resp.json()
            if not data.get("IsTor", False):
                raise TorConnectionError(
                    "check.torproject.org reports this is NOT a Tor exit node. "
                    "Verify Tor is running and the SOCKS port is correct."
                )
            log.info("Tor connectivity confirmed. Exit IP: %s", data.get("IP"))
        except requests.RequestException as exc:
            raise TorConnectionError(
                f"Could not verify Tor connectivity: {exc}"
            ) from exc


@contextmanager
def tor_session(**kwargs: object) -> Generator[TorSession, None, None]:
    """Context-manager shorthand for :class:`TorSession`."""
    session = TorSession(**kwargs)  # type: ignore[arg-type]
    session.open()
    try:
        yield session
    finally:
        session.close()
