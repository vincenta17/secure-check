"""
google_index_checker.py - Google Search Index Checker (Rewrite)

Checks whether a URL / domain is indexed by Google using the
Custom Search JSON API. Uses shelve for persistent caching.
"""

import os
import time
import shelve
import logging
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Tuple
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class GoogleIndexChecker:
    """
    Check whether a URL and its domain are indexed by Google.

    Uses the Custom Search JSON API with persistent shelve-based caching
    and in-memory LRU caching for the current session.

    Environment variables required:
        GOOGLE_API_KEY            – API key for Custom Search
        GOOGLE_SEARCH_ENGINE_ID   – Programmable Search Engine ID
    """

    _CACHE_FILE = "google_index_cache"
    _CACHE_TTL_DAYS = 7
    _MAX_RPS = 10  # requests per second

    def __init__(self):
        self._api_key = os.getenv("GOOGLE_API_KEY", "")
        self._cx = os.getenv("GOOGLE_SEARCH_ENGINE_ID", "")
        self._base_url = "https://www.googleapis.com/customsearch/v1"
        self._session = requests.Session()
        self._last_req = 0.0

        if not self._api_key or not self._cx:
            logger.warning("Google API credentials not found – index checks will assume indexed (1, 1).")

    # ──────── Rate limiting ────────

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_req
        interval = 1.0 / self._MAX_RPS
        if elapsed < interval:
            time.sleep(interval - elapsed)
        self._last_req = time.time()

    # ──────── Shelve cache ────────

    def _cache_get(self, key: str):
        try:
            with shelve.open(self._CACHE_FILE) as db:
                if key in db:
                    entry = db[key]
                    if datetime.now() - entry["ts"] <= timedelta(days=self._CACHE_TTL_DAYS):
                        return entry["val"]
        except Exception as exc:
            logger.debug("Cache read error: %s", exc)
        return None

    def _cache_set(self, key: str, value: Tuple[int, int]) -> None:
        try:
            with shelve.open(self._CACHE_FILE) as db:
                db[key] = {"val": value, "ts": datetime.now()}
        except Exception as exc:
            logger.debug("Cache write error: %s", exc)

    # ──────── Single query ────────

    @lru_cache(maxsize=256)
    def _query(self, q: str) -> int:
        """Send a single search query; return 1 if results exist, else 0."""
        try:
            self._rate_limit()
            resp = self._session.get(
                self._base_url,
                params={
                    "key": self._api_key,
                    "cx": self._cx,
                    "q": q,
                    "fields": "searchInformation(totalResults)",
                },
                timeout=5,
            )
            if resp.status_code == 429:
                logger.warning("Rate-limited by Google – retrying in 2 s")
                time.sleep(2)
                return self._query(q)
            if resp.status_code != 200:
                logger.error("Google API %d: %s", resp.status_code, resp.text[:200])
                return 0
            total = int(resp.json().get("searchInformation", {}).get("totalResults", 0))
            return 1 if total > 0 else 0
        except Exception as exc:
            logger.error("Google query error: %s", exc)
            return 0

    # ──────── Public API ────────

    def check_google_index(self, url: str) -> Tuple[int, int]:
        """
        Return (url_indexed, domain_indexed) – each 1 or 0.
        Results are cached for _CACHE_TTL_DAYS.
        """
        if not self._api_key or not self._cx:
            return 1, 1  # Assume indexed when API not configured

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return 0, 0

        domain = parsed.netloc
        cache_key = f"{url}|{domain}"

        cached = self._cache_get(cache_key)
        if cached is not None:
            logger.info("Cache hit for %s", url)
            return cached

        url_indexed = self._query(f'"{url}"')
        domain_indexed = self._query(f"site:{domain}")

        result = (url_indexed, domain_indexed)
        self._cache_set(cache_key, result)
        logger.info("Index check → URL=%d  Domain=%d", url_indexed, domain_indexed)
        return result

    def clear_cache(self) -> None:
        """Delete all cached entries."""
        try:
            with shelve.open(self._CACHE_FILE) as db:
                db.clear()
            logger.info("Cache cleared.")
        except Exception as exc:
            logger.error("Cache clear error: %s", exc)


# Singleton instance for backward compatibility
google_checker = GoogleIndexChecker()
