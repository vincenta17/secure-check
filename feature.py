"""
feature.py - URL Feature Extraction (Class-Based Rewrite)

Extracts 87 features from a given URL for phishing detection.
Uses parallel I/O for DNS, WHOIS, and network lookups.
"""

import re
import socket
import time
import logging
import threading
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from typing import Dict, Any, Tuple

import dns.resolver
import requests
import whois
from ipwhois import IPWhois

from google_index_checker import GoogleIndexChecker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extracts 87 URL-based features for phishing detection."""

    _SHORTENING_SERVICES = frozenset({
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
        "is.gd", "soo.gd", "trib.al", "adf.ly", "bit.do", "cutt.ly",
        "rebrand.ly", "bl.ink", "cli.re", "shorturl.at",
    })

    _CHAR_KEYS = (
        "dots", "hyphens", "underlines", "slashes", "questions",
        "equals", "ats", "ands", "exclamations", "spaces",
        "tildes", "commas", "plus", "asterisks", "hashtags",
        "dollars", "percents",
    )

    _CHAR_SYMBOLS = ".-_/?=@&! ~,+*#$%"

    def __init__(self, max_workers: int = 10):
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._google = GoogleIndexChecker()
        self._domain_cache: Dict[str, Any] = {}
        self._cache_lock = threading.Lock()

    # ──────── Character counting ────────

    @staticmethod
    def _count_chars(text: str) -> Dict[str, int]:
        return {
            "dots": text.count("."),
            "hyphens": text.count("-"),
            "underlines": text.count("_"),
            "slashes": text.count("/"),
            "questions": text.count("?"),
            "equals": text.count("="),
            "ats": text.count("@"),
            "ands": text.count("&"),
            "exclamations": text.count("!"),
            "spaces": text.count(" "),
            "tildes": text.count("~"),
            "commas": text.count(","),
            "plus": text.count("+"),
            "asterisks": text.count("*"),
            "hashtags": text.count("#"),
            "dollars": text.count("$"),
            "percents": text.count("%"),
        }

    # ──────── URL features (20) ────────

    def _url_features(self, url: str, counts: Dict[str, int]) -> Dict[str, Any]:
        return {
            "qty_dot_url": counts["dots"],
            "qty_hyphen_url": counts["hyphens"],
            "qty_underline_url": counts["underlines"],
            "qty_slash_url": counts["slashes"],
            "qty_questionmark_url": counts["questions"],
            "qty_equal_url": counts["equals"],
            "qty_at_url": counts["ats"],
            "qty_and_url": counts["ands"],
            "qty_exclamation_url": counts["exclamations"],
            "qty_space_url": counts["spaces"],
            "qty_tilde_url": counts["tildes"],
            "qty_comma_url": counts["commas"],
            "qty_plus_url": counts["plus"],
            "qty_asterisk_url": counts["asterisks"],
            "qty_hashtag_url": counts["hashtags"],
            "qty_dollar_url": counts["dollars"],
            "qty_percent_url": counts["percents"],
            "qty_tld_url": 1 if re.search(r"\.\w+$", urlparse(url).netloc) else 0,
            "length_url": len(url),
            "email_in_url": 1 if re.search(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", url
            ) else 0,
        }

    # ──────── Domain features (21) ────────

    def _domain_features(self, domain: str, counts: Dict[str, int]) -> Dict[str, Any]:
        return {
            "qty_dot_domain": counts["dots"],
            "qty_hyphen_domain": counts["hyphens"],
            "qty_underline_domain": counts["underlines"],
            "qty_slash_domain": counts["slashes"],
            "qty_questionmark_domain": counts["questions"],
            "qty_equal_domain": counts["equals"],
            "qty_at_domain": counts["ats"],
            "qty_and_domain": counts["ands"],
            "qty_exclamation_domain": counts["exclamations"],
            "qty_space_domain": counts["spaces"],
            "qty_tilde_domain": counts["tildes"],
            "qty_comma_domain": counts["commas"],
            "qty_plus_domain": counts["plus"],
            "qty_asterisk_domain": counts["asterisks"],
            "qty_hashtag_domain": counts["hashtags"],
            "qty_dollar_domain": counts["dollars"],
            "qty_percent_domain": counts["percents"],
            "qty_vowels_domain": sum(1 for c in domain if c in "aeiou"),
            "domain_length": len(domain),
            "domain_in_ip": 1 if re.match(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", domain) else 0,
            "server_client_domain": 1 if ("server" in domain or "client" in domain) else 0,
        }

    # ──────── Directory features (18) ────────

    def _directory_features(self, path: str, counts: Dict[str, int]) -> Dict[str, Any]:
        return {
            "qty_dot_directory": counts["dots"],
            "qty_hyphen_directory": counts["hyphens"],
            "qty_underline_directory": counts["underlines"],
            "qty_slash_directory": counts["slashes"],
            "qty_questionmark_directory": counts["questions"],
            "qty_equal_directory": counts["equals"],
            "qty_at_directory": counts["ats"],
            "qty_and_directory": counts["ands"],
            "qty_exclamation_directory": counts["exclamations"],
            "qty_space_directory": counts["spaces"],
            "qty_tilde_directory": counts["tildes"],
            "qty_comma_directory": counts["commas"],
            "qty_plus_directory": counts["plus"],
            "qty_asterisk_directory": counts["asterisks"],
            "qty_hashtag_directory": counts["hashtags"],
            "qty_dollar_directory": counts["dollars"],
            "qty_percent_directory": counts["percents"],
            "directory_length": len(path),
        }

    # ──────── File features (18) ────────

    def _file_features(self, path: str, counts: Dict[str, int]) -> Dict[str, Any]:
        return {
            "qty_dot_file": counts["dots"],
            "qty_hyphen_file": counts["hyphens"],
            "qty_underline_file": counts["underlines"],
            "qty_slash_file": counts["slashes"],
            "qty_questionmark_file": counts["questions"],
            "qty_equal_file": counts["equals"],
            "qty_at_file": counts["ats"],
            "qty_and_file": counts["ands"],
            "qty_exclamation_file": counts["exclamations"],
            "qty_space_file": counts["spaces"],
            "qty_tilde_file": counts["tildes"],
            "qty_comma_file": counts["commas"],
            "qty_plus_file": counts["plus"],
            "qty_asterisk_file": counts["asterisks"],
            "qty_hashtag_file": counts["hashtags"],
            "qty_dollar_file": counts["dollars"],
            "qty_percent_file": counts["percents"],
            "file_length": len(path),
        }

    # ──────── Parameter features (20) ────────

    def _params_features(self, query: str, counts: Dict[str, int]) -> Dict[str, Any]:
        return {
            "qty_dot_params": counts["dots"],
            "qty_hyphen_params": counts["hyphens"],
            "qty_underline_params": counts["underlines"],
            "qty_slash_params": counts["slashes"],
            "qty_questionmark_params": counts["questions"],
            "qty_equal_params": counts["equals"],
            "qty_at_params": counts["ats"],
            "qty_and_params": counts["ands"],
            "qty_exclamation_params": counts["exclamations"],
            "qty_space_params": counts["spaces"],
            "qty_tilde_params": counts["tildes"],
            "qty_comma_params": counts["commas"],
            "qty_plus_params": counts["plus"],
            "qty_asterisk_params": counts["asterisks"],
            "qty_hashtag_params": counts["hashtags"],
            "qty_dollar_params": counts["dollars"],
            "qty_percent_params": counts["percents"],
            "params_length": len(query),
            "tld_present_params": 1 if re.search(r"\.\w+$", query) else 0,
            "qty_params": query.count("&") + 1 if query else 0,
        }

    # ──────── External / network features ────────

    @staticmethod
    @lru_cache(maxsize=1024)
    def _resolve_response_time(domain: str) -> float:
        try:
            t0 = time.time()
            socket.gethostbyname(domain)
            return time.time() - t0
        except socket.gaierror:
            return 5.0
        except Exception:
            return 0.0

    @staticmethod
    @lru_cache(maxsize=1024)
    def _check_spf(domain: str) -> int:
        try:
            for rdata in dns.resolver.resolve(domain, "TXT"):
                if any(b"v=spf1" in txt for txt in rdata.strings):
                    return 1
            return 0
        except Exception:
            return 0

    @staticmethod
    @lru_cache(maxsize=1024)
    def _lookup_asn(domain: str) -> str:
        try:
            ip = socket.gethostbyname(domain)
            return IPWhois(ip).lookup_rdap().get("asn", "Unknown")
        except Exception:
            return "Unknown"

    @staticmethod
    @lru_cache(maxsize=1024)
    def _dns_records(domain: str) -> Tuple[int, int, int, int]:
        try:
            ips = set(e[4][0] for e in socket.getaddrinfo(domain, None))
            ns = len(dns.resolver.resolve(domain, "NS"))
            mx = len(dns.resolver.resolve(domain, "MX"))
            ttl = dns.resolver.resolve(domain, "A").rrset.ttl
            return len(ips), ns, mx, ttl
        except Exception:
            return 0, 0, 0, -1

    @staticmethod
    @lru_cache(maxsize=1024)
    def _count_redirects(url: str) -> int:
        try:
            resp = requests.get(url, allow_redirects=True, timeout=5)
            return len(resp.history)
        except Exception:
            return -1

    def _whois_info(self, domain: str):
        with self._cache_lock:
            if domain in self._domain_cache:
                return self._domain_cache[domain]
        try:
            socket.gethostbyname(domain)
            info = whois.whois(domain)
            if info and info.domain_name:
                with self._cache_lock:
                    self._domain_cache[domain] = info
                return info
        except Exception as exc:
            logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return None

    def _domain_time(self, domain: str) -> Tuple[int, int]:
        info = self._whois_info(domain)
        if info is None:
            return -1, -1
        try:
            creation = info.creation_date
            expiration = info.expiration_date
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(expiration, list):
                expiration = expiration[0]
            for dt in (creation, expiration):
                if isinstance(dt, str):
                    dt = datetime.strptime(dt.split(".")[0], "%Y-%m-%d %H:%M:%S")
            if not isinstance(creation, datetime) or not isinstance(expiration, datetime):
                return -1, -1
            now = datetime.now()
            return (now - creation).days, (expiration - now).days
        except Exception:
            return -1, -1

    def _external_features(self, url: str, domain: str, scheme: str) -> Dict[str, Any]:
        # Dispatch parallel I/O
        futures = {
            "dns": self._pool.submit(self._dns_records, domain),
            "time": self._pool.submit(self._domain_time, domain),
            "resp": self._pool.submit(self._resolve_response_time, domain),
            "spf": self._pool.submit(self._check_spf, domain),
            "asn": self._pool.submit(self._lookup_asn, domain),
            "redir": self._pool.submit(self._count_redirects, url),
            "gidx": self._pool.submit(self._google.check_google_index, url),
        }

        qty_ip, qty_ns, qty_mx, ttl = futures["dns"].result()
        act_days, exp_days = futures["time"].result()
        url_idx, dom_idx = futures["gidx"].result()

        return {
            "time_response": futures["resp"].result(),
            "domain_spf": futures["spf"].result(),
            "asn_ip": futures["asn"].result(),
            "time_domain_activation": act_days,
            "time_domain_expiration": exp_days,
            "qty_ip_resolved": qty_ip,
            "qty_nameservers": qty_ns,
            "qty_mx_servers": qty_mx,
            "ttl_hostname": ttl,
            "tls_ssl_certificate": 1 if scheme == "https" else 0,
            "qty_redirects": futures["redir"].result(),
            "url_google_index": url_idx,
            "domain_google_index": dom_idx,
            "url_shortened": 1 if urlparse(url).netloc.lower() in self._SHORTENING_SERVICES else 0,
        }

    # ──────── Public API ────────

    def extract(self, url: str) -> Dict[str, Any]:
        """Extract all 87 features from a URL and return as ordered dict."""
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query

        url_counts = self._count_chars(url)
        dom_counts = self._count_chars(domain)
        dir_counts = self._count_chars(path)
        file_counts = self._count_chars(path)
        par_counts = self._count_chars(query)

        features: Dict[str, Any] = {}
        features.update(self._url_features(url, url_counts))
        features.update(self._domain_features(domain, dom_counts))
        features.update(self._directory_features(path, dir_counts))
        features.update(self._file_features(path, file_counts))
        features.update(self._params_features(query, par_counts))
        features.update(self._external_features(url, domain, parsed.scheme))

        return features


# ──────── Module-level convenience (backward-compatible) ────────

_default_extractor = FeatureExtractor()


def extract_features_from_url(url: str) -> Dict[str, Any]:
    """Backward-compatible wrapper around FeatureExtractor.extract()."""
    return _default_extractor.extract(url)