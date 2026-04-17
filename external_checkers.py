"""
external_checkers.py - External Security API Integration

Checks URLs against VirusTotal and Google Safe Browsing APIs.
All APIs are optional - gracefully degrades if keys are not configured.
"""

import os
import time
import logging
import hashlib
import base64
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class VirusTotalChecker:
    """Check URLs against VirusTotal's 70+ antivirus engines."""

    def __init__(self):
        self._api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self._base_url = "https://www.virustotal.com/api/v3"
        self._session = requests.Session()
        self._last_request = 0.0
        self._min_interval = 15.0  # 4 requests/minute for free tier

        if not self._api_key:
            logger.warning("VirusTotal API key not configured - checks will be skipped.")

    @property
    def is_available(self) -> bool:
        return bool(self._api_key)

    def _rate_limit(self):
        """Enforce rate limiting for free tier."""
        elapsed = time.time() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.time()

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against VirusTotal.

        Returns:
            {
                "available": bool,
                "verdict": "phishing" | "legitimate" | "unknown",
                "malicious": int,    # number of engines flagging as malicious
                "suspicious": int,   # number of engines flagging as suspicious
                "harmless": int,     # number flagging as harmless
                "undetected": int,   # number with no opinion
                "total_engines": int,
                "score": float,      # 0.0 (safe) to 1.0 (dangerous)
                "details": str,
            }
        """
        if not self._api_key:
            return self._unavailable("API key not configured")

        try:
            self._rate_limit()

            # Submit URL for scanning
            headers = {"x-apikey": self._api_key}

            # Encode URL as VirusTotal URL identifier
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

            resp = self._session.get(
                f"{self._base_url}/urls/{url_id}",
                headers=headers,
                timeout=30,
            )

            if resp.status_code == 404:
                # URL not in VT database - submit for analysis
                submit_resp = self._session.post(
                    f"{self._base_url}/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=30,
                )
                if submit_resp.status_code == 200:
                    # Wait briefly and retry
                    time.sleep(3)
                    resp = self._session.get(
                        f"{self._base_url}/urls/{url_id}",
                        headers=headers,
                        timeout=30,
                    )

            if resp.status_code == 429:
                return self._unavailable("Rate limited - try again later")

            if resp.status_code != 200:
                return self._unavailable(f"API error {resp.status_code}")

            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            # Calculate danger score
            if total > 0:
                score = (malicious + suspicious * 0.5) / total
            else:
                score = 0.0

            if malicious >= 3:
                verdict = "phishing"
            elif malicious >= 1 or suspicious >= 2:
                verdict = "suspicious"
            else:
                verdict = "legitimate"

            details = f"{malicious} malicious, {suspicious} suspicious out of {total} engines"

            return {
                "available": True,
                "verdict": verdict,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total,
                "score": round(score, 4),
                "details": details,
            }

        except requests.Timeout:
            return self._unavailable("Request timed out")
        except Exception as exc:
            logger.error("VirusTotal check error: %s", exc)
            return self._unavailable(str(exc))

    @staticmethod
    def _unavailable(reason: str) -> Dict[str, Any]:
        return {
            "available": False,
            "verdict": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "score": 0.0,
            "details": reason,
        }


class SafeBrowsingChecker:
    """Check URLs against Google Safe Browsing database."""

    def __init__(self):
        self._api_key = os.getenv("SAFE_BROWSING_API_KEY", "")
        self._base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

        if not self._api_key:
            logger.warning("Safe Browsing API key not configured - checks will be skipped.")

    @property
    def is_available(self) -> bool:
        return bool(self._api_key)

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against Google Safe Browsing.

        Returns:
            {
                "available": bool,
                "verdict": "phishing" | "legitimate" | "unknown",
                "threats": list[str],  # e.g. ["SOCIAL_ENGINEERING", "MALWARE"]
                "score": float,        # 0.0 (safe) or 1.0 (flagged)
                "details": str,
            }
        """
        if not self._api_key:
            return self._unavailable("API key not configured")

        try:
            payload = {
                "client": {
                    "clientId": "secure-check",
                    "clientVersion": "2.0.0",
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }

            resp = requests.post(
                f"{self._base_url}?key={self._api_key}",
                json=payload,
                timeout=10,
            )

            if resp.status_code != 200:
                return self._unavailable(f"API error {resp.status_code}")

            data = resp.json()
            matches = data.get("matches", [])

            if matches:
                threats = list(set(m.get("threatType", "UNKNOWN") for m in matches))
                threat_names = [self._threat_label(t) for t in threats]
                return {
                    "available": True,
                    "verdict": "phishing",
                    "threats": threat_names,
                    "score": 1.0,
                    "details": f"Flagged by Google: {', '.join(threat_names)}",
                }
            else:
                return {
                    "available": True,
                    "verdict": "legitimate",
                    "threats": [],
                    "score": 0.0,
                    "details": "Not found in Google's threat database",
                }

        except requests.Timeout:
            return self._unavailable("Request timed out")
        except Exception as exc:
            logger.error("Safe Browsing check error: %s", exc)
            return self._unavailable(str(exc))

    @staticmethod
    def _threat_label(threat_type: str) -> str:
        labels = {
            "MALWARE": "Malware",
            "SOCIAL_ENGINEERING": "Phishing / Social Engineering",
            "UNWANTED_SOFTWARE": "Unwanted Software",
            "POTENTIALLY_HARMFUL_APPLICATION": "Harmful Application",
        }
        return labels.get(threat_type, threat_type)

    @staticmethod
    def _unavailable(reason: str) -> Dict[str, Any]:
        return {
            "available": False,
            "verdict": "unknown",
            "threats": [],
            "score": 0.0,
            "details": reason,
        }


class MultiLayerChecker:
    """
    Orchestrates all security checks and produces a combined verdict.

    Weighted scoring:
      - ML Model:        50% weight (or 100% if no APIs available)
      - VirusTotal:      30% weight
      - Safe Browsing:   20% weight
    """

    def __init__(self):
        self.vt = VirusTotalChecker()
        self.sb = SafeBrowsingChecker()
        self._pool = ThreadPoolExecutor(max_workers=3)

    def check_all(self, url: str) -> Dict[str, Any]:
        """
        Run VirusTotal + Safe Browsing checks in parallel.
        ML prediction is handled separately in app.py.

        Returns dict with vt_result and sb_result.
        """
        futures = {}
        if self.vt.is_available:
            futures["virustotal"] = self._pool.submit(self.vt.check_url, url)
        if self.sb.is_available:
            futures["safe_browsing"] = self._pool.submit(self.sb.check_url, url)

        results = {}
        for name, future in futures.items():
            try:
                results[name] = future.result(timeout=60)
            except Exception as exc:
                logger.error("Check %s failed: %s", name, exc)
                if name == "virustotal":
                    results[name] = self.vt._unavailable(str(exc))
                else:
                    results[name] = self.sb._unavailable(str(exc))

        # Fill in unavailable results
        if "virustotal" not in results:
            results["virustotal"] = self.vt._unavailable("API key not configured")
        if "safe_browsing" not in results:
            results["safe_browsing"] = self.sb._unavailable("API key not configured")

        return results

    @staticmethod
    def combine_scores(
        ml_score: float,
        vt_result: Dict[str, Any],
        sb_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Combine ML prediction with API results using weighted voting.

        Returns combined verdict and confidence.
        """
        # ML Score is the Baseline
        combined_score = ml_score

        # 1. Evaluate VirusTotal
        if vt_result["available"]:
            total_engines = vt_result.get("total_engines", 0)
            malicious = vt_result.get("malicious", 0)
            suspicious = vt_result.get("suspicious", 0)
            
            if total_engines > 0 and (malicious > 0 or suspicious > 0):
                # Boost the score proportionally if there are some hits
                danger_ratio = (malicious + (suspicious * 0.5)) / total_engines
                # If ML says 0.40, and VT danger is 0.10, we boost it.
                # If VT has >= 3 malicious, it's definitely phishing.
                if malicious >= 3:
                    combined_score = max(combined_score, 0.90)
                elif malicious >= 1:
                    combined_score = max(combined_score, 0.70)
                else:
                    combined_score = min(1.0, combined_score + danger_ratio)

        # 2. Evaluate Google Safe Browsing
        if sb_result["available"]:
            if sb_result["verdict"] == "phishing":
                # Safe Browsing is extremely strict. If it flags, it's 100% phishing.
                combined_score = max(combined_score, 0.95)

        combined_score = max(0.0, min(1.0, combined_score))

        # Determine final verdict
        if combined_score >= 0.50:
            verdict = "phishing"
            confidence = round(combined_score, 4)
        else:
            verdict = "legitimate"
            confidence = round(1.0 - combined_score, 4)

        sources_used = 1  # ML always used
        if vt_result["available"]:
            sources_used += 1
        if sb_result["available"]:
            sources_used += 1

        return {
            "classification": verdict,
            "confidence": confidence,
            "combined_score": round(combined_score, 4),
            "sources_used": sources_used,
        }
