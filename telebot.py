"""
telebot.py - Phishing Detection Telegram Bot

Pure ML version emphasizing Stacking Ensemble / AI prediction.
"""

import logging
import os
import re
from urllib.parse import urlparse

import requests as http_requests
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackContext,
    filters,
)

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
API_BASE = os.getenv("API_ENDPOINT", "http://127.0.0.1:8080")

_URL_RE = re.compile(
    r"(https?://[^\s]+)|"
    r"((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?)",
    re.IGNORECASE,
)

class PhishingBot:
    def __init__(self):
        self._app = Application.builder().token(TOKEN).build()
        self._register_handlers()

    def _register_handlers(self):
        self._app.add_handler(CommandHandler("start", self._cmd_start))
        self._app.add_handler(CommandHandler("help", self._cmd_help))
        self._app.add_handler(CommandHandler("check", self._cmd_check))
        self._app.add_handler(CommandHandler("report", self._cmd_report))
        self._app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self._auto_check)
        )
        self._app.add_error_handler(self._on_error)

    @staticmethod
    def _ensure_scheme(url: str) -> str:
        url = url.strip()
        if url.startswith(("http://", "https://")):
            return url
        return f"https://{url}"

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        try:
            p = urlparse(url)
            return bool(p.scheme in ("http", "https") and p.netloc and "." in p.netloc)
        except Exception:
            return False

    def _api_predict(self, url: str) -> dict:
        resp = http_requests.post(
            f"{API_BASE}/api/predict",
            json={"url": url},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()

    def _api_report(self, url: str, label: str) -> dict:
        resp = http_requests.post(
            f"{API_BASE}/api/dataset/add",
            json={"url": url, "label": label},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()

    async def _cmd_start(self, update: Update, ctx: CallbackContext):
        await update.message.reply_text(
            "👋 <b>Welcome to Secure Check Bot!</b>\n\n"
            "I use a highly accurate <b>Stacking Ensemble AI Model</b> (combining RandomForest, XGBoost, and Neural Networks) to detect phishing URLs.\n\n"
            "📌 <b>Commands:</b>\n"
            "/check &lt;url&gt; — Check a URL\n"
            "/report &lt;url&gt; phishing|legitimate — Report a URL\n"
            "/help — Show help\n\n"
            "Or simply send me any URL and I'll analyze it!",
            parse_mode="HTML",
        )

    async def _cmd_help(self, update: Update, ctx: CallbackContext):
        await update.message.reply_text(
            "🔍 <b>Available Commands</b>\n\n"
            "/start — Welcome message\n"
            "/help — This help message\n"
            "/check &lt;url&gt; — Analyze a URL with AI\n"
            "/report &lt;url&gt; phishing — Report as phishing\n"
            "/report &lt;url&gt; legitimate — Report as safe\n\n"
            "💡 You can also just send a URL directly!",
            parse_mode="HTML",
        )

    async def _cmd_check(self, update: Update, ctx: CallbackContext):
        if not ctx.args:
            await update.message.reply_text("⚠️ Usage: /check <url>\nExample: /check https://google.com")
            return
        url = self._ensure_scheme(ctx.args[0])
        if not self._is_valid_url(url):
            await update.message.reply_text("⚠️ Invalid URL format.")
            return
        await self._do_check(update, url)

    async def _cmd_report(self, update: Update, ctx: CallbackContext):
        if len(ctx.args) < 2:
            await update.message.reply_text(
                "⚠️ Usage: /report <url> <label>\n"
                "Labels: phishing, legitimate\n"
            )
            return

        url = self._ensure_scheme(ctx.args[0])
        label = ctx.args[1].lower()

        if not self._is_valid_url(url):
            await update.message.reply_text("⚠️ Invalid URL format.")
            return
        if label not in ("phishing", "legitimate"):
            await update.message.reply_text("⚠️ Label must be 'phishing' or 'legitimate'.")
            return

        try:
            self._api_report(url, label)
            emoji = "🔴" if label == "phishing" else "🟢"
            await update.message.reply_text(
                f"✅ <b>URL Reported Successfully</b>\n\n"
                f"URL: {url}\n"
                f"Label: {emoji} {label.upper()}\n\n"
                f"Thank you! 🙏",
                parse_mode="HTML",
            )
        except Exception:
            await update.message.reply_text("❌ Could not connect to the service.")

    async def _auto_check(self, update: Update, ctx: CallbackContext):
        text = update.message.text.strip()
        match = _URL_RE.search(text)
        if not match:
            await update.message.reply_text("⚠️ I didn't detect a valid URL.")
            return

        url = self._ensure_scheme(match.group(0))
        if not self._is_valid_url(url):
            await update.message.reply_text("⚠️ Invalid URL format.")
            return

        await self._do_check(update, url)

    async def _do_check(self, update: Update, url: str):
        await update.message.reply_text(
            f"🔍 <b>Analyzing URL using Ensemble AI Model...</b>\n\n"
            f"URL: {url}\n\n"
            f"Please wait...",
            parse_mode="HTML",
        )

        try:
            result = self._api_predict(url)

            if "classification" in result:
                cls = result["classification"]
                conf = result.get("confidence")
                sources = result.get("sources", {})

                main_emoji = "🟢" if cls == "legitimate" else "🔴"
                tip = "This URL appears legitimate." if cls == "legitimate" else "⚠️ Phishing detected!"

                msg = (
                    f"{main_emoji} <b>AI Result</b>\n\n"
                    f"URL: {url}\n"
                    f"Verdict: <b>{cls.upper()}</b>\n"
                )
                if conf is not None:
                    msg += f"Confidence: {conf:.1%}\n"

                ml = sources.get("ml_model", {})
                vt = sources.get("virustotal", {})
                sb = sources.get("safe_browsing", {})
                
                msg += f"\n📊 <b>Global Validation Breakdown:</b>\n"
                
                if ml:
                    model_name = ml.get("model", "Machine Learning")
                    msg += f"🧠 <b>{model_name}:</b> {ml.get('verdict', '').upper()}\n"
                    
                if vt:
                    if vt.get("available"):
                        vt_verdict = vt.get("verdict", "unknown").upper()
                        msg += f"🐛 <b>VirusTotal:</b> {vt_verdict} ({vt.get('malicious', 0)}/{vt.get('total_engines', 0)} engines)\n"
                    else:
                        msg += f"🐛 <b>VirusTotal:</b> {vt.get('details', 'Not configured or timeout')}\n"
                        
                if sb:
                    if sb.get("available"):
                        sb_verdict = sb.get("verdict", "unknown").upper()
                        threats = ", ".join(sb.get("threats", [])) if sb.get("threats") else "No threats"
                        msg += f"🛡 <b>Safe Browsing:</b> {sb_verdict} ({threats})\n"
                    else:
                        msg += f"🛡 <b>Safe Browsing:</b> {sb.get('details', 'Not configured')}\n"
                
                anomalies = result.get("anomalies", [])
                if anomalies:
                    msg += f"\n💡 <b>AI Explanation:</b>\n"
                    for a in anomalies:
                        msg += f"• {a}\n"
                
                msg += f"\n{tip}"

                await update.message.reply_text(msg, parse_mode="HTML")
            else:
                await update.message.reply_text("⚠️ Analysis failed.")
        except Exception as exc:
            logger.error("Check error: %s", exc)
            await update.message.reply_text("❌ Service unavailable.")

    async def _on_error(self, update: Update, ctx: CallbackContext):
        logger.error("Bot error: %s", ctx.error)

    def run(self):
        logger.info("Starting Phishing Bot (Pure ML)...")
        self._app.run_polling()

def main():
    if not TOKEN:
        logger.error("Set TELEGRAM_BOT_TOKEN")
        return
    PhishingBot().run()

if __name__ == "__main__":
    main()