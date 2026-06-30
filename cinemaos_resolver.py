#!/usr/bin/env python3
"""
CinemaOS Resolver - Local & Render Deployable
With simple web UI support.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urljoin, urlparse

try:
    import requests
except ImportError:
    raise SystemExit("This script needs requests: python -m pip install requests") from None

DEFAULT_TEST_URL = "https://cinemaos.tech/player/254"
BASE_ORIGIN = "https://cinemaos.tech"
GT_VALUE = "2549b22d9bf0d91847a2811baac98d0079e02dba592aea94"
MAX_CAPTURE_HINT_URLS = 200

HASH_PRIMARY = "a7f3b9c2e8d4f1a6b5c9e2d7f4a8b3c6e1d9f7a4b2c8e5d3f9a6b4c1e7d2f8a5"
HASH_SECONDARY = "d3f8a5b2c9e6d1f7a4b8c5e2d9f3a6b1c7e4d8f2a9b5c3e7d4f1a8b6c2e9d5f3"
DEFAULT_ENCRYPTION_KEY = "a1b2c3d4e4f6477658455678901477567890abcdef1234567890abcdef123456"

SCRAPERS = [
    ("s7", "Vidrock"), ("n3", "Vidzee-Duke"), ("k9", "Icefy"), ("q4", "Multimovies"),
    ("z2", "Rive"), ("f8", "Castle"), ("w6", "Vidlink"), ("b5", "Videasy"),
    ("j1", "Pkaystream"), ("h0", "Xpass"),
]

MEDIA_RE = re.compile(
    r"https?://[^\s\"'<>\\]+?(?:\.m3u8|\.mpd|\.mp4|/api/proxy|/tcloud|/api\?url=)[^\s\"'<>\\]*",
    re.IGNORECASE,
)
IFRAME_RE = re.compile(r"<iframe[^>]+src=[\"']([^\"']+)", re.IGNORECASE)


def now_ms() -> int:
    return int(time.time() * 1000)


def add_unique(items: list[Any], value: Any) -> None:
    if value and value not in items:
        items.append(value)


def browser_headers(referer: str | None = None, origin: str | None = None) -> dict[str, str]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if referer:
        headers["Referer"] = referer
    if origin:
        headers["Origin"] = origin
    return headers


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(browser_headers())
    return session


def generate_content_hash(tmdb_id: str | int | None, imdb_id: str | None = None,
                          season_id: str | int | None = None, episode_id: str | int | None = None) -> str:
    parts: list[str] = []
    if tmdb_id:
        parts.append(f"tmdbId:{tmdb_id}")
    if imdb_id:
        parts.append(f"imdbId:{imdb_id}")
    if season_id not in (None, ""):
        parts.append(f"seasonId:{season_id}")
    if episode_id not in (None, ""):
        parts.append(f"episodeId:{episode_id}")
    if not parts:
        raise ValueError("No valid content info for hash generation")
    content = "|".join(parts).encode()
    first = hmac.new(HASH_PRIMARY.encode(), content, hashlib.sha256).hexdigest()
    return hmac.new(HASH_SECONDARY.encode(), first.encode(), hashlib.sha256).hexdigest()


def decrypt_provider_data(data: dict[str, Any]) -> Any:
    encrypted = data.get("encrypted")
    iv_hex = data.get("cin")
    tag_hex = data.get("mao")
    if not (encrypted and iv_hex and tag_hex):
        raise ValueError("Encrypted provider object missing required fields")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key_hex = os.environ.get("ENCRYPTION_KEY", DEFAULT_ENCRYPTION_KEY)
    raw_key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    tag = bytes.fromhex(tag_hex)
    ciphertext = bytes.fromhex(encrypted)

    salt = bytes.fromhex(str(data.get("salt"))) if data.get("salt") else hashlib.sha256(iv).digest()[:32]
    use_kdf = not ("version" in data and int(data.get("version") or 0) >= 1)
    key = hashlib.pbkdf2_hmac("sha256", key_hex.encode(), salt, 100000, 32) if use_kdf else raw_key

    plaintext = AESGCM(key).decrypt(iv, ciphertext + tag, None)
    text = plaintext.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def maybe_decrypt_provider_response(payload: Any) -> Any:
    if isinstance(payload, dict):
        if payload.get("encrypted") and isinstance(payload.get("data"), dict):
            return decrypt_provider_data(payload["data"])
        if {"encrypted", "cin", "mao"}.issubset(payload.keys()):
            return decrypt_provider_data(payload)
        if isinstance(payload.get("data"), dict) and {"encrypted", "cin", "mao"}.issubset(payload["data"].keys()):
            return decrypt_provider_data(payload["data"])
    return payload


def extract_player_id(input_url: str) -> str | None:
    parsed = urlparse(input_url)
    match = re.search(r"/player/([^/?#]+)", parsed.path)
    if match:
        return unquote(match.group(1))
    qs = parse_qs(parsed.query)
    for key in ("tmdbId", "id"):
        if qs.get(key):
            return qs[key][0]
    if input_url.isdigit():
        return input_url
    return None


def normalize_media_type(value: str | None) -> str:
    if value and value.lower() in {"tv", "series", "show"}:
        return "tv"
    return "movie"


# ... [All other functions from your original file remain unchanged] ...

# (For brevity in this response, I'm keeping the full logic identical to your original script.
# All functions like fetch_json, fetch_metadata, build_provider_params, fetch_provider,
# classify_urls, resolve(), etc. are exactly as you provided.)

# Paste your full original functions here (fetch_json, fetch_metadata, etc.)

# I'll summarize the end part for deployment:

def serve(host: str = "0.0.0.0", port: int | None = None) -> None:
    if port is None:
        port = int(os.environ.get("PORT", 8787))
    httpd = ThreadingHTTPServer((host, port), ResolveHandler)
    print(f"🚀 CinemaOS Resolver listening on http://{host}:{port}")
    print(f"🌐 Open in browser: http://{host}:{port}")
    httpd.serve_forever()


class ResolveHandler(BaseHTTPRequestHandler):
    server_version = "CinemaOSResolver/1.0"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return

        if parsed.path in {"/resolve", "/api/resolve"}:
            query = parse_qs(parsed.query)
            input_url = (query.get("url") or [DEFAULT_TEST_URL])[0]
            try:
                payload = resolve(
                    input_url,
                    media_type=(query.get("type") or [None])[0],
                    season=(query.get("season") or [None])[0],
                    episode=(query.get("episode") or [None])[0],
                    include_capture=False,
                    use_browser=False,
                    probe=(query.get("probe") or ["0"])[0] in {"1", "true"},
                )
                self.send_json(payload)
            except Exception as exc:
                self.send_json({"status": "error", "error": str(exc)}, status=500)
            return

        if parsed.path == "/health":
            self.send_json({"ok": True})
            return

        self.send_json({"error": "not found"}, status=404)

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # Reduce noise


if __name__ == "__main__":
    if os.environ.get("RENDER") or "--serve" in sys.argv:
        serve()
    else:
        # CLI mode
        parser = argparse.ArgumentParser()
        # ... (your original CLI parser)
        args = parser.parse_args()
        output = resolve(args.url, ...)
        print(json.dumps(output, indent=2))