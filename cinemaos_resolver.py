#!/usr/bin/env python3
"""
CinemaOS Resolver - Full Deployable Version for Render.com
Updated: Supports /movie/, /tv/, /player/ URLs
"""

from __future__ import annotations

import argparse
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
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

try:
    import requests
except ImportError as exc:
    raise SystemExit("This script needs requests: python -m pip install requests") from exc

DEFAULT_TEST_URL = "https://cinemaos.tech/player/254"
BASE_ORIGIN = "https://cinemaos.tech"
GT_VALUE = "2549b22d9bf0d91847a2811baac98d0079e02dba592aea94"

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


def browser_headers(referer: str | None = None) -> dict[str, str]:
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": referer or BASE_ORIGIN,
    }


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(browser_headers())
    return session


def generate_content_hash(tmdb_id: str | int | None, imdb_id: str | None = None, season_id: str | int | None = None, episode_id: str | int | None = None) -> str:
    parts = []
    if tmdb_id: parts.append(f"tmdbId:{tmdb_id}")
    if imdb_id: parts.append(f"imdbId:{imdb_id}")
    if season_id not in (None, ""): parts.append(f"seasonId:{season_id}")
    if episode_id not in (None, ""): parts.append(f"episodeId:{episode_id}")
    if not parts:
        raise ValueError("No valid content info")
    content = "|".join(parts).encode()
    first = hmac.new(HASH_PRIMARY.encode(), content, hashlib.sha256).hexdigest()
    return hmac.new(HASH_SECONDARY.encode(), first.encode(), hashlib.sha256).hexdigest()


def decrypt_provider_data(data: dict[str, Any]) -> Any:
    encrypted = data.get("encrypted")
    iv_hex = data.get("cin")
    tag_hex = data.get("mao")
    if not (encrypted and iv_hex and tag_hex):
        raise ValueError("Missing encryption fields")

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
        if {"encrypted", "cin", "mao"}.issubset(payload.keys()):
            return decrypt_provider_data(payload)
        if isinstance(payload.get("data"), dict) and {"encrypted", "cin", "mao"}.issubset(payload["data"].keys()):
            return decrypt_provider_data(payload["data"])
    return payload


def extract_player_id(input_url: str) -> str | None:
    """Improved extractor for both movies and TV shows"""
    if not input_url:
        return None
    
    parsed = urlparse(input_url)
    path = parsed.path.lower()

    # Support multiple URL formats
    patterns = [
        r"/player/([^/?#]+)",
        r"/movie/([^/?#]+)",
        r"/tv/([^/?#]+)",
        r"/series/([^/?#]+)",
    ]
    
    for pattern in patterns:
        match = re.search(pattern, parsed.path)
        if match:
            return unquote(match.group(1))
    
    # Check query params
    qs = parse_qs(parsed.query)
    for key in ("tmdbId", "id", "tmdb_id"):
        if qs.get(key):
            return qs[key][0]
    
    # Pure number
    if input_url.strip().isdigit():
        return input_url.strip()
    
    return None


def normalize_media_type(value: str | None) -> str:
    if value and value.lower() in {"tv", "series", "show"}:
        return "tv"
    return "movie"


# ==================== Core Functions (unchanged from original) ====================

def fetch_json(session: requests.Session, url: str, steps: list, timeout: int = 20):
    started = now_ms()
    response = session.get(url, timeout=timeout, allow_redirects=True)
    steps.append({"method": "GET", "url": url, "status": response.status_code, "final_url": response.url, "elapsed_ms": now_ms() - started})
    response.raise_for_status()
    return response.json()


def fetch_metadata(session: requests.Session, tmdb_id: str, media_type: str, input_url: str, steps: list) -> dict:
    # Simplified version for stability
    try:
        url = f"{BASE_ORIGIN}/api/tmdb?id={tmdb_id}&requestID={'tvData' if media_type == 'tv' else 'movieData'}"
        payload = fetch_json(session, url, steps)
        if isinstance(payload, dict):
            return payload.get("data") or payload.get("result") or payload
    except Exception:
        pass
    return {"title": "Unknown Title"}


def build_provider_params(tmdb_id: str, media_type: str, metadata: dict, season: str | None = None, episode: str | None = None):
    params = {
        "type": media_type,
        "tmdbId": str(tmdb_id),
        "t": metadata.get("title", ""),
        "ry": metadata.get("year", ""),
    }
    if media_type == "tv":
        params["seasonId"] = str(season or 1)
        params["episodeId"] = str(episode or 1)
    params["secret"] = generate_content_hash(tmdb_id, None, params.get("seasonId"), params.get("episodeId"))
    params["_gt"] = GT_VALUE
    return params


def fetch_provider(session: requests.Session, params: dict, steps: list, scraper_id: str | None = None):
    endpoint = "/api/providerv4/scrape" if scraper_id else "/api/providerv4"
    url = f"{BASE_ORIGIN}{endpoint}?{urlencode(params)}"
    session.headers.update(browser_headers(f"{BASE_ORIGIN}/player/{params.get('tmdbId')}"))
    payload = fetch_json(session, url, steps, timeout=30)
    return maybe_decrypt_provider_response(payload)


def classify_urls(urls: list[str]) -> dict:
    groups = {"m3u8": [], "mpd": [], "mp4": [], "iframe_or_embed": [], "decoded_proxy_targets": []}
    for url in urls:
        lower = url.lower()
        if ".m3u8" in lower: groups["m3u8"].append(url)
        elif ".mpd" in lower: groups["mpd"].append(url)
        elif ".mp4" in lower: groups["mp4"].append(url)
        elif any(x in lower for x in ["embed", "iframe", "player"]): groups["iframe_or_embed"].append(url)
    return groups


def extract_urls_from_any(payload: Any) -> list[str]:
    urls = []
    if isinstance(payload, dict):
        for v in payload.values():
            if isinstance(v, str) and v.startswith("http"):
                urls.append(v)
    return urls


def resolve(input_url: str, media_type: str | None = None, season: str | None = None, episode: str | None = None):
    started = now_ms()
    steps = []
    errors = []
    
    tmdb_id = extract_player_id(input_url)
    if not tmdb_id:
        return {"status": "error", "error": "Could not extract TMDB/Player ID", "original_input_url": input_url}

    media_type = normalize_media_type(media_type)
    session = make_session()

    try:
        metadata = fetch_metadata(session, tmdb_id, media_type, input_url, steps)
        params = build_provider_params(tmdb_id, media_type, metadata, season, episode)
        provider_payload = fetch_provider(session, params, steps)
        
        urls = extract_urls_from_any(provider_payload)
        classified = classify_urls(urls)

        return {
            "status": "resolved",
            "original_input_url": input_url,
            "ids": {"tmdb_id": tmdb_id, "type": media_type, "season": season, "episode": episode},
            "metadata": metadata,
            "media_urls": classified,
            "elapsed_ms": now_ms() - started,
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "original_input_url": input_url, "elapsed_ms": now_ms() - started}


# ====================== HTTP Server ======================

class ResolveHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
            return

        if parsed.path in ("/resolve", "/api/resolve"):
            query = parse_qs(parsed.query)
            url = (query.get("url") or [""])[0]
            mtype = (query.get("type") or ["movie"])[0]
            season = (query.get("season") or [None])[0]
            episode = (query.get("episode") or [None])[0]

            result = resolve(url, mtype, season, episode)
            self.send_json(result)
            return

        self.send_json({"error": "Not found"}, 404)

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def serve():
    port = int(os.environ.get("PORT", 8787))
    server = ThreadingHTTPServer(("0.0.0.0", port), ResolveHandler)
    print(f"🚀 Server running on port {port}")
    print(f"🌐 Web UI: http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    if os.environ.get("RENDER") or "--serve" in sys.argv:
        serve()
    else:
        print("Use --serve flag or deploy on Render")