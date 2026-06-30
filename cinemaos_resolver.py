#!/usr/bin/env python3
"""
CinemaOS Resolver - Full Deployable Version for Render.com
With built-in simple web UI.
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
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

try:
    import requests
except ImportError as exc:
    raise SystemExit("This script needs requests: python -m pip install requests") from exc

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


def generate_content_hash(
    tmdb_id: str | int | None,
    imdb_id: str | None = None,
    season_id: str | int | None = None,
    episode_id: str | int | None = None,
) -> str:
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
        raise ValueError("Encrypted provider object missing encrypted/cin/mao fields")

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("cryptography is required to decrypt provider responses") from exc

    key_hex = os.environ.get("ENCRYPTION_KEY", DEFAULT_ENCRYPTION_KEY)
    raw_key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    tag = bytes.fromhex(tag_hex)
    ciphertext = bytes.fromhex(encrypted)

    if data.get("salt"):
        salt = bytes.fromhex(str(data["salt"]))
    else:
        salt = hashlib.sha256(iv).digest()[:32]

    use_kdf = not ("version" in data and not (int(data.get("version") or 0) >= 1))
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


def fetch_json(session: requests.Session, url: str, steps: list[dict[str, Any]], timeout: int = 20) -> Any:
    started = now_ms()
    response = session.get(url, timeout=timeout, allow_redirects=True)
    steps.append({
        "method": "GET", "url": url, "status": response.status_code,
        "final_url": response.url, "elapsed_ms": now_ms() - started,
        "content_type": response.headers.get("content-type", ""),
    })
    response.raise_for_status()
    return response.json()


def fetch_text(session: requests.Session, url: str, steps: list[dict[str, Any]], timeout: int = 20) -> str:
    started = now_ms()
    response = session.get(url, timeout=timeout, allow_redirects=True)
    steps.append({
        "method": "GET", "url": url, "status": response.status_code,
        "final_url": response.url, "elapsed_ms": now_ms() - started,
        "content_type": response.headers.get("content-type", ""),
    })
    response.raise_for_status()
    return response.text


def unwrap_tmdb_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        for key in ("data", "result", "movie", "tv", "item"):
            if isinstance(payload.get(key), dict):
                return payload[key]
        return payload
    return {}


def parse_year(metadata: dict[str, Any]) -> str:
    for key in ("release_year", "year"):
        if metadata.get(key):
            return str(metadata[key])
    for key in ("release_date", "first_air_date"):
        value = metadata.get(key)
        if value:
            match = re.match(r"(\d{4})", str(value))
            if match:
                return match.group(1)
    return ""


def find_metadata_in_html(html: str) -> dict[str, Any]:
    candidates = []
    for match in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
        text = match.group(1)
        if "imdb" in text.lower() or "tmdb" in text.lower() or "release_date" in text:
            candidates.append(text)
    joined = "\n".join(candidates)
    metadata: dict[str, Any] = {}
    for key, pattern in {
        "imdb_id": r'"imdb_id"\s*:\s*"([^"]+)"',
        "title": r'"title"\s*:\s*"([^"]+)"',
        "name": r'"name"\s*:\s*"([^"]+)"',
        "release_date": r'"release_date"\s*:\s*"([^"]+)"',
        "first_air_date": r'"first_air_date"\s*:\s*"([^"]+)"',
    }.items():
        found = re.search(pattern, joined)
        if found:
            metadata[key] = found.group(1)
    return metadata


def fetch_metadata(session: requests.Session, tmdb_id: str, media_type: str, input_url: str, steps: list[dict[str, Any]]) -> dict[str, Any]:
    request_id = "tvData" if media_type == "tv" else "movieData"
    candidates = [
        f"{BASE_ORIGIN}/api/tmdb?{urlencode({'id': tmdb_id, 'requestID': request_id, 'language': 'en-US'})}",
        f"{BASE_ORIGIN}/api/tmdb?{urlencode({'requestID': request_id, 'id': tmdb_id, 'language': 'en-US'})}",
    ]
    for url in candidates:
        try:
            payload = fetch_json(session, url, steps)
            metadata = unwrap_tmdb_payload(payload)
            if metadata:
                return metadata
        except Exception:
            continue

    try:
        html = fetch_text(session, input_url, steps)
        metadata = find_metadata_in_html(html)
        if metadata:
            return metadata
    except Exception:
        pass
    raise RuntimeError("Could not fetch metadata")


def build_provider_params(tmdb_id: str, media_type: str, metadata: dict[str, Any], season: str | None = None, episode: str | None = None) -> dict[str, str]:
    imdb_id = metadata.get("imdb_id") or metadata.get("imdbId") or ""
    title = metadata.get("title") or metadata.get("name") or ""
    params = {
        "type": media_type,
        "tmdbId": str(tmdb_id),
        "imdbId": str(imdb_id),
        "t": str(title),
        "ry": parse_year(metadata),
    }
    if media_type == "tv":
        params["seasonId"] = str(season or 1)
        params["episodeId"] = str(episode or 1)
    params = {k: v for k, v in params.items() if v not in ("", "None")}
    params["secret"] = generate_content_hash(params.get("tmdbId"), params.get("imdbId"), params.get("seasonId"), params.get("episodeId"))
    params["_gt"] = GT_VALUE
    return params


def fetch_provider(session: requests.Session, params: dict[str, str], steps: list[dict[str, Any]], scraper_id: str | None = None) -> Any:
    endpoint = "/api/providerv4/scrape" if scraper_id else "/api/providerv4"
    query = dict(params)
    if scraper_id:
        query["scraper"] = scraper_id
    url = f"{BASE_ORIGIN}{endpoint}?{urlencode(query)}"
    session.headers.update(browser_headers(referer=f"{BASE_ORIGIN}/player/{query.get('tmdbId')}"))
    payload = fetch_json(session, url, steps, timeout=30)
    return maybe_decrypt_provider_response(payload)


def walk_values(value: Any) -> list[Any]:
    out: list[Any] = []
    if isinstance(value, dict):
        for item in value.values():
            out.extend(walk_values(item))
    elif isinstance(value, list):
        for item in value:
            out.extend(walk_values(item))
    else:
        out.append(value)
    return out


def decode_base64_url(value: str) -> str | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode()).decode("utf-8", errors="replace")
    except Exception:
        try:
            padded = value + "=" * (-len(value) % 4)
            return base64.b64decode(padded.encode()).decode("utf-8", errors="replace")
        except Exception:
            return None


def decode_proxy_url(url: str) -> dict[str, Any] | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if parsed.netloc.endswith("tcloud.lordflix.club") and qs.get("u"):
        decoded = decode_base64_url(qs["u"][0])
        return {"proxy": "tcloud", "target_url": decoded} if decoded else None
    if "play.cinemaos.workers.dev" in parsed.netloc and qs.get("url"):
        return {"proxy": "cinemaos_worker", "target_url": qs["url"][0]}
    return None


def classify_urls(urls: list[str]) -> dict[str, list[str]]:
    groups = {"m3u8": [], "mpd": [], "mp4": [], "iframe_or_embed": [], "proxy_urls": [], "decoded_proxy_targets": [], "other_resources": []}
    for url in urls:
        lower = url.lower()
        if ".m3u8" in lower:
            add_unique(groups["m3u8"], url)
        elif ".mpd" in lower:
            add_unique(groups["mpd"], url)
        elif ".mp4" in lower:
            add_unique(groups["mp4"], url)
        elif any(marker in lower for marker in ("embed", "iframe", "/player/")):
            add_unique(groups["iframe_or_embed"], url)
        else:
            add_unique(groups["other_resources"], url)
        proxy_info = decode_proxy_url(url)
        if proxy_info and proxy_info.get("target_url"):
            add_unique(groups["decoded_proxy_targets"], proxy_info["target_url"])
    return groups


def extract_urls_from_any(payload: Any) -> list[str]:
    urls: list[str] = []
    for value in walk_values(payload):
        if isinstance(value, str):
            if value.startswith(("http://", "https://")):
                add_unique(urls, value)
            for found in MEDIA_RE.findall(value):
                add_unique(urls, found)
            for found in IFRAME_RE.findall(value):
                add_unique(urls, found)
    return urls


def source_list(provider_payload: Any) -> dict[str, Any]:
    if isinstance(provider_payload, dict):
        sources = provider_payload.get("sources")
        if isinstance(sources, dict):
            return sources
        if isinstance(sources, list):
            return {str(i): item for i, item in enumerate(sources)}
    return {}


def resolve(input_url: str, media_type: str | None = None, season: str | None = None, episode: str | None = None, probe: bool = False) -> dict[str, Any]:
    started = now_ms()
    steps: list[dict[str, Any]] = []
    errors: list[str] = []
    result: dict[str, Any] = {
        "status": "started",
        "original_input_url": input_url,
        "ids": {},
        "metadata": {},
        "media_urls": {"m3u8": [], "mpd": [], "mp4": [], "iframe_or_embed": [], "proxy_urls": [], "decoded_proxy_targets": [], "other_resources": []},
        "errors": errors,
        "request_steps": steps,
    }

    tmdb_id = extract_player_id(input_url)
    if not tmdb_id:
        result["status"] = "error"
        errors.append("Could not extract TMDB/Player ID")
        return result

    media_type = normalize_media_type(media_type)
    result["ids"] = {"tmdb_id": tmdb_id, "type": media_type, "season": season, "episode": episode}

    session = make_session()
    try:
        metadata = fetch_metadata(session, tmdb_id, media_type, input_url, steps)
        result["metadata"] = {"title": metadata.get("title") or metadata.get("name"), "year": parse_year(metadata)}

        provider_params = build_provider_params(tmdb_id, media_type, metadata, season, episode)
        provider_payload = fetch_provider(session, provider_params, steps)

        sources = source_list(provider_payload)
        urls = extract_urls_from_any(provider_payload)
        classified = classify_urls(urls)

        result["sources"] = sources
        result["media_urls"] = classified
        result["status"] = "resolved" if sources or any(classified.values()) else "no_sources_found"
    except Exception as exc:
        result["status"] = "failed"
        errors.append(str(exc))

    result["elapsed_ms"] = now_ms() - started
    return result


class ResolveHandler(BaseHTTPRequestHandler):
    server_version = "CinemaOSResolver/1.0"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            try:
                with open("index.html", "rb") as f:
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.wfile.write(b"<h1>index.html not found</h1>")
            return

        if parsed.path in ("/resolve", "/api/resolve"):
            query = parse_qs(parsed.query)
            input_url = (query.get("url") or [DEFAULT_TEST_URL])[0]
            try:
                payload = resolve(
                    input_url,
                    media_type=(query.get("type") or [None])[0],
                    season=(query.get("season") or [None])[0],
                    episode=(query.get("episode") or [None])[0],
                    probe=(query.get("probe") or ["0"])[0] in {"1", "true"}
                )
                self.send_json(payload)
            except Exception as exc:
                self.send_json({"status": "error", "error": str(exc)}, 500)
            return

        if parsed.path == "/health":
            self.send_json({"ok": True})
            return

        self.send_json({"error": "Not found"}, 404)

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass


def serve(host: str = "0.0.0.0", port: int | None = None) -> None:
    if port is None:
        port = int(os.environ.get("PORT", 8787))
    httpd = ThreadingHTTPServer((host, port), ResolveHandler)
    print(f"🚀 CinemaOS Resolver running on http://{host}:{port}")
    print(f"🌐 Web UI → http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    if os.environ.get("RENDER") or "--serve" in sys.argv:
        serve()
    else:
        # CLI fallback
        parser = argparse.ArgumentParser()
        parser.add_argument("--url", default=DEFAULT_TEST_URL)
        parser.add_argument("--type", default="movie")
        parser.add_argument("--season")
        parser.add_argument("--episode")
        args = parser.parse_args()
        output = resolve(args.url, args.type, args.season, args.episode)
        print(json.dumps(output, indent=2))