"""Favicon/logo visual brand comparison using a DCT perceptual hash.

Extracts the page favicon (``link[rel~=icon]`` or ``/favicon.ico``),
computes a 64-bit pHash, and compares it with the official favicon of a
matched brand (fetched from its official domain and cached).  When the
visual hashes are close but the page domain is not an official brand
asset, that is strong page-side brand evidence (CONTENT-205): phishing
kits usually copy the official favicon verbatim, while ordinary pages
that merely mention a brand keep their own icon.

Image fetching reuses the scanner network safety policy (SSRF guards).
All failures degrade to "no result" and never break the scan.
"""
import hashlib
import io
import re
from typing import Callable, Dict, Optional
from urllib.parse import urljoin, urlparse

from ..utils.cache import TTLFileCache, null_cache
from ..utils.domain import registered_domain
from ..utils.tld import TLD_EXTRACTOR


try:  # pragma: no cover
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

from ..integrations.http import NetworkSafetyPolicy


HASH_SIZE = 8       # 8x8 DCT block -> 64-bit hash
IMAGE_SIZE = 32     # resized image fed to the DCT
DEFAULT_THRESHOLD = 10
MAX_IMAGE_BYTES = 256 * 1024
FAVICON_TTL = 30 * 24 * 3600


class LogoAnalyzer:
    """Compare the page favicon against a brand's official favicon."""

    def __init__(self, fetch_image: Optional[Callable] = None,
                 cache: Optional[TTLFileCache] = None,
                 threshold: int = DEFAULT_THRESHOLD,
                 safety_policy: Optional[NetworkSafetyPolicy] = None):
        self._fetch_image = fetch_image or self._default_fetch_image
        self.cache = cache or null_cache()
        self.threshold = int(threshold)
        self.safety_policy = safety_policy or NetworkSafetyPolicy()

    def analyze(self, soup, page_url: str, brand_result: Optional[dict]) -> Optional[dict]:
        """Return a logo-impersonation signal dict, or None."""
        if Image is None or not soup:
            return None
        brand_result = brand_result or {}
        brand_name = brand_result.get('brand_name')
        official_domains = brand_result.get('official_domains') or []
        if not brand_name or not official_domains or brand_result.get('is_official'):
            return None

        favicon_url = self._page_favicon_url(soup, page_url)
        if not favicon_url:
            return None
        page_domain = registered_domain(
            urlparse(favicon_url).hostname or '', TLD_EXTRACTOR,
        )
        official_domain = str(official_domains[0]).lower()
        if page_domain == official_domain:
            return None

        page_hash = self._favicon_hash(favicon_url)
        if page_hash is None:
            return None
        official_hash = self._official_favicon_hash(brand_name, official_domain)
        if official_hash is None:
            return None

        distance = hamming_distance(page_hash, official_hash)
        if distance <= self.threshold:
            return {
                'brand': brand_name,
                'method': 'phash',
                'distance': distance,
                'threshold': self.threshold,
                'page_favicon': favicon_url,
                'official_domain': official_domain,
            }
        return None

    # ------------------------------------------------------------------
    def _page_favicon_url(self, soup, page_url: str) -> str:
        for tag in soup.find_all('link'):
            rel = ' '.join(str(tag.get('rel', '')).lower().split())
            href = str(tag.get('href', '')).strip()
            if href and ('icon' in rel.split()):
                return urljoin(page_url, href)
        candidate = urljoin(page_url, '/favicon.ico')
        if self._fetch_image(candidate) is not None:
            return candidate
        return ''

    def _favicon_hash(self, favicon_url: str) -> Optional[int]:
        cached = self.cache.get(f'favicon:{favicon_url}')
        if isinstance(cached, int):
            return cached
        data = self._fetch_image(favicon_url)
        if data is None:
            return None
        computed = phash_bytes(data)
        if computed is None:
            return None
        self.cache.set(f'favicon:{favicon_url}', computed)
        return computed

    def _official_favicon_hash(self, brand_name: str, official_domain: str) -> Optional[int]:
        key = f'official-favicon:{brand_name.lower()}'
        cached = self.cache.get(key)
        if isinstance(cached, int):
            return cached
        favicon_url = f'https://{official_domain}/favicon.ico'
        data = self._fetch_image(favicon_url)
        if data is None:
            # Negative caching avoids hammering dead hosts on every scan.
            self.cache.set(key, 'unavailable')
            return None
        computed = phash_bytes(data)
        if computed is None:
            self.cache.set(key, 'unavailable')
            return None
        self.cache.set(key, computed)
        return computed

    def _default_fetch_image(self, url: str) -> Optional[bytes]:
        import requests
        try:
            self.safety_policy.validate(url)
            response = requests.get(
                url, timeout=(3, 5), stream=True,
                headers={'User-Agent': 'PhishingScanner/2.1'},
            )
            response.raise_for_status()
            content_type = response.headers.get('content-type', '').lower()
            if content_type and 'image/' not in content_type:
                response.close()
                return None
            content = bytearray()
            with response:
                for chunk in response.iter_content(chunk_size=8192):
                    content.extend(chunk[: MAX_IMAGE_BYTES - len(content)])
                    if len(content) >= MAX_IMAGE_BYTES:
                        break
            return bytes(content) if content else None
        except Exception:
            return None


def phash_bytes(data: bytes) -> Optional[int]:
    """Compute the 64-bit DCT perceptual hash of an image."""
    if Image is None:
        return None
    try:
        image = Image.open(io.BytesIO(data))
        image = image.convert('L').resize((IMAGE_SIZE, IMAGE_SIZE), Image.LANCZOS)
        if hasattr(image, 'get_flattened_data'):  # Pillow >= 12.3
            pixels = list(image.get_flattened_data())
        else:  # pragma: no cover - older Pillow
            pixels = list(image.getdata())
    except Exception:
        return None
    matrix = [pixels[row * IMAGE_SIZE:(row + 1) * IMAGE_SIZE]
              for row in range(IMAGE_SIZE)]
    dct = _dct2(matrix)
    # Skip the DC term (index 0,0): it carries brightness, not structure.
    low = [dct[row][col]
           for row in range(HASH_SIZE)
           for col in range(HASH_SIZE)][1:]
    if not low:
        return None
    median = sorted(low)[len(low) // 2]
    bits = 0
    position = 0
    for row in range(HASH_SIZE):
        for col in range(HASH_SIZE):
            if row == 0 and col == 0:
                continue
            if dct[row][col] > median:
                bits |= 1 << position
            position += 1
    return bits


def hamming_distance(first: int, second: int) -> int:
    return bin(first ^ second).count('1')


def _dct_cosine() -> list:
    import math
    return [
        math.cos((2 * index + 1) * k * math.pi / (2 * IMAGE_SIZE))
        for k in range(IMAGE_SIZE)
        for index in range(IMAGE_SIZE)
    ]


_COSINES = None


def _dct2(matrix: list) -> list:
    """Naive 2-D DCT-II; 32x32 is small enough for pure Python."""
    global _COSINES
    import math
    if _COSINES is None:
        _COSINES = _dct_cosine()

    def cos_at(k: int, index: int) -> float:
        return _COSINES[k * IMAGE_SIZE + index]

    scale = [1.0 / math.sqrt(2.0) if k == 0 else 1.0 for k in range(IMAGE_SIZE)]
    # Row transform then column transform.
    rows = [[0.0] * IMAGE_SIZE for _ in range(IMAGE_SIZE)]
    for row in range(IMAGE_SIZE):
        source = matrix[row]
        for k in range(IMAGE_SIZE):
            total = 0.0
            for index in range(IMAGE_SIZE):
                total += source[index] * cos_at(k, index)
            rows[row][k] = scale[k] * total
    result = [[0.0] * IMAGE_SIZE for _ in range(IMAGE_SIZE)]
    for col in range(IMAGE_SIZE):
        for k in range(IMAGE_SIZE):
            total = 0.0
            for row in range(IMAGE_SIZE):
                total += rows[row][col] * cos_at(k, row)
            result[k][col] = scale[k] * total
    return result
