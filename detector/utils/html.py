import re

from requests.utils import get_encoding_from_headers


META_CHARSET_PATTERN = re.compile(
    br'<meta[^>]+charset\s*=\s*["\']?\s*([a-zA-Z0-9._-]+)',
    re.IGNORECASE,
)
META_CONTENT_TYPE_PATTERN = re.compile(
    br'<meta[^>]+content\s*=\s*["\'][^"\']*charset\s*=\s*([a-zA-Z0-9._-]+)',
    re.IGNORECASE,
)


def decode_content(content, headers=None, apparent_encoding=None):
    """Decode HTML bytes without silently replacing undecodable characters.

    Candidate order matters: requests' ``get_encoding_from_headers``
    returns ISO-8859-1 by default for ``text/*`` responses without an
    explicit charset, and Latin-1 decodes any byte sequence successfully.
    If that default ran first, every unlabelled UTF-8 page would decode
    to mojibake and Chinese keyword detection would silently fail.  Meta
    charset declarations and a real UTF-8 attempt therefore take
    precedence over the header-derived encoding.
    """
    content = content or b''
    headers = headers or {}
    candidates = []

    if content.startswith(b'\xef\xbb\xbf'):
        candidates.append('utf-8-sig')
    elif content.startswith((b'\xff\xfe', b'\xfe\xff')):
        candidates.append('utf-16')

    head = content[:8192]
    for pattern in (META_CHARSET_PATTERN, META_CONTENT_TYPE_PATTERN):
        match = pattern.search(head)
        if match:
            candidates.append(match.group(1).decode('ascii', errors='ignore'))

    candidates.append('utf-8')

    declared = get_encoding_from_headers(headers)
    if declared:
        candidates.append(declared)

    if apparent_encoding:
        candidates.append(apparent_encoding)
    candidates.append('gb18030')

    tried = set()
    for encoding in candidates:
        normalized = str(encoding or '').strip().lower()
        if not normalized or normalized in tried:
            continue
        tried.add(normalized)
        try:
            return content.decode(normalized, errors='strict')
        except (LookupError, UnicodeDecodeError):
            continue

    return content.decode('utf-8', errors='replace')


def decode_response(response):
    """Compatibility wrapper for search-engine response objects."""
    return decode_content(
        response.content,
        response.headers,
        getattr(response, 'apparent_encoding', None),
    )
