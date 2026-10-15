"""UTS#39-style skeleton and script-mixing detection.

Implements the Unicode "skeleton" transform described in UTS #39
(Unicode Technical Standard #39, Identifier Security):

1. NFD normalization,
2. removal of nonspacing marks (category ``Mn``),
3. mapping each character through the confusables table,
repeated until the string reaches a fixed point.

Two strings that are visually confusable collapse to the same skeleton
(for example Cyrillic ``а`` and Latin ``a``).  ``mixed_script`` reports
whether a token mixes scripts (a classic IDN homograph signal).
"""
import unicodedata

from .confusables import CONFUSABLES


def skeleton(value: str) -> str:
    """Return the UTS#39-style skeleton of *value* (lowercased)."""
    text = str(value or '').lower()
    for _ in range(8):  # confusable chains are shallow; 8 rounds is ample
        previous = text
        text = unicodedata.normalize('NFD', text)
        text = ''.join(
            char for char in text
            if unicodedata.category(char) != 'Mn'
        )
        text = ''.join(
            CONFUSABLES.get(char, char) for char in text
        )
        if text == previous:
            break
    return text.lower()


def _script_name(char: str) -> str:
    try:
        name = unicodedata.name(char)
    except ValueError:
        return ''
    if name.startswith('LATIN'):
        return 'Latin'
    if name.startswith('CYRILLIC'):
        return 'Cyrillic'
    if name.startswith('GREEK'):
        return 'Greek'
    if name.startswith('HAN'):
        return 'Han'
    if name.startswith('HIRAGANA'):
        return 'Hiragana'
    if name.startswith('KATAKANA'):
        return 'Katakana'
    if name.startswith('HANGUL'):
        return 'Hangul'
    if name.startswith('ARABIC'):
        return 'Arabic'
    if name.startswith('HEBREW'):
        return 'Hebrew'
    if name.startswith('THAI'):
        return 'Thai'
    return ''


def mixed_script(value: str) -> bool:
    """Return True when *value* mixes characters from two letter scripts.

    Digits, punctuation, and combining marks are ignored so that ordinary
    hostnames with digits never count as "mixed".  Han-only strings are not
    mixed even when CJK punctuation is present.
    """
    scripts = set()
    for char in str(value or ''):
        category = unicodedata.category(char)
        if category.startswith('L'):
            script = _script_name(char)
            if script:
                scripts.add(script)
    return len(scripts) > 1
