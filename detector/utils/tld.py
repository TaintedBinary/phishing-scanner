"""Shared TLD extraction singleton.

All modules that need TLD extraction should import TLD_EXTRACTOR from here
instead of creating their own instance. This avoids redundant suffix list
loading and ensures consistent behavior across the codebase.
"""

import tldextract

TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)