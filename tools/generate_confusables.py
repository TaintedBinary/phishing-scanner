# Generate detector/utils/confusables.py from Unicode UTS#39 confusables.txt
import re

SOURCE = r'C:\Users\a\AppData\Local\Temp\opencode\confusables.txt'
TARGET = r'C:\Users\a\Desktop\phishing-scanner2\detector\utils\confusables.py'

LINE_RE = re.compile(r'^([0-9A-Fa-f]+)\s*;\s*((?:[0-9A-Fa-f]+\s*)+);\s*(\w+)')

def parse():
    pairs = []
    with open(SOURCE, 'r', encoding='utf-8') as handle:
        for line in handle:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            match = LINE_RE.match(line)
            if not match:
                continue
            source = chr(int(match.group(1), 16))
            target = ''.join(
                chr(int(code, 16)) for code in match.group(2).split()
            )
            pairs.append((source, target))
    return pairs

def main():
    pairs = parse()
    # Keep mappings whose skeleton target stays within a compact charset:
    # ASCII letters/digits plus common marks.  Full data is ~6800 entries;
    # we keep every single-source mapping but drop ones whose source is
    # already ASCII (those do not occur in homograph attacks).
    kept = [(s, t) for s, t in pairs if ord(s) > 127]
    lines = [
        '"""Unicode UTS#39 confusables mapping table (auto-generated).',
        '',
        'Generated from https://www.unicode.org/Public/security/latest/',
        'confusables.txt.  Each key maps a single non-ASCII code point to its',
        'skeleton-equivalent sequence.  Do not edit by hand; regenerate with',
        'tools/generate_confusables.py.',
        '"""',
        '',
        'CONFUSABLES = {',
    ]
    for source, target in sorted(kept, key=lambda item: ord(item[0])):
        lines.append(f'    {source!r}: {target!r},')
    lines.append('}')
    lines.append('')
    with open(TARGET, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(lines))
    print(f'wrote {len(kept)} mappings to {TARGET}')

if __name__ == '__main__':
    main()
