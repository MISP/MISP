#!/usr/bin/env python3
"""Check MISP gettext catalogs without requiring a running MISP instance."""

import argparse
from collections import Counter
from gettext import GNUTranslations
from io import BytesIO
from pathlib import Path
import re
import sys

import polib

ROOT = Path(__file__).resolve().parents[2]
LOCALES = ('zh-s', 'fra', 'deu', 'pt', 'pt_BR')
# CakePHP escapes bare percent signs before calling vsprintf. In particular,
# "% of" in prose is not a conversion. Keep argument positions and types so
# translators can reorder parameters using %2$s without losing any argument.
PRINTF = re.compile(
    r"%(?:%|(?:(\d+)\$)?(?:[-+0]|'.)*(?:\d+)?(?:\.\d+)?([bcdeEfFgGosuxXdi]))"
)
NAMED = re.compile(r'\{:[A-Za-z_][A-Za-z_0-9]*\}')


def placeholders(text):
    result = Counter()
    position = 0
    for match in PRINTF.finditer(text):
        if match.group() == '%%':
            continue
        if match[1]:
            index = int(match[1])
        else:
            position += 1
            index = position
        result[(index, match[2])] += 1
    result.update(NAMED.findall(text))
    return result


def validate_entry(entry, plural_count):
    if entry.obsolete or not entry.msgid:
        return []
    values = list(entry.msgstr_plural.values()) if entry.msgid_plural else [entry.msgstr]
    if not any(values):
        return []  # Untranslated text falls back to English at runtime.
    errors = []
    if entry.msgid_plural:
        if set(entry.msgstr_plural) != set(range(plural_count)) or not all(values):
            errors.append('missing or extra plural forms')
        if placeholders(entry.msgid) != placeholders(entry.msgid_plural):
            errors.append('singular and plural source placeholders differ')
    expected = placeholders(entry.msgid)
    for index, value in enumerate(values):
        if value and placeholders(value) != expected:
            errors.append('placeholders differ in translation form %s' % index)
    return errors


def check_catalog(path):
    # polib checks syntax and duplicate (context, msgid) keys. Compiling in
    # memory also checks the metadata/plural expression with GNU gettext.
    catalog = polib.pofile(str(path), check_for_duplicates=True)
    plural_header = catalog.metadata.get('Plural-Forms', '')
    match = re.search(r'nplurals\s*=\s*(\d+)\s*;', plural_header)
    if not match or int(match[1]) < 1:
        return catalog, ['missing or invalid Plural-Forms header']
    GNUTranslations(BytesIO(catalog.to_binary()))
    errors = []
    for entry in catalog:
        for error in validate_entry(entry, int(match[1])):
            errors.append('%r: %s' % (entry.msgid, error))
    return catalog, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('catalogs', nargs='*', type=Path,
                        help='PO files; defaults to the five 3.0 priority catalogs')
    args = parser.parse_args()
    paths = args.catalogs or [ROOT / 'app/Locale' / loc / 'LC_MESSAGES/default.po'
                             for loc in LOCALES]
    failed = False
    for path in paths:
        try:
            catalog, errors = check_catalog(path)
            print('%s: %s/%s translated' % (
                path, len(catalog.translated_entries()), len(catalog)))
            for error in errors:
                print('  ' + error, file=sys.stderr)
            failed = failed or bool(errors)
        except (OSError, ValueError, SyntaxError) as error:
            print('%s: %s' % (path, error), file=sys.stderr)
            failed = True
    # The Crowdin template must also stay parseable and have unique keys.
    try:
        polib.pofile(str(ROOT / 'app/Locale/default.pot'), check_for_duplicates=True)
    except (OSError, ValueError) as error:
        print('default.pot: %s' % error, file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
