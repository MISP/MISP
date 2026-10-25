#!/usr/bin/env python3
"""Check MISP gettext catalogs without requiring a running MISP instance."""

import argparse
import json
from collections import Counter
from gettext import GNUTranslations
from io import BytesIO
from pathlib import Path
import re
import sys

import polib

ROOT = Path(__file__).resolve().parents[2]


def catalog_paths():
    return sorted(path for path in (ROOT / 'app/Locale').glob('*/LC_MESSAGES/*.po')
                  if not path.parent.parent.is_symlink())


LOCALES = tuple(path.parent.parent.name for path in catalog_paths()
                if path.name == 'default.po')
COVERAGE = ROOT / 'tools/i18n/overmind-core.json'
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
    expected = [placeholders(entry.msgid)]
    if entry.msgid_plural:
        # Source variants can legitimately differ, e.g. "Tag added" /
        # "%s tags added". Single-form languages may use the count in both.
        expected.append(placeholders(entry.msgid_plural))
    if 'php-format' in entry.flags:
        # GNU gettext does not apply CakePHP's repair of bare percent signs.
        # A flagged message must be a valid format in both tools.
        for text in [entry.msgid, entry.msgid_plural] + values:
            if not text:
                continue
            covered = {index for match in PRINTF.finditer(text)
                       for index in range(match.start(), match.end())}
            if any(char == '%' and index not in covered
                   for index, char in enumerate(text)):
                errors.append('unescaped percent sign in PHP format')
    for index, value in enumerate(values):
        if value and placeholders(value) not in expected:
            errors.append('placeholders differ in translation form %s' % index)
        if value and (value.startswith('\n') != entry.msgid.startswith('\n')
                      or value.endswith('\n') != entry.msgid.endswith('\n')):
            errors.append('source and translation edge newlines differ')
    return errors


def check_catalog(path):
    # polib checks syntax and duplicate (context, msgid) keys. Compiling in
    # memory also checks the metadata/plural expression with GNU gettext.
    path = Path(path)
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
    coverage = json.loads(COVERAGE.read_text(encoding='utf-8'))
    if path.name == 'default.po' and path.parent.parent.name in coverage['locales']:
        entries = {(entry.msgctxt, entry.msgid): entry for entry in catalog}
        for message, plural in coverage['messages'].items():
            entry = entries.get((None, message))
            if (not entry or not entry.translated()
                    or entry.msgid_plural != (plural or '')):
                errors.append('%r: missing shared UI translation' % message)
    return catalog, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('catalogs', nargs='*', type=Path,
                        help='PO files; defaults to every catalog, excluding aliases')
    args = parser.parse_args()
    paths = args.catalogs or catalog_paths()
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
        template = polib.pofile(str(ROOT / 'app/Locale/default.pot'),
                                check_for_duplicates=True)
        source_keys = {entry.msgid for entry in template}
        coverage = json.loads(COVERAGE.read_text(encoding='utf-8'))
        missing = set(coverage['messages']) - source_keys
        if missing:
            print('default.pot: missing shared UI source messages: %s' % sorted(missing),
                  file=sys.stderr)
            failed = True
    except (OSError, ValueError) as error:
        print('default.pot: %s' % error, file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
