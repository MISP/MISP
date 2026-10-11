#!/usr/bin/env python3
"""Merge CakePHP extraction output into MISP catalogs without guessing translations.

Requires polib and GNU gettext (msgmerge and msgfmt). See docs/translations.md.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

import polib

ROOT = Path(__file__).resolve().parents[1]
LOCALE = ROOT / 'app' / 'Locale'
FORMAT = re.compile(r'%(?:\d+\$)?[-+ 0#]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[bcdeEfFgGosuxX]')
LANGUAGES = {
    'ara': ('ar', 'nplurals=6; plural=(n==0 ? 0 : n==1 ? 1 : n==2 ? 2 : n%100>=3 && n%100<=10 ? 3 : n%100>=11 && n%100<=99 ? 4 : 5);'),
    'cze': ('cs', 'nplurals=3; plural=(n==1 ? 0 : n>=2 && n<=4 ? 1 : 2);'),
    'dan': ('da', 'nplurals=2; plural=(n != 1);'),
    'deu': ('de', 'nplurals=2; plural=(n != 1);'),
    'fra': ('fr_FR', 'nplurals=2; plural=(n > 1);'),
    'hun': ('hu', 'nplurals=2; plural=(n != 1);'),
    'ita': ('it', 'nplurals=2; plural=(n != 1);'),
    'jpn': ('ja', 'nplurals=1; plural=0;'),
    'kor': ('ko', 'nplurals=1; plural=0;'),
    'no': ('nb', 'nplurals=2; plural=(n != 1);'),
    'pol': ('pl', 'nplurals=3; plural=(n==1 ? 0 : n%10>=2 && n%10<=4 && (n%100<12 || n%100>14) ? 1 : 2);'),
    'pt': ('pt', 'nplurals=2; plural=(n != 1);'),
    'pt_BR': ('pt_BR', 'nplurals=2; plural=(n > 1);'),
    'ro': ('ro', 'nplurals=3; plural=(n==1 ? 0 : n==0 || (n%100>0 && n%100<20) ? 1 : 2);'),
    'rus': ('ru', 'nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<12 || n%100>14) ? 1 : 2);'),
    'si-LK': ('si', 'nplurals=2; plural=(n != 1);'),
    'spa': ('es', 'nplurals=2; plural=(n != 1);'),
    'swe': ('sv', 'nplurals=2; plural=(n != 1);'),
    'th_TH': ('th', 'nplurals=1; plural=0;'),
    'ukr': ('uk', 'nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<12 || n%100>14) ? 1 : 2);'),
    'zh-s': ('zh_CN', 'nplurals=1; plural=0;'),
}


def read_catalog(path):
    # Empty source messages collide with gettext's reserved header entry.
    blocks = path.read_text(encoding='utf-8-sig').split('\n\n')
    blocks = [block for i, block in enumerate(blocks) if i == 0 or not re.search(
        r'^msgid ""\nmsgstr ""\s*(?:""\s*)?$', block, re.M)]
    return polib.pofile('\n\n'.join(blocks), wrapwidth=0)


def normalize_template(path):
    catalog = read_catalog(path)
    catalog.metadata = {
        'Project-Id-Version': 'MISP 3.0',
        'MIME-Version': '1.0',
        'Content-Type': 'text/plain; charset=UTF-8',
        'Content-Transfer-Encoding': '8bit',
    }
    catalog.header = 'Translation template for MISP. Generated with CakePHP i18n extract.'
    catalog.metadata_is_fuzzy = False
    for entry in catalog:
        # CakePHP joins multiple line numbers with semicolons; gettext expects
        # individual file:line references, which editors can navigate.
        entry.occurrences = [(file, number) for file, numbers in entry.occurrences
                             for number in numbers.split(';')]
        if FORMAT.search(entry.msgid.replace('%%', '')) or FORMAT.search(entry.msgid_plural.replace('%%', '')):
            if 'php-format' not in entry.flags:
                entry.flags.append('php-format')
    return catalog


def refresh(templates, msgmerge, msgfmt):
    with tempfile.TemporaryDirectory() as directory:
        scratch = Path(directory)
        updates = []
        extracted_templates = sorted(templates.glob('*.pot'))
        if not extracted_templates:
            raise ValueError('No POT files found in ' + str(templates))
        for extracted in extracted_templates:
            if not (LOCALE / extracted.name).exists():
                raise ValueError('Unexpected translation domain: ' + extracted.stem)
            catalog = normalize_template(extracted)
            template = scratch / extracted.name
            catalog.save(str(template))
            updates.append((LOCALE / extracted.name, template))
            for path in sorted(LOCALE.glob('*/LC_MESSAGES/' + extracted.stem + '.po')):
                old = read_catalog(path)
                language, plural = LANGUAGES[path.parent.parent.name]
                old.metadata.setdefault('Language', language)
                if 'INTEGER' in old.metadata.get('Plural-Forms', '') or not old.metadata.get('Plural-Forms'):
                    old.metadata['Plural-Forms'] = plural
                old.metadata_is_fuzzy = False
                previous = scratch / 'previous.po'
                old.save(str(previous))
                result = subprocess.run([msgmerge, '--quiet', '--no-fuzzy-matching', '--no-wrap',
                                         str(previous), str(template)], check=True, capture_output=True)
                merged = scratch / (path.parent.parent.name + '-' + path.name)
                merged.write_bytes(result.stdout)
                subprocess.run([msgfmt, '--check', '--check-format', '-o', os.devnull, str(merged)], check=True)
                updates.append((path, merged))
        for destination, source in updates:
            destination.write_bytes(source.read_bytes())
            print(destination.relative_to(ROOT))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--templates', type=Path, required=True, help='Directory with CakePHP-extracted POT files')
    parser.add_argument('--msgmerge', default='msgmerge')
    parser.add_argument('--msgfmt', default='msgfmt')
    args = parser.parse_args()
    refresh(args.templates, args.msgmerge, args.msgfmt)
