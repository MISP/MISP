"""Regression checks for placeholder loss, reordering and plural completeness."""
import importlib.util
from pathlib import Path

import polib

spec = importlib.util.spec_from_file_location(
    'translation_check', Path(__file__).resolve().parents[1] / 'tools/i18n/check.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def test_positional_parameters_can_be_reordered():
    entry = polib.POEntry(msgid='%s created %d events',
                         msgstr='%2$d Ereignisse von %1$s erstellt')
    assert checker.validate_entry(entry, 2) == []


def test_repeated_parameters_keep_their_positions():
    entry = polib.POEntry(msgid='%s / %s', msgstr='%1$s / %1$s')
    assert checker.validate_entry(entry, 2)


def test_dropped_or_changed_parameters_are_rejected():
    for value in ['Erstellt', '%d erstellt', '%s %s erstellt', '％s erstellt']:
        entry = polib.POEntry(msgid='%s created', msgstr=value)
        assert checker.validate_entry(entry, 2)


def test_pagination_tokens_are_preserved():
    entry = polib.POEntry(msgid='Page {:page} of {:pages}',
                         msgstr='Seite {:page} von {:pages}')
    assert checker.validate_entry(entry, 2) == []
    entry.msgstr = 'Seite {:page}'
    assert checker.validate_entry(entry, 2)


def test_literal_percent_signs_are_not_arguments():
    entry = polib.POEntry(msgid='%s% of %s', msgstr='%2$s 的 %1$s%')
    assert checker.validate_entry(entry, 2) == []
    assert checker.placeholders('100%%; %02d; %.2f') == {(1, 'd'): 1, (2, 'f'): 1}


def test_chinese_needs_only_one_plural_form():
    entry = polib.POEntry(msgid='%s member', msgid_plural='%s members',
                         msgstr_plural={0: '%s 个成员'})
    assert checker.validate_entry(entry, 1) == []
    assert checker.validate_entry(entry, 2)


def test_each_plural_form_needs_its_placeholders():
    entry = polib.POEntry(msgid='%s member', msgid_plural='%s members',
                         msgstr_plural={0: '%s Mitglied', 1: 'Mitglieder'})
    assert checker.validate_entry(entry, 2)


def test_untranslated_messages_keep_the_english_fallback():
    assert checker.validate_entry(polib.POEntry(msgid='Hello'), 2) == []


def test_invalid_plural_metadata_fails(tmp_path):
    path = tmp_path / 'default.po'
    catalog = polib.POFile()
    catalog.metadata = {'Content-Type': 'text/plain; charset=UTF-8'}
    catalog.save(str(path))
    _, errors = checker.check_catalog(path)
    assert errors


def test_all_priority_catalogs_are_valid():
    for locale in checker.LOCALES:
        path = checker.ROOT / 'app/Locale' / locale / 'LC_MESSAGES/default.po'
        _, errors = checker.check_catalog(path)
        assert not errors, (locale, errors)
