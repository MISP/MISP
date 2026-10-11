# MISP 3.0 translations

The application catalog contains 11,037 active source strings, including 4,712
used by the Overmind theme. Compared with the previous template, 6,438 source
keys were added and 1,115 were retired (a plural change counts as a new key).
`app/Locale/default.pot` is the field inventory: every message has its source
locations. All 21 application language catalogs and the French `cake_dev.po`
were refreshed. Retired translations remain as obsolete entries for reuse.

The initial language pass adds 434 translations: French 68, German 70,
Spanish 76, Italian 70, Portuguese 76, and Brazilian Portuguese 74. These cover
shared UI controls, search hints, analyst data, and sharing descriptions. New
translations should receive native-speaker review through the project's normal
Crowdin/reviewer workflow. Existing wording is retained; two existing newline
boundaries were repaired. A formerly singular Sinhala `cluster` translation is
preserved in the plural entry and marked fuzzy for review.

## Coverage after this refresh

Every application catalog has the same 11,037 active keys. “Review” means fuzzy;
those entries are excluded from compiled translations until reviewed.

| Locale directory | Translated | Untranslated | Review |
| --- | ---: | ---: | ---: |
| ara | 48 | 10,989 | 0 |
| cze | 390 | 10,647 | 0 |
| dan | 1,706 | 9,330 | 1 |
| deu | 1,232 | 9,805 | 0 |
| fra | 2,176 | 8,860 | 1 |
| hun | 14 | 11,023 | 0 |
| ita | 1,664 | 9,373 | 0 |
| jpn | 1,724 | 9,312 | 1 |
| kor | 271 | 10,766 | 0 |
| no | 2,149 | 8,888 | 0 |
| pol | 386 | 10,651 | 0 |
| pt | 83 | 10,954 | 0 |
| pt_BR | 936 | 10,101 | 0 |
| ro | 0 | 11,037 | 0 |
| rus | 1,301 | 9,731 | 5 |
| si-LK | 4,212 | 6,818 | 7 |
| spa | 453 | 10,584 | 0 |
| swe | 62 | 10,975 | 0 |
| th_TH | 1,957 | 9,079 | 1 |
| ukr | 2 | 11,035 | 0 |
| zh-s | 2,804 | 8,222 | 11 |

## Locale lookup

`MispL10n` resolves the existing catalog directory names without renaming them.
MISP lists these directory names in its language setting, while CakePHP maps
several of them to different paths (for example `pt` to `por` and Brazilian
Portuguese to `pt_br`). The resolver prioritizes the selected MISP directory,
retains CakePHP language metadata and fallback paths, and uses UTF-8 consistently.
It is installed by `AppController` after the language setting is applied.

## Source review and remaining work

The extraction covers application controllers, models (including validation
messages), library helpers, plugins, and both legacy and Overmind views. Vendor
code, framework code, tests, temporary files and webroot assets are excluded.
The `cake` and `cake_dev` templates contain application calls in those domains;
`cake_resque.pot` is an external dependency catalog and is unchanged.

The source pass makes natural-language search placeholders, Cerebrate preview
help, flash/modal close buttons, pagination labels, table/card controls, login,
footer, API tab labels, and shared card/field labels extractable. Distribution
labels and descriptions now use literal translation calls. Mass-action verbs,
health status labels, the TOTP delete label and an interpolated object-template
error also now extract correctly. Identifier values, URLs, hashes, JSON samples,
relationship IDs, date-format tokens and protocol names remain literal.

This catalog refresh does **not** complete all UI localization. The following
areas need a separate source pass before translating their remaining fields:

- Dashboard JavaScript modules (`app/webroot/js/dashboard/`), especially gallery,
  configure, toolbar, import/export and session-management controls. Their
  literal labels and constructed count/error messages need a locale dictionary
  and plural-aware formatting supplied by PHP.
- Embedded JavaScript in the pivot explorer
  (`View/Themed/Overmind/Elements/Events/View/event_pivot_explorer.ctp`): relationship
  picker, tray labels, notifications and errors still contain English literals.
- Metadata stored in PHP class properties (dashboard widget titles/descriptions,
  workflow module metadata and some schema help): translating a variable at the
  use site does not make its original literal discoverable by CakePHP.
- Longer workflow/API help prose and static headings: several legacy and
  Overmind copies still contain unmarked text mixed with code examples. Review
  sentence boundaries and retain escaping when adding translation calls.

Three dynamic marker warnings remain in the PHP extraction. Analyst-data chip
`$type` values (`Note`, `Opinion`, `Relationship`) already have literal entries
elsewhere. Picker text is supplied by callers and needs literal markers there.
Remote `$decoded['error']` is arbitrary upstream text and cannot be exhaustively
enumerated in a local catalog.

## Refreshing catalogs

Use the branch's CakePHP submodule and installed application PHP dependencies.
The CakePHP i18n shell expects `app/Config/database.php` to exist, although the
extractor uses reflection and does not need a database connection. Install GNU
gettext and Python `polib` for the merge step.

Run from the repository root:

```sh
mkdir -p work/translation-extract
app/Console/cake i18n extract \
    --paths "$PWD/app/" \
    --output "$PWD/work/translation-extract" \
    --exclude Lib/cakephp,Vendor,Test,tmp,webroot \
    --extract-core no --merge no --overwrite
python3 tools/update_translations.py --templates work/translation-extract
```

Inspect all extraction warnings. `tools/update_translations.py` removes empty
message entries that collide with the gettext header, normalizes source
references and adds `php-format` flags for printf messages. It merges by exact
key with `msgmerge --no-fuzzy-matching`, retains translator metadata and valid
plural rules, and supplies missing language/plural headers. All staged PO files
must pass `msgfmt --check --check-format` before any catalog is replaced. New
messages remain untranslated rather than acquiring a similar message's wording.
A change from singular to plural may be retained by gettext as a fuzzy entry;
review it before enabling the translation.

## Validation

All 22 PO files compile with gettext header, syntax, plural and format checks.
All changed PHP/CTP files pass PHP lint. The old translated entries were compared
with the refreshed files to check preservation, including obsolete entries.
The merge was repeated to check that it introduces no further catalog changes.
The real CakePHP PO loader was exercised for all 21 locale directories, six
new translated labels, English fallback, Arabic text direction, and replacement
of a resolver with an already-cached language:

```sh
php tests/test_translation_locales.php
```

Application integration tests and an interactive browser language-switch test
were not run; source and catalog checks are the validation scope of this PR.
