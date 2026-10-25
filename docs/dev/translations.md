# MISP 3.0 translations

English (`eng`) is the source language and the fallback for untranslated text.
Set `MISP.language` in **Administration → Server Settings & Maintenance**.
The selector uses native names while preserving the catalog codes from MISP 2.5.

| Language | Setting / catalog directory | HTML language |
| --- | --- | --- |
| English | `eng` (source strings) | `en` |
| Arabic | `ara` | `ar` |
| Czech | `cze` | `cs` |
| Danish | `dan` | `da` |
| German | `deu` | `de` |
| French | `fra` | `fr` |
| Hungarian | `hun` | `hu` |
| Italian | `ita` | `it` |
| Japanese | `jpn` | `ja` |
| Korean | `kor` | `ko` |
| Norwegian | `no` | `no` |
| Polish | `pol` | `pl` |
| Portuguese (Portugal) | `pt` | `pt` |
| Portuguese (Brazil) | `pt_BR` | `pt-BR` |
| Romanian | `ro` | `ro` |
| Russian | `rus` | `ru` |
| Sinhala | `si-LK` | `si-LK` |
| Spanish | `spa` | `es` |
| Swedish | `swe` | `sv` |
| Thai | `th_TH` | `th-TH` |
| Ukrainian | `ukr` | `uk` |
| Simplified Chinese | `zh-s` | `zh-Hans` |

The newer Sindarin (`sjn`) catalog remains selectable and is validated too.
Arabic pages emit `dir="rtl"`; the other languages use `dir="ltr"`.
`MispLanguage` shares display names and HTML language metadata between the
settings selector and the default/dashboard layouts for Default, UiBeta and
Overmind.

## Catalog compatibility

CakePHP resolves several language codes to directories different from Crowdin's
export paths. Keep these symlinks when packaging an installation:

| Runtime directory | Existing catalog |
| --- | --- |
| `ces` | `cze` |
| `nor` | `no` |
| `por` | `pt` |
| `ron` | `ro` |

Aliases do not appear as additional language choices. Existing configuration
values and Crowdin export paths remain valid.

Czech, Polish, Russian and Ukrainian use their three integer-count plural forms.
Their older four-form CLDR headers included decimal categories that CakePHP's
integer plural dispatcher did not recognise, causing it to select the first
form for every count. Arabic retains six forms; Romanian has three; Japanese,
Korean, Thai and Chinese have one. The other catalogs have two, including the
French and Brazilian Portuguese rule that treats zero like one.

## Current scope and language review

All 21 language catalogs shipped in MISP 2.5 cover the same 466 shared Overmind
messages: navigation, sign-in, event browsing and statistics, sharing-group
popovers, filters, pagination, bulk actions and side panels. The coverage list
is maintained in `tools/i18n/overmind-core.json` and checked automatically.
The Sindarin catalog was added in 3.0 and is not part of that coverage contract.

The full application catalogs still contain untranslated messages outside this
scope; those continue to fall back to English. Existing nonempty translations
are retained except for repairs to placeholders, percentage escaping, metadata
and newline formatting. The new wording is machine-assisted draft translation
and requires native-language review before merge. Technical validation does not
establish linguistic accuracy.

Use the existing `default` domain and `app/Locale/default.pot`. Submit wording
improvements through [MISP on Crowdin](https://crowdin.com/project/misp), with
language review as described in [CONTRIBUTING.md](../../CONTRIBUTING.md#translating-misp).
Keep Portuguese variants separate, preserving vocabulary such as `palavra-passe`
/ `senha` and `utilizador` / `usuário`.

## Validate changes

From the repository root:

```sh
python3 -m pip install 'polib>=1.2,<2' pytest
python3 tools/i18n/check.py
python3 -m pytest -q tests/test_translation_validation.py
git submodule update --init app/Lib/cakephp
php tests/translation_smoke.php work/i18n/scripts
```

The checker discovers every `.po` file under `app/Locale`, excludes symlink
aliases, and validates duplicate keys, metadata/plural expressions, complete
plural entries, printf argument positions/types, named pagination tokens and
newline boundaries. It enforces the shared UI coverage contract in each legacy
catalog and checks the source template for duplicate or missing coverage keys.
Outside that contract, empty entries are allowed to preserve English fallback.
Pass individual `.po` paths to validate a subset.

The PHP smoke check uses the real framework without application configuration,
a database or cache files. It checks catalog lookup for all language choices,
shared messages, plural dispatch for counts 0–202 and selected larger values,
English fallback, percentage formatting, HTML language/direction metadata and
navbar encoding. It renders the document openings from all six theme/layout
combinations to check language/direction attributes and retained Overmind rail
and theme attributes. A fixture with quotes, a newline and a script terminator checks
inline script escaping. The optional output directory receives rendered scripts
for JavaScript syntax checks:

```sh
for script in work/i18n/scripts/*.js; do node --check "$script"; done
```

Also run GNU gettext's compiler, which has stricter PHP format rules than
CakePHP's runtime:

```sh
find app/Locale -type f -name '*.po' -exec \
  msgfmt --check --check-format -o /dev/null '{}' \;
```

For manual review, open the login page and events index in each language. Check
the selector, filters, column chooser, pagination, sharing-group popover and
feedback messages. Review long labels on narrow layouts, Arabic text direction,
and mixed-direction identifiers/values. Full browser/layout verification remains
a separate check from catalog and runtime validation.

## Prepare source strings

Wrap complete sentences in `__()` and count-dependent messages in `__n()`.
Use explicit labels rather than translating controller names or concatenating
sentence fragments. Preserve `%s`, `%d`, positional arguments such as `%2$s`,
and named tokens such as `{:page}`. A singular source may omit a count that is
present in its plural source, for example `Tag added` / `%s tags added`.

Write literal percent signs as `%%` in PHP-format messages, in both the source
and translations. CakePHP repairs some bare percent signs at runtime; GNU
gettext rejects them in messages flagged `php-format`. For example, write
`%s%% of the data` so formatting produces `25% of the data`.

Escape translated plain text with `h()` when emitting HTML. Use `json_encode()`
with `JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT` for translated
strings inside inline scripts. Keep intentional links or markup outside plain
text escaping and escape their dynamic values separately.

On a configured development installation, extract into a scratch directory
before reviewing the template diff:

```sh
mkdir -p work/i18n
app/Console/cake i18n extract --paths "$PWD/app" \
  --exclude Vendor,Lib/cakephp,Plugin,tmp,files \
  --output "$PWD/work/i18n" --extract-core no \
  --ignore-model-validation --overwrite
```

Review additions against `app/Locale/default.pot` and update the shared coverage
list when its interface messages change. Merge intended source updates without
discarding reviewed translations or automatically accepting fuzzy matches.
Restart PHP processes or clear the MISP core translation cache after deploying
catalog changes.
