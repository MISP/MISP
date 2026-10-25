# MISP 3.0 translations

English (`eng`) is the source language and the fallback for untranslated text.
Set `MISP.language` in **Administration → Server Settings & Maintenance**.
The selector shows native names for these catalogs:

| Language | Setting / catalog directory | HTML language |
| --- | --- | --- |
| English | `eng` (source strings) | `en` |
| Simplified Chinese | `zh-s` | `zh-Hans` |
| French | `fra` | `fr` |
| German | `deu` | `de` |
| Portuguese (Portugal) | `pt` | `pt` |
| Portuguese (Brazil) | `pt_BR` | `pt-BR` |

`por` is a symlink to `pt`: CakePHP resolves Portuguese to `por`, while
Crowdin exports to `pt`. Keep the alias when packaging an installation. It is
not an additional language in the settings selector. Existing setting values
and Crowdin paths are preserved.

## Current scope

The 3.0 additions cover 466 messages used by Overmind navigation, sign-in,
event browsing and statistics, sharing-group popovers, filters, pagination,
bulk actions and shared side panels. Existing nonempty translations are
retained except for repairs to broken placeholders. The full application catalogs still contain untranslated messages;
this is not a claim of complete application translation. Other pages continue
to fall back to English where their catalog entries are empty or absent.

Translations use the existing `default` domain and `app/Locale/default.pot`.
Submit wording improvements through [MISP on Crowdin](https://crowdin.com/project/misp)
and obtain language review as described in [CONTRIBUTING.md](../../CONTRIBUTING.md#translating-misp).
Portuguese variants are separate catalogs: preserve vocabulary such as
`palavra-passe` / `senha` and `utilizador` / `usuário`.

## Validate changes

From the repository root:

```sh
python3 -m pip install 'polib>=1.2,<2' pytest
python3 tools/i18n/check.py
python3 -m pytest -q tests/test_translation_validation.py
git submodule update --init app/Lib/cakephp
php tests/translation_smoke.php
```

The catalog checker detects duplicate keys, invalid metadata/plural expressions,
incomplete plural entries, and changed printf or named pagination placeholders.
It reports total translated entries and permits untranslated entries so English
fallback remains available. It also checks the source template for duplicate
keys. Pass individual `.po` paths to validate other locales.

The PHP smoke check uses the actual framework loader without application
configuration or a database. It checks the six language choices, singular/plural
forms (including French/Brazilian Portuguese zero and Chinese), English fallback, and encoded navbar
messages. It also exercises the Portuguese directory alias.

For a manual UI check, open the Overmind login page and events index in each
language. Check the language selector, filters, column chooser, pagination,
sharing-group popover and theme/homepage feedback. Check narrow layouts for
long labels and verify that a message containing quotes does not break scripts.

## Prepare source strings

Wrap complete sentences in `__()` and count-dependent messages in `__n()`.
Use explicit labels rather than translating controller names or concatenating
sentence fragments. Keep `%s`, `%d`, positional placeholders such as `%2$s`,
and named tokens such as `{:page}`. Chinese has one plural form; French,
German and the Portuguese catalogs have two, with their own plural rules.

Escape translated plain text with `h()` when emitting HTML. Use `json_encode()`
with `JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT` for translated
strings inside inline scripts. Keep intentional links or other markup outside
plain-text escaping and escape their dynamic values separately.

On a configured development installation, extract into a scratch directory
before reviewing the template diff:

```sh
mkdir -p work/i18n
app/Console/cake i18n extract --paths "$PWD/app" \
  --exclude Vendor,Lib/cakephp,Plugin,tmp,files \
  --output "$PWD/work/i18n" --extract-core no \
  --ignore-model-validation --overwrite
```

Review additions against `app/Locale/default.pot`. Merge intended source updates
without discarding reviewed translations or automatically accepting fuzzy
matches. This PR adds the source messages used by the scope above; it does not
regenerate unrelated parts of the existing template. Restart PHP processes or
clear the MISP core translation cache after deploying catalog changes.
