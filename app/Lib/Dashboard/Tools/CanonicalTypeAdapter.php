<?php

App::uses('WidgetSchema', 'Lib/Dashboard/Tools');

/**
 * Canonical-type adapter (PRD §5.5 keystone).
 *
 * Per the additive-only posture, v2 doesn't touch legacy widget
 * `handler()` parsing. Instead, a single adapter sits in front of
 * `handler()` and translates canonical wire shapes (ISO 8601
 * durations, `date_range` objects, etc.) into the legacy shape each
 * widget's handler already parses. The adapter is driven off
 * `$widget->$schema` (see WidgetSchema): a config key whose schema
 * entry declares a canonical `type` gets routed to the matching
 * per-type translator; non-canonical (scalar) entries and keys
 * without a schema entry are passed through unchanged.
 *
 * Two responsibilities — call them in this order, in `translate()`:
 *
 *   1. **Default injection** for missing-but-schema'd keys. Per
 *      lesson #2 of the 2026-05-18 handoff, canonical-type defaults
 *      were deliberately omitted in the Phase 2 schema backfill so
 *      they couldn't reach legacy handlers in canonical shape; this
 *      adapter is the right place to apply them because the
 *      translation hop is in place.
 *
 *   2. **Canonical → legacy translation** per the PRD §5.5 table:
 *
 *        time_window:
 *          - `P<N>D`            → `<N>d`              (legacy days form)
 *          - `P<N>W`            → `<N*7>d`            (weeks → days)
 *          - `PT<N>H`           → `<N*3600>` (int)    (hours → seconds)
 *          - `-1` / `"-1"`      → unchanged           (all-time sentinel)
 *          - integer seconds    → unchanged           (legacy raw seconds)
 *          - any other shape    → unchanged           (legacy values e.g. "7d")
 *
 *      Future canonical types add one `translate<Type>()` method
 *      and one `switch` case in `translate()`.
 *
 * The adapter is intentionally *defensive* — unrecognized values
 * fall through untouched so widgets parsing legacy shapes today
 * keep working without any handler change. The whole point of
 * Phase 2's `$schema` backfill being decoupled from the canonical
 * wire format was to allow legacy values (`"7d"`, raw integers)
 * to survive the contract — the adapter preserves that property.
 *
 * Call site: `DashboardsController::renderWidget()` invokes
 * `CanonicalTypeAdapter::translate($widget, $config)` right before
 * `$widget->handler($user, $config)`. The bulk-edit toolbar's
 * persisted configs flow through the same hook because they go
 * through `renderWidget` on re-render.
 */
class CanonicalTypeAdapter
{
    /**
     * Apply per-key canonical-to-legacy translation across the config,
     * driven off the widget's `$schema` declarations.
     *
     * The translation is idempotent: passing a config that's already
     * in legacy shape (or partially) leaves those keys unchanged.
     * Keys absent from `$schema` are untouched.
     *
     * @param object $widget Widget instance.
     * @param array  $config Widget config (typically from
     *                       UserSetting:dashboard or the toolbar).
     * @return array Translated config — pass directly to handler().
     */
    public static function translate($widget, array $config): array
    {
        $schema = WidgetSchema::getSchema($widget);
        if ($schema === []) {
            return $config;
        }
        foreach ($schema as $key => $entry) {
            if (!is_array($entry) || !isset($entry['type'])) {
                continue;
            }
            // Default injection — only when the key is *absent* from
            // config. An explicit `null` or empty-string value coming
            // in from the user counts as the user's choice and is
            // honored as-is (and may trigger the handler's own
            // empty()-fallback).
            if (!array_key_exists($key, $config) && array_key_exists('default', $entry)) {
                $config[$key] = $entry['default'];
            }
            if (!array_key_exists($key, $config)) {
                continue;
            }
            $type = $entry['type'];
            switch ($type) {
                case 'time_window':
                    $config[$key] = self::translateTimeWindow($config[$key]);
                    break;
                case 'date_range':
                    // 1-to-N expansion: a canonical date_range slot
                    // writes legacy start_date and end_date keys
                    // (matching the convention used by every existing
                    // start_date/end_date-consuming widget). When the
                    // legacy keys already exist in config, canonical
                    // wins — the configure form / toolbar are
                    // expected to write canonical going forward and
                    // any stale legacy values alongside should be
                    // overwritten on translate.
                    $derived = self::translateDateRange($config[$key]);
                    if ($derived !== null) {
                        foreach ($derived as $legacyKey => $legacyValue) {
                            $config[$legacyKey] = $legacyValue;
                        }
                    }
                    break;
                case 'tag_filter':
                    // 1-to-N expansion: canonical tag_filter writes
                    // the legacy `include` / `exclude` top-level keys
                    // every existing tag-filtering widget reads
                    // (TrendingTagsWidget today; future canonical
                    // adopters can read `config['tag_filter']`
                    // directly). Empty canonical lists do NOT
                    // overwrite legacy entries — same pattern as
                    // date_range — so a user's bottom-tier-set legacy
                    // include/exclude survives a canonical-unset state.
                    $derived = self::translateTagFilter($config[$key]);
                    if ($derived !== null) {
                        foreach ($derived as $legacyKey => $legacyValue) {
                            $config[$legacyKey] = $legacyValue;
                        }
                    }
                    break;
                case 'org_meta_filter':
                    // Pass-through: canonical and legacy shapes match
                    // — every consuming widget today already reads
                    // `$options[<schemaKey>]` as the {sector, type,
                    // nationality, name, uuid, local} record the
                    // canonical defines. The explicit case documents
                    // intent (vs. falling through silently) and gives
                    // us a single place to add per-widget shape
                    // normalisation later if it surfaces. See
                    // translateOrgMetaFilter() for the (currently
                    // identity) transform.
                    $config[$key] = self::translateOrgMetaFilter($config[$key]);
                    break;
                case 'distribution_filter':
                    // Canonical wire shape is an int array (subset of
                    // {0..5}). `Event::fetchEvent` already accepts
                    // either a scalar or an array under `distribution`
                    // (line 2703-2707, CakePHP IN coercion). The
                    // adapter normalises to int array so downstream
                    // SQL receives a consistent shape; legacy scalars
                    // (a user who saved `'distribution' => 3` from a
                    // hand-edited config) get wrapped into `[3]`. Empty
                    // arrays / null pass through — the widget's
                    // empty()-guard skips the WHERE clause.
                    $config[$key] = self::translateDistributionFilter($config[$key]);
                    break;
                case 'threat_level_filter':
                    // Same wire shape as distribution_filter: int array
                    // subset of {1..4} (1=High, 2=Medium, 3=Low,
                    // 4=Undefined). `Event::fetchEvent` accepts the int
                    // array directly under `threat_level_id` (Event.php
                    // line 3868). When `analysis_filter` lands as the
                    // third int-enum-array canonical type, this and
                    // `translateDistributionFilter` are the right pair
                    // to extract a shared `_normaliseIntArray` helper
                    // from. Two copies isn't yet enough.
                    $config[$key] = self::translateThreatLevelFilter($config[$key]);
                    break;
                // Phase 3 adds: org_filter, sharing_group_filter,
                // galaxy_cluster_filter, analysis_filter,
                // attribute_type_filter, event_id_filter. Each adds
                // one case + one translate<Type>() method below.
            }
        }
        return $config;
    }

    /**
     * Translate a single `time_window` value per the PRD §5.5 table.
     *
     * Accepts:
     *   - ISO 8601 day duration `P<N>D` → `"<N>d"` string (legacy)
     *   - ISO 8601 week duration `P<N>W` → `"<N*7>d"` string
     *   - ISO 8601 hour duration `PT<N>H` → `<N*3600>` int seconds
     *   - sentinel `-1` (string or int) → unchanged
     *   - integer seconds (any non-negative) → unchanged
     *   - legacy days form `"<N>d"` → unchanged
     *   - null → null
     *   - anything else → passthrough (handler's own fallback governs)
     *
     * The choice of return type (string `"<N>d"` vs int seconds)
     * mirrors the shape legacy handlers parse — TrendingTagsWidget's
     * `handler()` does `substr(..., -1) === 'd'` then falls back to
     * `(int)$value`, so both shapes are accepted.
     *
     * @param mixed $value
     * @return mixed
     */
    public static function translateTimeWindow($value)
    {
        if ($value === null) {
            return null;
        }
        if (is_int($value)) {
            return $value;
        }
        if (!is_string($value)) {
            return $value;
        }
        // ISO 8601 day duration: P<N>D
        if (preg_match('/^P([0-9]+)D$/', $value, $m)) {
            return ((int)$m[1]) . 'd';
        }
        // ISO 8601 week duration: P<N>W
        if (preg_match('/^P([0-9]+)W$/', $value, $m)) {
            return (((int)$m[1]) * 7) . 'd';
        }
        // ISO 8601 hour duration: PT<N>H — express as seconds since
        // the legacy days-form ("Nd") can't represent sub-day windows.
        if (preg_match('/^PT([0-9]+)H$/', $value, $m)) {
            return ((int)$m[1]) * 3600;
        }
        // Sentinel "-1" stays as-is; handler casts to int and matches.
        // Legacy "<N>d" passes through; the handler's substr-check
        // accepts it directly.
        // Numeric strings ("604800") pass through; handler casts.
        return $value;
    }

    /**
     * Translate a single `date_range` value into the legacy
     * `start_date` / `end_date` key pair every existing
     * start_date/end_date-consuming widget expects.
     *
     * Returns an associative array of legacy keys to inject into the
     * caller's `$config`, or `null` when the value isn't translatable.
     *
     * Canonical shape (PRD §5.5): `{ from: "<ISO date>", to: "<ISO date>" | null }`.
     *   - `from` (when a non-empty string) → `start_date`
     *   - `to`   (when a non-empty string) → `end_date`
     *   - `to: null` is the "open-ended" sentinel — `end_date` stays
     *     unset so the widget's existing "now" fallback (e.g.
     *     `EventEvolutionLineWidget`) engages.
     *
     * Legacy date strings ship verbatim — widgets parse them via
     * `new DateTime($options['start_date'])` and friends, which
     * accept the ISO YYYY-MM-DD shape canonical date_range produces.
     *
     * @param mixed $value
     * @return array<string,string>|null
     */
    public static function translateDateRange($value)
    {
        if (!is_array($value)) {
            return null;
        }
        $result = [];
        if (isset($value['from']) && is_string($value['from']) && $value['from'] !== '') {
            $result['start_date'] = $value['from'];
        }
        if (isset($value['to']) && is_string($value['to']) && $value['to'] !== '') {
            $result['end_date'] = $value['to'];
        }
        // No usable keys → return null so the caller leaves config
        // untouched (no spurious empty keys land on the handler).
        return $result === [] ? null : $result;
    }

    /**
     * Translate a single `tag_filter` value into the legacy
     * `include` / `exclude` key pair every existing tag-filtering
     * widget reads (TrendingTagsWidget today).
     *
     * Canonical shape (PRD §5.5):
     *   { include: string[], exclude: string[],
     *     taxonomies?: string[],
     *     match_event_tags?: bool, match_attribute_tags?: bool }
     *
     * Translation responsibilities (this Phase 3 landing):
     *   - `include` (non-empty array) → legacy `include`
     *   - `exclude` (non-empty array) → legacy `exclude`
     *   - empty / missing lists → not written (caller's existing
     *     legacy value, if any, survives)
     *
     * Forward-compat fields that this translator deliberately drops
     * on the floor for now:
     *   - `taxonomies` — UI hint for the picker only; no legacy
     *     widget today scopes its tag filter by taxonomy.
     *   - `match_event_tags` / `match_attribute_tags` — TrendingTags
     *     today filters tags after the events are fetched; no
     *     event-vs-attribute scoping at the canonical layer. When
     *     a future widget adopts the canonical shape directly, it
     *     can read `config['tag_filter']` (the canonical wire stays
     *     in config alongside the derived legacy keys, identical to
     *     date_range's behavior).
     *
     * String coercion is defensive — the chip-input picker emits
     * strings, but JSON round-trips can sneak non-string entries
     * (numeric tag names → numbers after JSON.parse). Legacy
     * handlers do `strpos($tag, $include)` which fatals on non-
     * strings; coerce here.
     *
     * @param mixed $value
     * @return array<string,string[]>|null
     */
    public static function translateTagFilter($value)
    {
        if (!is_array($value)) {
            return null;
        }
        $result = [];
        if (isset($value['include']) && is_array($value['include']) && $value['include'] !== []) {
            $result['include'] = array_values(array_map('strval', $value['include']));
        }
        if (isset($value['exclude']) && is_array($value['exclude']) && $value['exclude'] !== []) {
            $result['exclude'] = array_values(array_map('strval', $value['exclude']));
        }
        return $result === [] ? null : $result;
    }

    /**
     * Translate a single `org_meta_filter` value (PRD §5.5).
     *
     * Canonical shape:
     *   { sector?: string[], type?: string[], nationality?: string[],
     *     name?: string[], uuid?: string[],
     *     local?: (0|1|true|false)[] }
     * Each string entry may have a `!` prefix to negate.
     *
     * This is a **pass-through** transform — canonical and legacy
     * widget shapes match, so the function's job is normalisation
     * only:
     *   - non-array input → returned untouched (the handler's own
     *     `!empty(... && is_array(...))` defensive check will skip
     *     malformed values without exception).
     *   - scalar entries inside a key (legacy widgets coerce single
     *     values to arrays via `if (!is_array(...)) ... = [$value];`)
     *     pass through unchanged — the existing widget code handles
     *     the coercion.
     *   - empty arrays at any key pass through; the widget's
     *     `if (!empty(...))` guard skips them.
     *   - unknown keys are kept; each widget's private
     *     `$validFilterKeys` array filters down to the subset that
     *     widget understands (e.g. OrganisationMapWidget only consumes
     *     sector/type/local). Keeping unknown keys means a future
     *     widget that adds a new $validFilterKeys entry doesn't need
     *     a translator update.
     *
     * Defensive null handling: passes through unchanged so the
     * handler's empty()-guard skips the empty case.
     *
     * @param mixed $value
     * @return mixed Same shape as input.
     */
    public static function translateOrgMetaFilter($value)
    {
        return $value;
    }

    /**
     * Translate a `distribution_filter` value.
     *
     * Accepts:
     *   - int array `[0, 1, 2]` → unchanged (canonical happy path).
     *   - scalar int `3` (legacy) → wrapped to `[3]`.
     *   - scalar numeric string `"3"` → wrapped to `[3]`.
     *   - mixed array `[0, "1", 2.0, "bad"]` → numeric entries
     *     coerced to int; non-numeric dropped → `[0, 1, 2]`.
     *   - empty array `[]` → unchanged (no filter).
     *   - null → null (no filter).
     *   - other unrecognised shapes → null (defensive — fetchEvent's
     *     `if ($options['distribution'])` truthiness check treats
     *     null as "no filter applied").
     *
     * Out-of-range distribution levels (anything outside {0..5}) are
     * preserved on the array path — Event::fetchEvent passes the
     * array to CakePHP's IN coercion, an unknown level simply
     * matches no rows. Filtering here would silently mask user typos
     * which is worse than the empty-result feedback loop.
     *
     * @param mixed $value
     * @return int[]|null
     */
    public static function translateDistributionFilter($value)
    {
        if ($value === null) {
            return null;
        }
        if (is_int($value)) {
            return [$value];
        }
        if (is_string($value) && is_numeric($value)) {
            return [(int)$value];
        }
        if (!is_array($value)) {
            return null;
        }
        $out = [];
        foreach ($value as $entry) {
            if (is_int($entry)) {
                $out[] = $entry;
            } elseif (is_string($entry) && is_numeric($entry)) {
                $out[] = (int)$entry;
            } elseif (is_float($entry) && is_finite($entry)) {
                $out[] = (int)$entry;
            }
            // Non-numeric / non-finite entries are silently dropped.
        }
        return $out;
    }

    /**
     * Translate a `threat_level_filter` value.
     *
     * Accepts the same shape vocabulary as translateDistributionFilter —
     * int array (canonical), scalar int / numeric string (legacy or
     * hand-edited config), mixed numeric / non-numeric array (coerce
     * + drop), empty array / null (no filter). MISP's threat_level_id
     * enum is `{1=High, 2=Medium, 3=Low, 4=Undefined}`; out-of-range
     * values are preserved on the array path so a typo surfaces as
     * an empty result (loud feedback) instead of silent filtering.
     *
     * Unlike distribution_filter, `Event::fetchEvent` does NOT accept
     * `threat_level_id` as a filter option — that lives only in the
     * restSearch dispatcher (`set_filter_threat_level_id`). Consumer
     * widgets therefore apply the filter as a PHP post-filter against
     * the ACL-filtered fetchEvent result set, matching the pattern
     * TrendingTagsWidget uses for distribution_filter. Post-filter is
     * ACL-safe — the filter can only narrow visibility.
     *
     * @param mixed $value
     * @return int[]|null
     */
    public static function translateThreatLevelFilter($value)
    {
        if ($value === null) {
            return null;
        }
        if (is_int($value)) {
            return [$value];
        }
        if (is_string($value) && is_numeric($value)) {
            return [(int)$value];
        }
        if (!is_array($value)) {
            return null;
        }
        $out = [];
        foreach ($value as $entry) {
            if (is_int($entry)) {
                $out[] = $entry;
            } elseif (is_string($entry) && is_numeric($entry)) {
                $out[] = (int)$entry;
            } elseif (is_float($entry) && is_finite($entry)) {
                $out[] = (int)$entry;
            }
            // Non-numeric / non-finite entries are silently dropped.
        }
        return $out;
    }
}
