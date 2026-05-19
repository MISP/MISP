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
                // Phase 3 adds: date_range, tag_filter, org_filter,
                // sharing_group_filter, galaxy_cluster_filter,
                // distribution_filter, threat_level_filter,
                // analysis_filter, attribute_type_filter,
                // event_id_filter. Each adds one case + one
                // translate<Type>() method below.
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
}
