<?php

/**
 * Widget `$schema` property contract helper (PRD §5.7).
 *
 * A widget class may declare a `$schema` property that documents each
 * configurable parameter with a `type` drawn from the canonical
 * catalogue (PRD §5.5) or a scalar fallback. The schema drives:
 *
 *   - The configure form's typed-fields tier (DD-06).
 *   - Toolbar reachability (PRD §5.6 / DD-05): the bulk-edit toolbar
 *     shows a control for canonical type X iff at least one widget on
 *     the dashboard declares X in its `$schema`.
 *   - The canonical-type adapter (PRD §5.5): knows which slots in a
 *     widget's config are canonical and need legacy-format translation
 *     on the way to `handler()`.
 *
 * Contract (per PRD §5.7):
 *
 *   public $schema = [
 *       '<param_key>' => [
 *           'type'     => '<canonical-type | scalar-type>',
 *           'default'  => <any>,         // optional
 *           'help'     => '<string>',    // optional
 *           'required' => <bool>,        // optional
 *           'enum'     => [...],         // required when type === 'enum'
 *       ],
 *       ...
 *   ];
 *
 * A widget that doesn't declare `$schema` (custom third-party widgets,
 * legacy widgets) keeps working: getSchema() returns `[]`, the
 * configure form collapses to the key-value tier (DD-06), and the
 * widget is invisible to the toolbar.
 *
 * `$schema` is the v2 replacement for `$params`. The two are
 * complementary, not alternative: `$params` continues to drive the
 * configure form's bottom tier for parameters not described in
 * `$schema`. Per [[parity_vs_improvement]], richer typing on top of
 * the existing `$params` surface is improvement, not scope creep.
 */
class WidgetSchema
{
    /**
     * Canonical parameter types from PRD §5.5 — the JSON shape of
     * each is stable across widgets so the toolbar's bulk-edit
     * semantics work without per-widget special-casing.
     */
    const CANONICAL_TYPES = [
        'time_window',
        'date_range',
        'tag_filter',
        'org_filter',
        'org_meta_filter',
        'sharing_group_filter',
        'galaxy_cluster_filter',
        'distribution_filter',
        'threat_level_filter',
        'analysis_filter',
        'attribute_type_filter',
        'event_id_filter',
    ];

    /**
     * Scalar fallback types for free-form widget-specific knobs
     * (`threshold`, `over_time`, etc.) — never reach the toolbar.
     */
    const SCALAR_TYPES = [
        'string',
        'int',
        'bool',
        'enum',
    ];

    /**
     * Subset of CANONICAL_TYPES that the dashboard toolbar surfaces
     * as a bulk-edit control. Mirrors the "Toolbar-eligible: yes"
     * column in PRD §5.5. `attribute_type_filter` and
     * `event_id_filter` are widget-only — they don't make sense at
     * board level.
     */
    const TOOLBAR_ELIGIBLE_TYPES = [
        'time_window',
        'date_range',
        'tag_filter',
        'org_filter',
        'org_meta_filter',
        'sharing_group_filter',
        'galaxy_cluster_filter',
        'distribution_filter',
        'threat_level_filter',
        'analysis_filter',
    ];

    /**
     * Return the widget's declared schema, or [] if none / malformed.
     *
     * Defensive: a widget that defines `$schema` as a non-array (dev
     * error) is treated the same as one that doesn't define it at
     * all — the configure form collapses to the key-value tier.
     * Call validate() at catalogue-load time to surface the dev
     * error separately.
     *
     * @param object $widget Widget instance (not a class name).
     * @return array
     */
    public static function getSchema($widget)
    {
        if (!is_object($widget)) {
            return [];
        }
        if (!property_exists($widget, 'schema')) {
            return [];
        }
        $schema = $widget->schema;
        if (!is_array($schema)) {
            return [];
        }
        return $schema;
    }

    /**
     * Validate a `$schema` array against the contract.
     *
     * Returns null when the schema is well-formed. Otherwise returns
     * an associative array of `<param_key> => <error message>`
     * suitable for logging at catalogue-load time.
     *
     * The top-level `$schema = []` (empty array) is valid — it means
     * the widget explicitly declares no typed parameters and the
     * configure form will use the key-value tier only.
     *
     * @param mixed $schema The value of $widget->schema.
     * @return array<string,string>|null Errors keyed by param, or null.
     */
    public static function validate($schema)
    {
        if (!is_array($schema)) {
            return ['_schema' => 'schema must be an array'];
        }
        $errors = [];
        $known = array_merge(self::CANONICAL_TYPES, self::SCALAR_TYPES);
        foreach ($schema as $key => $entry) {
            if (!is_string($key) || $key === '') {
                $errors['_keys'] = 'all schema keys must be non-empty strings';
                continue;
            }
            if (!is_array($entry)) {
                $errors[$key] = 'entry must be an array';
                continue;
            }
            if (!isset($entry['type'])) {
                $errors[$key] = "missing required 'type'";
                continue;
            }
            if (!is_string($entry['type']) || !in_array($entry['type'], $known, true)) {
                $errors[$key] = sprintf("unknown type '%s'", is_string($entry['type']) ? $entry['type'] : gettype($entry['type']));
                continue;
            }
            if ($entry['type'] === 'enum') {
                if (!isset($entry['enum']) || !is_array($entry['enum']) || empty($entry['enum'])) {
                    $errors[$key] = "type=enum requires non-empty 'enum' array";
                    continue;
                }
            }
            if (isset($entry['required']) && !is_bool($entry['required'])) {
                $errors[$key] = "'required' must be boolean";
                continue;
            }
            if (isset($entry['help']) && !is_string($entry['help'])) {
                $errors[$key] = "'help' must be a string";
                continue;
            }
        }
        return $errors === [] ? null : $errors;
    }

    /**
     * Convenience predicate for Phase 3 toolbar reachability: is a
     * given canonical type one that the dashboard toolbar surfaces?
     *
     * @param string $type
     * @return bool
     */
    public static function isToolbarEligible($type)
    {
        return is_string($type) && in_array($type, self::TOOLBAR_ELIGIBLE_TYPES, true);
    }
}
