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
                    // Same int-enum-array shape as distribution_filter
                    // (subset of {1..4}: 1=High, 2=Medium, 3=Low,
                    // 4=Undefined). Consumer widgets apply the filter
                    // as a PHP post-filter — fetchEvent doesn't
                    // natively accept `threat_level_id` (that lives in
                    // the restSearch dispatcher). Translator delegates
                    // to `_normaliseIntArray`.
                    $config[$key] = self::translateThreatLevelFilter($config[$key]);
                    break;
                case 'analysis_filter':
                    // Third int-enum-array canonical (subset of
                    // {0, 1, 2}: 0=Initial, 1=Ongoing, 2=Complete).
                    // Like threat_level_filter, applied as a PHP
                    // post-filter on the fetchEvent result —
                    // fetchEvent doesn't accept `analysis` as a
                    // filter option. The third copy of this pattern
                    // is what triggered the `_normaliseIntArray`
                    // helper extraction.
                    $config[$key] = self::translateAnalysisFilter($config[$key]);
                    break;
                case 'sharing_group_filter':
                    // Int array of SharingGroup.id values. Wire shape
                    // is the same as the int-enum canonicals
                    // (distribution / threat_level / analysis) but
                    // the valid set is NOT a fixed enum — it's the
                    // set of SGs the current user can see, which is
                    // user-specific and runtime-determined. The
                    // adapter doesn't validate against the user's
                    // accessible set (it has no user context); ACL
                    // enforcement lives in the consumer widget's
                    // query path (Event.sharing_group_id IN (...)
                    // on a base set that's already ACL-filtered, so
                    // unauthorized IDs simply match no rows — same
                    // loud-feedback semantics as out-of-range
                    // threat_level / analysis values).
                    $config[$key] = self::translateSharingGroupFilter($config[$key]);
                    break;
                case 'org_filter':
                    // Structured object — orgs list + match_via axis.
                    // Wire shape (deviation from PRD §5.5 documented in
                    // commit body — `match_via` replaces `role` to avoid
                    // collision with MISP's User.role_id concept;
                    // `orgc`/`sharing_group` replace `creator`/
                    // `distribution` to match MISP DB field naming;
                    // additive per-entry `negate` extends the canonical
                    // to preserve legacy `!`-prefix negation):
                    //   { orgs: [{ uuid?, id?, name?, negate? }],
                    //     match_via: "orgc"|"sharing_group"|"any" }
                    // Legacy input (EventStreamWidget's $params['orgs']
                    // slot): comma-separated string `"Org1,!Org2"` or
                    // array `["Org1", "!Org2"]` — translated to the
                    // canonical shape with default `match_via: "orgc"`
                    // (matches the legacy slot's existing semantic).
                    $config[$key] = self::translateOrgFilter($config[$key]);
                    break;
                case 'galaxy_cluster_filter':
                    // Structured object — galaxy_cluster_filter has
                    // two semantic axes so the bare-array convention
                    // (distribution / threat_level / analysis / SG)
                    // doesn't fit. Wire shape:
                    //   { tag_names: string[],
                    //     galaxy_types?: string[] }
                    // tag_names is the filter (specific cluster tag
                    // names like
                    //   'misp-galaxy:mitre-attack-pattern="Phishing - T1566"');
                    // galaxy_types is a picker scope hint (e.g.
                    // ['mitre-attack-pattern']) that constrains
                    // typeahead suggestions on the client. The
                    // adapter normalises both — string arrays with
                    // duplicates removed, non-string entries
                    // dropped, missing keys default to empty arrays.
                    $config[$key] = self::translateGalaxyClusterFilter($config[$key]);
                    break;
                // Phase 3 follow-ups: attribute_type_filter,
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
     * MISP's distribution enum is `{0=Org only, 1=Community,
     * 2=Connected, 3=All, 4=Sharing group, 5=Inherit}`. Wire shape
     * is an int array (canonical), scalar int / numeric string
     * (legacy or hand-edited config), or null (no filter).
     *
     * `Event::fetchEvent` accepts the int array directly under
     * `distribution` (line 125 of the fetchEvent body) — CakePHP's
     * IN coercion handles both scalar and array shapes. So
     * TrendingTagsWidget's consumer can pass straight through (no
     * post-filter step required), unlike threat_level / analysis
     * which lack a fetchEvent option and need PHP post-filtering.
     *
     * Out-of-range distribution levels are preserved per the
     * shared `_normaliseIntArray` contract — empty results from an
     * unknown level are louder feedback than silent filtering.
     *
     * @param mixed $value
     * @return int[]|null
     */
    public static function translateDistributionFilter($value)
    {
        return self::_normaliseIntArray($value);
    }

    /**
     * Translate a `threat_level_filter` value.
     *
     * MISP's threat_level_id enum is `{1=High, 2=Medium, 3=Low,
     * 4=Undefined}`. Wire shape is an int array (canonical), scalar
     * int / numeric string (legacy or hand-edited config), or null
     * (no filter). Out-of-range values are preserved on the array
     * path so typos surface as empty results (loud feedback) rather
     * than silent filtering.
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
        return self::_normaliseIntArray($value);
    }

    /**
     * Translate an `analysis_filter` value.
     *
     * MISP's analysis enum is `{0=Initial, 1=Ongoing, 2=Complete}`.
     * Wire shape identical to distribution_filter / threat_level_filter
     * (int array, scalar int / numeric string, null). Like
     * threat_level_filter, `Event::fetchEvent` doesn't natively
     * accept `analysis` as a filter input — consumer widgets apply
     * a PHP post-filter against the ACL-filtered result set.
     * Post-filter is ACL-safe since it can only narrow visibility.
     *
     * @param mixed $value
     * @return int[]|null
     */
    public static function translateAnalysisFilter($value)
    {
        return self::_normaliseIntArray($value);
    }

    /**
     * Translate a `sharing_group_filter` value.
     *
     * Wire shape is an int array of `SharingGroup.id` values (canonical),
     * scalar int / numeric string (legacy or hand-edited config), or
     * null (no filter). Unlike the int-enum canonicals there is no
     * fixed valid range — accessible SG IDs depend on the user, so
     * any positive integer is structurally valid here; ACL enforcement
     * happens in the consumer widget's query path against an already-
     * ACL-filtered base set.
     *
     * Same `_normaliseIntArray` contract as distribution / threat_level
     * / analysis: array passthrough, scalar/string wrap, mixed coerce
     * + non-numeric drop, null preservation. Unauthorized IDs that
     * survive the normaliser simply match no rows in the downstream
     * `Event.sharing_group_id IN (...)` clause — same loud-feedback
     * semantics as out-of-range threat_level values.
     *
     * @param mixed $value
     * @return int[]|null
     */
    public static function translateSharingGroupFilter($value)
    {
        return self::_normaliseIntArray($value);
    }

    /**
     * Translate an `org_filter` value.
     *
     * Wire shape (refined from PRD §5.5 — see commit body for rationale):
     *
     *   { orgs: [{ uuid?, id?, name?, negate? }],
     *     match_via: "orgc" | "sharing_group" | "any" }
     *
     *   - `orgs` — list of org identity records. Each entry MAY carry
     *     `uuid` (string), `id` (int), or `name` (string) — at least one
     *     must be set (defensive drop otherwise). Optional `negate: true`
     *     inverts the match for that entry (legacy `!`-prefix semantics
     *     preserved as an additive refinement to PRD §5.5).
     *   - `match_via` — which Event-Org relationship to filter on:
     *     `"orgc"` (Event.orgc_id; matches MISP DB field naming), or
     *     `"sharing_group"` (visibility via Event.sharing_group_id →
     *     SharingGroup → SharingGroupOrg), or `"any"` (either).
     *
     * Legacy inputs accepted (EventStreamWidget's `$params['orgs']`
     * slot historically holds these shapes):
     *   - Comma-separated string `"Org1,!Org2,Org3"` → canonical shape
     *     with `match_via: "orgc"` (the legacy slot's semantic) and
     *     each token wrapped into `{name: <token>, negate?: true}`.
     *   - Plain array `["Org1", "!Org2"]` → same translation per entry.
     *   - null → null.
     *   - other unrecognised shapes → null.
     *
     * Out-of-domain values (unknown org names/UUIDs/IDs) survive the
     * normaliser; the consumer widget's query path matches them against
     * an already-ACL-filtered base set — unauthorised or non-existent
     * identifiers simply match no rows, same loud-feedback semantics
     * as the other identity canonicals.
     *
     * @param mixed $value
     * @return array|null
     */
    public static function translateOrgFilter($value)
    {
        if ($value === null) {
            return null;
        }
        // Legacy comma-separated string from EventStreamWidget's
        // $params['orgs'] historical shape.
        if (is_string($value)) {
            $tokens = array_map('trim', explode(',', $value));
            $tokens = array_filter($tokens, function ($t) { return $t !== ''; });
            return [
                'orgs'      => array_values(array_map([self::class, '_orgTokenToEntry'], $tokens)),
                'match_via' => 'orgc',
            ];
        }
        if (!is_array($value)) {
            return null;
        }
        // Legacy plain array of token strings (no `orgs`/`match_via` keys).
        $hasShape = array_key_exists('orgs', $value)
                 || array_key_exists('match_via', $value);
        if (!$hasShape) {
            $tokens = array_filter($value, 'is_string');
            $tokens = array_filter($tokens, function ($t) { return $t !== ''; });
            return [
                'orgs'      => array_values(array_map([self::class, '_orgTokenToEntry'], $tokens)),
                'match_via' => 'orgc',
            ];
        }
        // Canonical shape — normalise both axes.
        $orgs = [];
        if (isset($value['orgs']) && is_array($value['orgs'])) {
            foreach ($value['orgs'] as $entry) {
                $normalised = self::_normaliseOrgEntry($entry);
                if ($normalised !== null) {
                    $orgs[] = $normalised;
                }
            }
        }
        $matchVia = isset($value['match_via']) && is_string($value['match_via'])
            ? $value['match_via']
            : 'any';
        if (!in_array($matchVia, ['orgc', 'sharing_group', 'any'], true)) {
            $matchVia = 'any';
        }
        return ['orgs' => $orgs, 'match_via' => $matchVia];
    }

    /**
     * Token string ("Org1" or "!Org2") to canonical entry.
     */
    private static function _orgTokenToEntry($token)
    {
        $negate = false;
        if (strlen($token) > 0 && $token[0] === '!') {
            $negate = true;
            $token = substr($token, 1);
        }
        $entry = ['name' => $token];
        if ($negate) $entry['negate'] = true;
        return $entry;
    }

    /**
     * Normalise one canonical org entry. At least one of `uuid` / `id`
     * / `name` must be present (defensive); `negate` (when present)
     * coerces to bool. Returns null when no identity key is set —
     * dropped from the translated list.
     */
    private static function _normaliseOrgEntry($entry)
    {
        if (!is_array($entry)) return null;
        $out = [];
        if (isset($entry['uuid']) && is_string($entry['uuid']) && $entry['uuid'] !== '') {
            $out['uuid'] = $entry['uuid'];
        }
        if (isset($entry['id']) && (is_int($entry['id']) || (is_string($entry['id']) && is_numeric($entry['id'])))) {
            $out['id'] = (int)$entry['id'];
        }
        if (isset($entry['name']) && is_string($entry['name']) && $entry['name'] !== '') {
            $out['name'] = $entry['name'];
        }
        if ($out === []) return null;
        if (!empty($entry['negate'])) $out['negate'] = true;
        return $out;
    }

    /**
     * Translate a `galaxy_cluster_filter` value.
     *
     * Wire shape is a structured object — galaxy_cluster_filter has
     * two semantic axes so it doesn't fit the bare-array convention:
     *
     *   { tag_names:   string[],
     *     galaxy_types?: string[] }
     *
     *   - `tag_names`: the actual filter — array of literal galaxy
     *     cluster tag names (e.g. `'misp-galaxy:mitre-attack-pattern=
     *     "Phishing - T1566"'`). Consumer widgets filter events to
     *     those tagged with any of these.
     *   - `galaxy_types`: a picker scope hint — array of galaxy type
     *     keys (e.g. `['mitre-attack-pattern', 'mitre-tool']`) that
     *     constrains the typeahead suggestions in the picker.
     *     Optional; absent / empty = unconstrained suggestions.
     *
     * Normalises:
     *   - object with both keys → both normalised to unique-string-array
     *   - missing keys → defaulted to []
     *   - non-array inputs → null (no filter)
     *   - null → null (no filter)
     *
     * Duplicate string entries removed, non-string entries dropped.
     * Empty `tag_names` after normalisation = no filter (the consumer's
     * truthiness check on `tag_names` treats empty array as inactive).
     *
     * @param mixed $value
     * @return array|null
     */
    public static function translateGalaxyClusterFilter($value)
    {
        if ($value === null) {
            return null;
        }
        if (!is_array($value)) {
            return null;
        }
        // Structured object check — assoc arrays look like indexed
        // arrays in PHP. Accept any array that has tag_names or
        // galaxy_types keys; otherwise return null.
        $hasShape = array_key_exists('tag_names', $value)
                 || array_key_exists('galaxy_types', $value);
        if (!$hasShape) {
            return null;
        }
        return [
            'tag_names'    => self::_normaliseStringArray($value['tag_names'] ?? []),
            'galaxy_types' => self::_normaliseStringArray($value['galaxy_types'] ?? []),
        ];
    }

    /**
     * Shared normaliser for int-enum-array canonicals. Extracted on
     * the third copy (distribution_filter + threat_level_filter
     * landed first with parallel implementations; analysis_filter
     * forced the extraction).
     *
     * Accepts:
     *   - int array `[0, 1, 2]` → unchanged (canonical happy path).
     *   - scalar int `3` → wrapped to `[3]`.
     *   - scalar numeric string `"3"` → wrapped to `[3]`.
     *   - mixed array `[0, "1", 2.0, "bad"]` → numeric entries
     *     coerced to int; non-numeric dropped → `[0, 1, 2]`.
     *   - empty array `[]` → unchanged (no filter).
     *   - null → null (no filter).
     *   - other unrecognised shapes → null (defensive — consumer's
     *     truthiness check treats null as "no filter applied").
     *
     * Out-of-range values are preserved on the array path — each
     * consumer's enum has a different valid set ({0..5} for
     * distribution, {1..4} for threat_level, {0..2} for analysis)
     * and CakePHP's IN coercion (or the PHP post-filter's in_array)
     * matches no rows for unknown values. Filtering here would
     * silently mask user typos which is worse than the empty-result
     * feedback loop.
     *
     * @param mixed $value
     * @return int[]|null
     */
    private static function _normaliseIntArray($value)
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
     * Normalise a value to a unique-string array. Used by
     * `translateGalaxyClusterFilter` for both the `tag_names` filter
     * axis and the `galaxy_types` scope hint.
     *
     * Accepts:
     *   - string array → duplicates removed, non-strings dropped.
     *   - scalar string → wrapped to `[string]`.
     *   - null / non-array / non-scalar → empty `[]`.
     *
     * Returns an indexed array (sequential int keys) so JSON
     * serialisation of the canonical value produces a JS array,
     * not a `{0: "x", 2: "y"}` object.
     *
     * @param mixed $value
     * @return string[]
     */
    private static function _normaliseStringArray($value)
    {
        if (is_string($value)) {
            return $value === '' ? [] : [$value];
        }
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        $seen = [];
        foreach ($value as $entry) {
            if (!is_string($entry) || $entry === '') continue;
            if (isset($seen[$entry])) continue;
            $seen[$entry] = true;
            $out[] = $entry;
        }
        return $out;
    }

    // ====================================================================
    // Validators (PRD §5.5 — Phase 3 closer)
    // --------------------------------------------------------------------
    // Stricter shape checks than the translate<Type> methods. Each
    // translator is lenient by design (legacy passthrough, fallback to
    // null on weird inputs) — but at SAVE time we want to reject
    // outright-wrong shapes loudly so a buggy client or a malformed
    // REST payload surfaces immediately rather than silently coercing
    // to an empty filter the user didn't ask for.
    //
    // Validators accept both canonical and legacy shapes (mirrors the
    // translator's acceptance set), so a layout drag that re-POSTs a
    // saved legacy config doesn't fail validation. They reject values
    // that fit neither shape (object where a scalar is expected,
    // scalar where an object is expected, etc.).

    /**
     * Walk the widget's $schema; for every canonical-typed slot present
     * in $config, run the per-type validator. Returns null on success,
     * or an associative `<schemaKey> => <error message>` array of
     * failures. Designed for the controller to convert to a 400
     * response.
     *
     * Pure shape validation — does NOT enforce per-enum value ranges
     * (e.g. threat_level in {1..4}). Out-of-range values are caught at
     * the consumer's IN clause naturally (no rows match), which gives
     * the user loud-but-recoverable feedback. Value-range checks belong
     * in the picker, not the validator.
     *
     * @param object $widget Widget instance.
     * @param array  $config Widget config to validate.
     * @return array|null Associative error map, or null when valid.
     */
    public static function validate($widget, array $config): ?array
    {
        $schema = WidgetSchema::getSchema($widget);
        if ($schema === []) {
            return null;
        }
        $errors = [];
        foreach ($schema as $key => $entry) {
            if (!is_array($entry) || !isset($entry['type'])) {
                continue;
            }
            if (!array_key_exists($key, $config)) {
                continue;
            }
            $value = $config[$key];
            $error = null;
            switch ($entry['type']) {
                case 'time_window':
                    $error = self::validateTimeWindow($value);
                    break;
                case 'date_range':
                    $error = self::validateDateRange($value);
                    break;
                case 'tag_filter':
                    $error = self::validateTagFilter($value);
                    break;
                case 'org_meta_filter':
                    $error = self::validateOrgMetaFilter($value);
                    break;
                case 'distribution_filter':
                case 'threat_level_filter':
                case 'analysis_filter':
                case 'sharing_group_filter':
                    $error = self::validateIntArrayCanonical($value);
                    break;
                case 'galaxy_cluster_filter':
                    $error = self::validateGalaxyClusterFilter($value);
                    break;
                case 'org_filter':
                    $error = self::validateOrgFilter($value);
                    break;
                // Phase 3 follow-ups: attribute_type_filter,
                // event_id_filter. Each lands with its translate<Type>
                // and adds a case here.
            }
            if ($error !== null) {
                $errors[$key] = $error;
            }
        }
        return $errors === [] ? null : $errors;
    }

    /** scalar / null only; PRD §5.5 wire-shape table. */
    public static function validateTimeWindow($value): ?string
    {
        if ($value === null || is_int($value) || is_string($value)) {
            return null;
        }
        return 'time_window must be a scalar (null, int seconds, '
             . 'or string like "7d" / "P7D" / "PT12H").';
    }

    /** `{from: <string|null>, to: <string|null>}` object. */
    public static function validateDateRange($value): ?string
    {
        if ($value === null) return null;
        if (!is_array($value)) {
            return 'date_range must be an object with from / to keys.';
        }
        foreach (['from', 'to'] as $axis) {
            if (!array_key_exists($axis, $value)) continue;
            $v = $value[$axis];
            if ($v !== null && !is_string($v)) {
                return "date_range.$axis must be a string or null.";
            }
        }
        return null;
    }

    /** `{include?: string[], exclude?: string[]}` object. */
    public static function validateTagFilter($value): ?string
    {
        if ($value === null) return null;
        if (!is_array($value)) {
            return 'tag_filter must be an object with include / exclude arrays.';
        }
        foreach (['include', 'exclude'] as $axis) {
            if (!array_key_exists($axis, $value)) continue;
            $v = $value[$axis];
            if ($v === null) continue;
            if (!is_array($v)) {
                return "tag_filter.$axis must be an array of strings.";
            }
            foreach ($v as $entry) {
                if (!is_string($entry)) {
                    return "tag_filter.$axis entries must be strings.";
                }
            }
        }
        return null;
    }

    /** Object with optional sector/type/nationality/name/uuid/local keys. */
    public static function validateOrgMetaFilter($value): ?string
    {
        if ($value === null) return null;
        if (!is_array($value)) {
            return 'org_meta_filter must be an object.';
        }
        return null;
    }

    /**
     * Shared validator for the four int-array-canonical types
     * (distribution / threat_level / analysis / sharing_group). Accepts
     * the same shapes _normaliseIntArray normalises — int, numeric
     * string, or array of those — and rejects everything else.
     */
    public static function validateIntArrayCanonical($value): ?string
    {
        if ($value === null) return null;
        if (is_int($value)) return null;
        if (is_string($value)) {
            return is_numeric($value) ? null
                : 'int-array canonical must be int, numeric string, '
                . 'or array of those.';
        }
        if (!is_array($value)) {
            return 'int-array canonical must be int, numeric string, '
                 . 'or array of those.';
        }
        foreach ($value as $entry) {
            if (is_int($entry)) continue;
            if (is_string($entry) && is_numeric($entry)) continue;
            if (is_float($entry) && is_finite($entry)) continue;
            return 'int-array canonical entries must be numeric.';
        }
        return null;
    }

    /**
     * `{orgs: [...], match_via: ...}` object, or legacy string/array
     * shapes accepted by the translator.
     */
    public static function validateOrgFilter($value): ?string
    {
        if ($value === null) return null;
        // Legacy string ("Org1,!Org2") and plain array of strings are
        // accepted shapes — translator wraps them.
        if (is_string($value)) return null;
        if (!is_array($value)) {
            return 'org_filter must be an object, a comma-separated string, or an array of names.';
        }
        $hasShape = array_key_exists('orgs', $value)
                 || array_key_exists('match_via', $value);
        if (!$hasShape) {
            // Plain array of org name strings → translator handles it.
            foreach ($value as $entry) {
                if (!is_string($entry)) {
                    return 'org_filter array entries must be strings (org names with optional ! prefix).';
                }
            }
            return null;
        }
        if (isset($value['orgs'])) {
            if (!is_array($value['orgs'])) {
                return 'org_filter.orgs must be an array of org entries.';
            }
            foreach ($value['orgs'] as $entry) {
                if (!is_array($entry)) {
                    return 'org_filter.orgs entries must be objects with uuid/id/name.';
                }
                $hasIdentity = (isset($entry['uuid']) && is_string($entry['uuid']) && $entry['uuid'] !== '')
                            || (isset($entry['id']) && (is_int($entry['id']) || (is_string($entry['id']) && is_numeric($entry['id']))))
                            || (isset($entry['name']) && is_string($entry['name']) && $entry['name'] !== '');
                if (!$hasIdentity) {
                    return 'org_filter.orgs entries must declare at least one of uuid / id / name.';
                }
            }
        }
        if (isset($value['match_via'])) {
            if (!is_string($value['match_via'])
                || !in_array($value['match_via'], ['orgc', 'sharing_group', 'any'], true)
            ) {
                return 'org_filter.match_via must be one of: orgc, sharing_group, any.';
            }
        }
        return null;
    }

    /** `{tag_names: string[], galaxy_types?: string[]}` object. */
    public static function validateGalaxyClusterFilter($value): ?string
    {
        if ($value === null) return null;
        if (!is_array($value)) {
            return 'galaxy_cluster_filter must be an object with tag_names / galaxy_types.';
        }
        $hasShape = array_key_exists('tag_names', $value)
                 || array_key_exists('galaxy_types', $value);
        if (!$hasShape) {
            // Bare arrays (without the structured keys) are how the
            // translator silently drops malformed input; surface that
            // shape as an error here so the caller knows the value
            // won't take effect.
            return 'galaxy_cluster_filter must declare tag_names and/or galaxy_types.';
        }
        foreach (['tag_names', 'galaxy_types'] as $axis) {
            if (!array_key_exists($axis, $value)) continue;
            $v = $value[$axis];
            if ($v === null) continue;
            if (is_string($v)) continue; // _normaliseStringArray accepts scalars
            if (!is_array($v)) {
                return "galaxy_cluster_filter.$axis must be an array of strings.";
            }
            foreach ($v as $entry) {
                if (!is_string($entry)) {
                    return "galaxy_cluster_filter.$axis entries must be strings.";
                }
            }
        }
        return null;
    }
}
