<?php

/**
 * PewPewMapWidget (dashboard v2, DD-45; named DD-48) — animated
 * "pew-pew" attacker→victim arcs derived from MISP galaxy
 * attributions on events. The name is a deliberate, playful nod to
 * the much-memed Norse attack map (DD-48).
 *
 * Renders the `PewPewMap` render kind (new with DD-45). One arc per
 * `(event, threat-actor's country, country-galaxy's ISO)` triple;
 * aggregated across events into `(src_iso, dst_iso)` pairs with a
 * `value` count. Capped at `max_arcs` (default 500, value-desc).
 *
 * Three render modes via config (DD-45 mode switch; DD-46 globe impl;
 * DD-47 WebGL globe):
 *   - `2d` (default) — ECharts geo + animated `lines` series
 *     (lines-airline style: great-circle arcs with trail effect).
 *   - `3d-globe` — the SAME ECharts geo + lines, with the geo
 *     projection swapped to a hemisphere-culling orthographic for a
 *     from-space "2.5D" globe (d3-geo `geoOrthographic`, already
 *     vendored — no echarts-gl, no WebGL; DD-46 superseded DD-45's
 *     echarts-gl plan after it proved unmaintained + echarts@6-
 *     incompatible). The lightweight globe.
 *   - `webgl-globe` (DD-47) — a real textured/lit WebGL globe via
 *     globe.gl (Three.js), lazy-loaded on first use. The premium
 *     Norse-style attack-globe; opt-in, heavier (a separate ≈508 KB
 *     gzipped bundle + a surface texture, fetched only when this mode
 *     actually renders). All front-end: same `flows[]` payload. The
 *     surface texture is selectable via `skin` (night / day / dark,
 *     DD-49) — only the chosen skin's image downloads.
 *
 * The same `flows[]` payload feeds both modes; the renderer
 * (`buildPewPewOption` in charts.module.mjs) dispatches by
 * `payload.mode` (synchronously — no lazy bundle load).
 *
 * Data resolution path (DD-45):
 *   1. Per event tagged with a `misp-galaxy:country=...` cluster
 *      whose cluster carries an `ISO` galaxy element, collect the
 *      victim ISO list.
 *   2. For the SAME event, collect attacker ISO list from
 *      `misp-galaxy:threat-actor=...` clusters whose cluster
 *      carries a `country` galaxy element (937 of ~5000 actor
 *      clusters on the dev DB carry it; clusters without it are
 *      silently dropped).
 *   3. Cross-product `(actor_iso, victim_iso)` within each event,
 *      skip self-loops.
 *   4. Aggregate by `(src_iso, dst_iso)` → integer `value` count.
 *   5. Sort value-desc, slice to `max_arcs`.
 *   6. Resolve centroids from `iso-centroids.json` (DD-45 Phase B1).
 *      ISO codes without a centroid (de-facto entities, etc.) are
 *      silently dropped.
 *
 * Aggregate-only posture (matches AttributeGeoMapWidget DD-11):
 * no `drilldown` URLs (no stable region→events mapping since the
 * arc resolution is computed transiently per render), no admin
 * gate (the widget surfaces only ISO-level aggregates with no
 * per-user variation).
 *
 * Caching (DD-20): `$cache_duration=3600` + `$cache_scope='global'`
 * (default for cache_scope, but stated explicitly via $cache_path).
 * Galaxies and their `country` / `ISO` elements change rarely, so
 * a 1-hour aggregate cache is generous and a config-keyed global
 * payload is correct.
 */
class PewPewMapWidget
{
    public $title = 'Pew-pew map';
    public $category = 'events';
    public $render = 'PewPewMap';
    public $description = 'Pew pew map threat-actor origin country and victim country, derived from misp-galaxy:threat-actor and misp-galaxy:country tags on events. Renders as a 2D flat map (default, animated great-circle lines), a lightweight orthographic "globe" view of the same arcs, or an opt-in real WebGL 3D globe (globe.gl, lazy-loaded).';
    public $width = 6;
    public $height = 5;
    // cacheLifetime + autoRefreshDelay are inert in dashboard v2 —
    // caching is the generic WidgetCache opt-in (DD-20) via
    // $cache_duration + $cache_path below.
    public $cacheLifetime = false;
    public $autoRefreshDelay = false;
    public $cache_path = 'misp:pew_pew_map_cache';
    public $cache_duration = 3600;
    public $params = [
        'time_window' => 'The time window, going back in seconds, that should be included (also accepts "30d" day form, or -1 for all historic data).',
        'mode' => 'Render mode: "2d" (default, animated lines-airline arcs on a flat map), "3d-globe" (the same arcs on a lightweight orthographic from-space globe), or "webgl-globe" (a real textured 3D globe via globe.gl/Three.js, lazy-loaded on first use — opt-in, heavier).',
        'skin' => 'Surface texture for the "webgl-globe" mode only: "night" (default, city lights), "day" (NASA Blue Marble daytime earth), or "dark" (minimal grey). Ignored by the 2d/3d-globe modes.',
        'max_arcs' => 'Maximum number of arcs rendered. Truncation is value-desc so the strongest signals always render. Default 500.',
    ];
    public $schema = [
        'time_window' => [
            'type' => 'time_window',
            'default' => 'P30D',
            'help' => 'Recency window over which events are scanned (last N days/hours, or all time). Toolbar-reachable.',
        ],
        'mode' => [
            'type' => 'enum',
            'enum' => ['2d', '3d-globe', 'webgl-globe'],
            // Stored values stay '2d'/'3d-globe'/'webgl-globe' (schema
            // stability, DD-44/DD-46/DD-47); the configure-form <select>
            // shows these friendly labels. Two distinct "globe" labels
            // so the lightweight (orthographic) vs. real-3D (WebGL)
            // distinction is explicit at the point of choice.
            'enum_labels' => [
                '2d' => '2D map',
                '3d-globe' => 'Globe (lightweight)',
                'webgl-globe' => 'Globe (3D)',
            ],
            'default' => '2d',
            'help' => 'Render mode. 2D flat-map animated arcs (default); "Globe (lightweight)" — an orthographic from-space view of the same arcs, no extra download; or "Globe (3D)" — a real textured WebGL globe (globe.gl), lazy-loaded on first use (heavier, opt-in).',
        ],
        'skin' => [
            'type' => 'enum',
            'enum' => ['night', 'day', 'dark', 'char'],
            // Texture skin for the "Globe (3D)" mode only (DD-49); the
            // 2D / lightweight-globe modes ignore it. Only the selected
            // skin's image is fetched (lazy, per instance). 'char' is an
            // easter-egg skin (custom char.png texture).
            'enum_labels' => [
                'night' => 'Night (city lights)',
                'day' => 'Day (Blue Marble)',
                'dark' => 'Dark (minimal)',
                'char' => 'Char',
            ],
            'default' => 'night',
            'help' => 'Surface texture for the "Globe (3D)" mode only (ignored by the 2D / lightweight-globe modes): "Night" city-lights (default, dramatic — arcs pop), "Day" NASA Blue Marble (bright daytime earth), or "Dark" minimal grey silhouette.',
        ],
        'max_arcs' => [
            'type' => 'int',
            'default' => 500,
            'help' => 'Maximum number of arcs rendered; truncation is value-desc so the strongest signals always render.',
        ],
    ];
    public $placeholder =
'{
    "time_window": "30d",
    "mode": "2d",
    "skin": "night",
    "max_arcs": 500
}';

    // Vendor path for ISO → centroid lookup (DD-45 Phase B1).
    // WWW_ROOT is /<repo>/app/webroot/, so JS / DS / ... lands us
    // at the existing chart-vendor directory.
    const ISO_CENTROIDS_FILE = 'js' . DS . 'dashboard' . DS . 'charts' . DS . 'vendor' . DS . 'iso-centroids.json';

    private $centroidCache = null;

    public function handler($user, $options = array())
    {
        $since = $this->resolveSince($options);
        $mode = $this->resolveMode($options);
        $skin = $this->resolveSkin($options);
        $maxArcs = (!empty($options['max_arcs']) && (int)$options['max_arcs'] > 0)
            ? (int)$options['max_arcs'] : 500;

        // Victims first — these gate everything (events without a
        // country galaxy can't yield an arc).
        $victims = $this->collectIsoByEvent('country', 'ISO', $since, null);
        if (empty($victims)) {
            return ['mode' => $mode, 'skin' => $skin, 'flows' => []];
        }
        // Attackers restricted to the same event id set — saves the
        // join the cost of scanning threat-actor tags on events
        // that can't yield an arc anyway.
        $attackers = $this->collectIsoByEvent('threat-actor', 'country', $since, array_keys($victims));
        if (empty($attackers)) {
            return ['mode' => $mode, 'skin' => $skin, 'flows' => []];
        }

        // Per-event cross product; aggregate by (src, dst) pair.
        $pairCounts = [];
        foreach ($victims as $eventId => $vIsos) {
            if (empty($attackers[$eventId])) {
                continue;
            }
            foreach ($attackers[$eventId] as $srcIso) {
                foreach ($vIsos as $dstIso) {
                    if ($srcIso === $dstIso) {
                        // Self-loop — actor and victim same country.
                        // Not visually useful on a pew-pew map.
                        continue;
                    }
                    $key = $srcIso . '|' . $dstIso;
                    $pairCounts[$key] = (isset($pairCounts[$key]) ? $pairCounts[$key] : 0) + 1;
                }
            }
        }
        if (empty($pairCounts)) {
            return ['mode' => $mode, 'skin' => $skin, 'flows' => []];
        }

        // value-desc, cap at max_arcs.
        arsort($pairCounts);
        if (count($pairCounts) > $maxArcs) {
            $pairCounts = array_slice($pairCounts, 0, $maxArcs, true);
        }

        $centroids = $this->loadCentroids();
        $flows = [];
        foreach ($pairCounts as $key => $value) {
            list($srcIso, $dstIso) = explode('|', $key, 2);
            if (!isset($centroids[$srcIso]) || !isset($centroids[$dstIso])) {
                continue;
            }
            $flows[] = [
                'src' => $centroids[$srcIso],
                'dst' => $centroids[$dstIso],
                'value' => $value,
                'src_iso' => $srcIso,
                'dst_iso' => $dstIso,
            ];
        }

        return [
            'mode' => $mode,
            'skin' => $skin,
            'flows' => $flows,
        ];
    }

    private function resolveMode($options)
    {
        $mode = isset($options['mode']) ? (string)$options['mode'] : '2d';
        // Whitelist must track the $schema 'mode' enum (DD-47 added
        // 'webgl-globe') — an unlisted stored value silently degrades
        // to '2d'.
        return in_array($mode, ['2d', '3d-globe', 'webgl-globe'], true) ? $mode : '2d';
    }

    /**
     * Resolve the WebGL globe skin (DD-49). Only meaningful in the
     * `webgl-globe` mode — the 2d/3d-globe ECharts modes draw a
     * flat-shaded political map with no surface texture and ignore it.
     * Whitelist must track the $schema 'skin' enum; an unlisted value
     * degrades to 'night' (the default attack-globe look).
     */
    private function resolveSkin($options)
    {
        $skin = isset($options['skin']) ? (string)$options['skin'] : 'night';
        return in_array($skin, ['night', 'day', 'dark', 'char'], true) ? $skin : 'night';
    }

    /**
     * Resolve the recency lower bound (unix ts), or null for all
     * time. Mirrors AttributeGeoMapWidget::resolveSince — the
     * CanonicalTypeAdapter translates the P30D schema default /
     * toolbar value into the "30d" day form before we get here.
     */
    private function resolveSince($options)
    {
        $raw = isset($options['time_window']) && $options['time_window'] !== '' ? $options['time_window'] : '30d';
        if (is_string($raw) && substr($raw, -1) === 'd') {
            $window = ((int)substr($raw, 0, -1)) * 24 * 60 * 60;
        } else {
            $window = (int)$raw;
        }
        if ($window === -1) {
            return null;
        }
        if ($window <= 0) {
            $window = 30 * 24 * 60 * 60;
        }
        return time() - $window;
    }

    /**
     * Load `iso-centroids.json` once per request. Failure to load
     * (missing file, garbled JSON) returns an empty map and the
     * widget gracefully degrades to no flows — operator can see
     * the empty state in the UI and check the vendor file.
     */
    private function loadCentroids()
    {
        if ($this->centroidCache !== null) {
            return $this->centroidCache;
        }
        $path = WWW_ROOT . self::ISO_CENTROIDS_FILE;
        $raw = @file_get_contents($path);
        if ($raw === false) {
            $this->centroidCache = [];
            return $this->centroidCache;
        }
        $decoded = json_decode($raw, true);
        $this->centroidCache = is_array($decoded) ? $decoded : [];
        return $this->centroidCache;
    }

    /**
     * Returns `{event_id => [ISO, ISO, ...]}` for events tagged
     * with a `misp-galaxy:<$galaxyType>=...` cluster whose cluster
     * carries an `<$elementKey>` galaxy element with a 2-letter
     * ISO alpha-2 value.
     *
     * If `$eventIdFilter` is non-null it restricts the join to
     * that event id set (used to skip the expensive scan of
     * threat-actor tags on events that don't carry a country
     * galaxy anyway).
     *
     * Mirrors AttributeGeoMapWidget::eventGalaxyCounts but
     * preserves the per-event grouping (the geo widget aggregates
     * straight to per-ISO counts; we need (event, iso) pairs to
     * cross-product within each event).
     */
    private function collectIsoByEvent($galaxyType, $elementKey, $since, $eventIdFilter)
    {
        if ($eventIdFilter !== null && empty($eventIdFilter)) {
            return [];
        }
        $eventTag = ClassRegistry::init('EventTag');
        $eventConditions = ['Event.id = EventTag.event_id'];
        if ($since !== null) {
            $eventConditions['Event.timestamp >='] = $since;
        }
        $rowConditions = [];
        if ($eventIdFilter !== null) {
            $rowConditions['EventTag.event_id IN'] = array_values($eventIdFilter);
        }
        $rows = $eventTag->find('all', [
            'fields' => ['EventTag.event_id', 'GalaxyElement.value'],
            'recursive' => -1,
            'conditions' => $rowConditions,
            'joins' => [
                [
                    'table' => 'events',
                    'alias' => 'Event',
                    'type' => 'inner',
                    'conditions' => $eventConditions,
                ],
                [
                    'table' => 'tags',
                    'alias' => 'Tag',
                    'type' => 'inner',
                    'conditions' => ['Tag.id = EventTag.tag_id'],
                ],
                [
                    'table' => 'galaxy_clusters',
                    'alias' => 'GalaxyCluster',
                    'type' => 'inner',
                    'conditions' => ['GalaxyCluster.tag_name = Tag.name'],
                ],
                [
                    'table' => 'galaxies',
                    'alias' => 'Galaxy',
                    'type' => 'inner',
                    'conditions' => [
                        'Galaxy.id = GalaxyCluster.galaxy_id',
                        'Galaxy.type' => $galaxyType,
                    ],
                ],
                [
                    'table' => 'galaxy_elements',
                    'alias' => 'GalaxyElement',
                    'type' => 'inner',
                    'conditions' => [
                        'GalaxyElement.galaxy_cluster_id = GalaxyCluster.id',
                        'GalaxyElement.key' => $elementKey,
                    ],
                ],
            ],
        ]);
        $out = [];
        foreach ($rows as $r) {
            $eid = isset($r['EventTag']['event_id']) ? (int)$r['EventTag']['event_id'] : 0;
            $iso = isset($r['GalaxyElement']['value']) ? strtoupper(trim((string)$r['GalaxyElement']['value'])) : '';
            if ($eid <= 0 || !preg_match('/^[A-Z]{2}$/', $iso)) {
                continue;
            }
            // Dedupe ISOs within an event — multiple tag rows pointing
            // at the same cluster shouldn't double-count.
            $out[$eid][$iso] = true;
        }
        foreach ($out as $eid => $isoMap) {
            $out[$eid] = array_keys($isoMap);
        }
        return $out;
    }
}
