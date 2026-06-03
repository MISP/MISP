<?php

App::uses('RedisTool', 'Tools');

/**
 * NewDataStatsWidget — the analyst dashboard's "what's new" pulse
 * (AD-W7 / AD-05..07; reworked AD-21). A standalone StatGrid widget (no
 * dependency on the Trending engine, no new render kind): nine KPI cards,
 * each showing the metric's count in the current time window and a ▲/▼ delta
 * vs the immediately-preceding equal-length window (the AD-03 prior-window
 * baseline, shared with the Trending engine). Opts into StatGrid's glyph +
 * label header (AD-21 `$statGridLabels`) so each card is self-labelled.
 *
 * The original four metrics (AD-07):
 *   1. New events       — COUNT(Event) with Event.timestamp in window.
 *                         GLOBAL scale-count, no ACL filter (AD-06).
 *   2. New attributes   — COUNT(Attribute) with Attribute.timestamp in
 *                         window and deleted = 0. GLOBAL, no ACL (AD-06).
 *   3. Targeting my org — distinct events in window carrying
 *                         misp-galaxy:country="<c>" ∪ sector="<s>", with
 *                         <c>/<s> resolved by the targeting waterfall
 *                         (config → org meta → org-name ccTLD → N/A).
 *                         Org-CONTEXTUAL, not ACL-scoped — shows N/A (not
 *                         0) when neither country nor sector resolves.
 *   4. Published by my org — Event.orgc_id = my org AND published = 1 AND
 *                         publish_timestamp in window. publish_timestamp is
 *                         OK *here only*: for an org's OWN events it is a
 *                         genuine local publish act, not a sync import, so
 *                         the AD-05 objection to publish_timestamp does not
 *                         apply (AD-05 exception).
 *
 * The AD-21 rework adds five more GLOBAL scale-counts (AD-06), windowed +
 * delta like the above: new objects (Object.timestamp), event reports
 * (EventReport.timestamp), LOCAL galaxy clusters (GalaxyCluster.version,
 * default=0 — shipped clusters carry batch import dates), and analyst notes &
 * opinions (Note/Opinion.modified, a UTC datetime, not an epoch).
 *
 * Window anchor (AD-05): Event.timestamp for metrics 1/3, Attribute.timestamp
 * for metric 2, publish_timestamp for metric 4. The window is driven by the
 * `time_window` canonical (AD-12 — the dashboard toolbar drives the whole
 * board); default P7D.
 *
 * Cache (AD-06): the four metrics have THREE different natural cache scopes,
 * which a single WidgetCache `cache_scope` cannot express — and the `org`
 * scope's site-admin `sa:` no-ACL bucket is *wrong* here (these counts are
 * not ACL-scoped; metrics 3/4 are org-contextual, so two site admins from
 * different orgs must not share them). So instead of opting into the
 * whole-payload WidgetCache, each metric is cached in Redis under its own
 * key inside handler(): metrics 1-2 GLOBAL (one compute per instance, shared
 * across every org), metric 3 keyed by (country, sector), metric 4 keyed by
 * orgc_id. Keys carry the window LENGTH (not the drifting absolute `now`), so
 * a hit within the TTL serves a window anchored up to TTL seconds stale —
 * the same modest-freshness posture as every other cached dashboard widget
 * (DD-19). ~5 min TTL (counts are cheap).
 */
class NewDataStatsWidget
{
    public $title = 'New data';
    public $category = 'events';
    public $render = 'StatGrid';
    public $width = 4;
    public $height = 6;

    // AD-21: opt into StatGrid's glyph+label header (vs the glyph-only
    // DD-32 default) so each of the 9 KPI cards is self-labelled, not a
    // bare glyph. StatGrid reads this flag; no other consumer is affected.
    public $statGridLabels = true;

    public $params = array(
        'time_window' => 'The time window, going back in seconds, to include '
            . '(e.g. "30d"; -1 = all historic data). Drives both the '
            . 'current-window count and the prior-window delta.',
        'country' => 'Optional: explicitly set the country for the "targeting '
            . 'my org" metric (overrides the org-meta / org-name heuristics). '
            . 'A country galaxy value (e.g. "luxembourg"), ISO code or ccTLD.',
        'sector' => 'Optional: explicitly set the sector for the "targeting my '
            . 'org" metric (overrides the org-meta heuristic). A sector galaxy '
            . 'value (e.g. "Bank").',
    );

    public $schema = array(
        'time_window' => array(
            'type' => 'time_window',
            'default' => 'P7D',
            'help' => 'Time window over which to count new data (last N '
                . 'days/hours, or all time). Driven by the dashboard toolbar.',
        ),
        // B9: `country` / `sector` promoted from `$params`-only knobs to typed
        // `string` scalars so the configure form renders labelled text inputs
        // instead of advanced JSON keys. `string` is a WidgetSchema scalar
        // type; the configure form's readback posts the text verbatim and the
        // handler reads it via `!empty($options[...])` (an empty string ⇒ the
        // override is skipped and the org-meta / ccTLD waterfall engages). The
        // `default=>''` flows through CanonicalTypeAdapter untouched (no scalar
        // switch case) and preserves that no-override behaviour. Pure additive
        // `$schema` edit — no platform/JS change. The `$params` text below
        // stays as the field help.
        'country' => array(
            'type' => 'string',
            'default' => '',
            'help' => 'Optional: explicit country for the "targeting my org" '
                . 'metric (overrides the org-meta / org-name heuristics). A '
                . 'country galaxy value (e.g. "luxembourg"), ISO code or ccTLD. '
                . 'Leave blank to auto-detect.',
        ),
        'sector' => array(
            'type' => 'string',
            'default' => '',
            'help' => 'Optional: explicit sector for the "targeting my org" '
                . 'metric (overrides the org-meta heuristic). A sector galaxy '
                . 'value (e.g. "Bank"). Leave blank to auto-detect.',
        ),
    );

    public $placeholder =
'{
    "time_window": "7d",
    "country": "luxembourg",
    "sector": "Bank"
}';

    public $description = 'New-data pulse: windowed counts (each with a ▲/▼ '
        . 'delta vs the previous equal-length window) of new events, '
        . 'attributes, objects, event reports, local galaxy clusters, analyst '
        . 'notes & opinions, plus events targeting my org\'s country/sector and '
        . 'events my org published.';

    // No whole-payload WidgetCache (see the class docblock): the metrics span
    // three cache scopes and the `org` scope's site-admin bucket is wrong for
    // these non-ACL counts. Caching is per-metric, inside handler().
    public $cacheLifetime = false;
    public $autoRefreshDelay = false;

    /** Per-metric Redis cache (AD-06). */
    const CACHE_PREFIX = 'misp:dashboard:new_data_stats';
    const CACHE_TTL = 300; // ~5 min — counts are cheap (AD-07).

    /** Self-contained country/sector resolution sources (AD-07). */
    const COUNTRY_FILE = APP . 'files' . DS . 'misp-galaxy' . DS . 'clusters' . DS . 'country.json';
    const SECTOR_FILE = APP . 'files' . DS . 'misp-galaxy' . DS . 'clusters' . DS . 'sector.json';

    /** @var Redis|null best-effort cache handle (null degrades to live). */
    private $redis = null;

    public function handler($user, $options = array())
    {
        $this->redis = $this->initRedis();

        $windowSeconds = $this->parseWindow($options);
        $now = time();
        // Current window [now - w, now]; prior equal window [now - 2w, now - w]
        // (AD-03 baseline). Non-overlapping: current uses `>=`, prior uses `<`
        // the shared boundary. All-time (-1) has no upper bound, no prior
        // window and therefore no delta.
        $hasPrior = ($windowSeconds !== -1);
        if ($hasPrior) {
            $curBounds = array($now - $windowSeconds, null);
            $priorBounds = array($now - (2 * $windowSeconds), $now - $windowSeconds);
        } else {
            $curBounds = array(null, null);
            $priorBounds = array(null, null);
        }

        $eventModel = ClassRegistry::init('Event');
        $attributeModel = ClassRegistry::init('MispAttribute');
        $objectModel = ClassRegistry::init('MispObject');
        $reportModel = ClassRegistry::init('EventReport');
        $clusterModel = ClassRegistry::init('GalaxyCluster');
        $noteModel = ClassRegistry::init('Note');
        $opinionModel = ClassRegistry::init('Opinion');

        $rows = array();

        // --- Metric 1: new events (global; Event.timestamp) -----------------
        $rows[] = $this->deltaRow(
            __('Events'),
            'calendar',
            'events:' . $windowSeconds,
            $hasPrior,
            $curBounds,
            $priorBounds,
            function ($start, $end) use ($eventModel) {
                return $eventModel->find('count', array(
                    'recursive' => -1,
                    'conditions' => $this->timeConditions('Event.timestamp', $start, $end),
                ));
            },
            $this->indexDrilldown('/events/index', $windowSeconds, 'searchtimestamp')
        );

        // --- Metric 2: new attributes (global; Attribute.timestamp) ---------
        $rows[] = $this->deltaRow(
            __('Attributes'),
            'tag',
            'attributes:' . $windowSeconds,
            $hasPrior,
            $curBounds,
            $priorBounds,
            function ($start, $end) use ($attributeModel) {
                $conditions = $this->timeConditions('Attribute.timestamp', $start, $end);
                $conditions['Attribute.deleted'] = 0;
                return $attributeModel->find('count', array(
                    'recursive' => -1,
                    'conditions' => $conditions,
                ));
            },
            '/attributes/index'
        );

        // --- Metric 3: new objects (global; Object.timestamp) ---------------
        $rows[] = $this->deltaRow(
            __('Objects'),
            'layers',
            'objects:' . $windowSeconds,
            $hasPrior,
            $curBounds,
            $priorBounds,
            function ($start, $end) use ($objectModel) {
                $conditions = $this->timeConditions('Object.timestamp', $start, $end);
                $conditions['Object.deleted'] = 0;
                return $objectModel->find('count', array('recursive' => -1, 'conditions' => $conditions));
            }
        );

        // --- Metric 4: new event reports (global; EventReport.timestamp) ----
        $rows[] = $this->deltaRow(
            __('Event reports'),
            'pencil',
            'reports:' . $windowSeconds,
            $hasPrior,
            $curBounds,
            $priorBounds,
            function ($start, $end) use ($reportModel) {
                $conditions = $this->timeConditions('EventReport.timestamp', $start, $end);
                $conditions['EventReport.deleted'] = 0;
                return $reportModel->find('count', array('recursive' => -1, 'conditions' => $conditions));
            }
        );

        // --- Metric 5: new LOCAL galaxy clusters (global) -------------------
        // GalaxyCluster.version is the only timestamp (set on create AND edit).
        // default=0 (local) only — like W12: shipped (default=1) clusters carry
        // batch import dates and would flood the count on every sync.
        $rows[] = $this->deltaRow(
            __('Galaxy clusters'),
            'sitemap',
            'clusters:' . $windowSeconds,
            $hasPrior,
            $curBounds,
            $priorBounds,
            function ($start, $end) use ($clusterModel) {
                $conditions = $this->timeConditions('GalaxyCluster.version', $start, $end);
                $conditions['GalaxyCluster.default'] = 0;
                $conditions['GalaxyCluster.deleted'] = 0;
                return $clusterModel->find('count', array('recursive' => -1, 'conditions' => $conditions));
            }
        );

        // --- Metric 6: new analyst notes (global; Note.modified) ------------
        // modified is a UTC datetime (not an epoch) and the table has no
        // `deleted` column — use the datetime window helper, no delete filter.
        $rows[] = $this->deltaRow(
            __('Notes'),
            'chat',
            'notes:' . $windowSeconds,
            $hasPrior,
            $curBounds,
            $priorBounds,
            function ($start, $end) use ($noteModel) {
                return $noteModel->find('count', array(
                    'recursive' => -1,
                    'conditions' => $this->timeConditionsDatetime('Note.modified', $start, $end),
                ));
            }
        );

        // --- Metric 7: new analyst opinions (global; Opinion.modified) ------
        $rows[] = $this->deltaRow(
            __('Opinions'),
            'chat-lines',
            'opinions:' . $windowSeconds,
            $hasPrior,
            $curBounds,
            $priorBounds,
            function ($start, $end) use ($opinionModel) {
                return $opinionModel->find('count', array(
                    'recursive' => -1,
                    'conditions' => $this->timeConditionsDatetime('Opinion.modified', $start, $end),
                ));
            }
        );

        // --- Metric 8: events targeting my org (org-contextual) -------------
        $rows[] = $this->targetingMetric($user, $options, $windowSeconds, $hasPrior, $curBounds, $priorBounds, $eventModel);

        // --- Metric 9: events published by my org ---------------------------
        $myOrgId = isset($user['org_id']) ? (int)$user['org_id'] : 0;
        $publishedDrilldown = $myOrgId
            ? $this->indexDrilldown(
                '/events/index/searchpublished:1/searchorg:' . $myOrgId,
                $windowSeconds,
                'searchpublishtimestamp'
            )
            : null;
        $rows[] = $this->deltaRow(
            __('Published by my org'),
            'building',
            'published:' . $windowSeconds . ':o' . $myOrgId,
            $hasPrior,
            $curBounds,
            $priorBounds,
            function ($start, $end) use ($eventModel, $myOrgId) {
                if (!$myOrgId) {
                    return 0;
                }
                $conditions = $this->timeConditions('Event.publish_timestamp', $start, $end);
                $conditions['Event.orgc_id'] = $myOrgId;
                $conditions['Event.published'] = 1;
                return $eventModel->find('count', array(
                    'recursive' => -1,
                    'conditions' => $conditions,
                ));
            },
            $publishedDrilldown
        );

        return $rows;
    }

    // ---- metric 3 (targeting waterfall) -----------------------------------

    /**
     * Build the "events targeting my org" StatGrid row. Resolves the org's
     * country and sector via the AD-07 waterfall, then counts distinct events
     * carrying misp-galaxy:country="<c>" ∪ sector="<s>". N/A (not 0) when
     * neither resolves; a resolved-but-untagged context is a genuine 0.
     */
    private function targetingMetric($user, $options, $windowSeconds, $hasPrior, $curBounds, $priorBounds, $eventModel)
    {
        $org = $this->myOrg($user);
        $country = $this->resolveCountry($options, $org);
        $sector = $this->resolveSector($options, $org);
        $title = __('Targeting my org');

        // Neither axis resolved → the metric is not applicable (AD-07).
        if ($country === null && $sector === null) {
            return array('title' => $title, 'icon' => 'shield', 'value' => __('N/A'));
        }

        $tagIds = $this->targetingTagIds($country, $sector);
        // Key by the resolved (country, sector) context + window (AD-06).
        $contextKey = 'targeting:' . $windowSeconds . ':'
            . substr(hash('sha256', (string)$country . '|' . (string)$sector), 0, 16);
        $count = function ($start, $end) use ($tagIds, $eventModel) {
            if (empty($tagIds)) {
                return 0; // context resolved but no such tag exists yet
            }
            return $this->distinctEventsWithTags($eventModel, $tagIds, $start, $end);
        };

        // Drill-down to a representative tag (country preferred); both axes
        // can't be OR-expressed in one index URL, so link the primary one.
        $drilldown = !empty($tagIds)
            ? $this->indexDrilldown('/events/index/searchtag:' . (int)$tagIds[0], $windowSeconds, 'searchtimestamp')
            : null;

        return $this->deltaRow($title, 'shield', $contextKey, $hasPrior, $curBounds, $priorBounds, $count, $drilldown);
    }

    /**
     * COUNT(DISTINCT Event.id) over events carrying any of $tagIds at the
     * event level (EventTag), window-bounded by Event.timestamp (AD-05).
     * A narrow indexed join — no event hydration; an event tagged with both
     * the country and sector tag counts once (AD-02 distinct-event posture).
     */
    private function distinctEventsWithTags($eventModel, array $tagIds, $start, $end)
    {
        $conditions = $this->timeConditions('Event.timestamp', $start, $end);
        $eventModel->virtualFields['nds_count'] = 0;
        $row = $eventModel->find('first', array(
            'recursive' => -1,
            'joins' => array(array(
                'table' => 'event_tags',
                'alias' => 'EventTag',
                'type' => 'INNER',
                'conditions' => array(
                    'EventTag.event_id = Event.id',
                    'EventTag.tag_id' => $tagIds,
                ),
            )),
            'conditions' => $conditions,
            'fields' => array('COUNT(DISTINCT Event.id) as Event__nds_count'),
        ));
        unset($eventModel->virtualFields['nds_count']);
        return isset($row['Event']['nds_count']) ? (int)$row['Event']['nds_count'] : 0;
    }

    /**
     * Resolve the misp-galaxy:country / :sector tag ids for the resolved
     * context. Either axis may be null; returns the existing tag ids (may be
     * empty if the galaxy/tag was never used on this instance).
     */
    private function targetingTagIds($country, $sector)
    {
        $names = array();
        if ($country !== null) {
            $names[] = 'misp-galaxy:country="' . $country . '"';
        }
        if ($sector !== null) {
            $names[] = 'misp-galaxy:sector="' . $sector . '"';
        }
        if (empty($names)) {
            return array();
        }
        $tagModel = ClassRegistry::init('Tag');
        $ids = $tagModel->find('column', array(
            'recursive' => -1,
            'conditions' => array('Tag.name' => $names),
            'fields' => array('Tag.id'),
        ));
        return array_values(array_map('intval', $ids));
    }

    // ---- targeting waterfall: country / sector resolution (AD-07) ---------

    /**
     * Country waterfall: explicit config → org.nationality → org-name ccTLD
     * → null. Returns the country galaxy cluster `value` (e.g. "luxembourg")
     * used in the misp-galaxy:country="…" tag, or null.
     */
    private function resolveCountry($options, $org)
    {
        $map = $this->countryMaps();
        if (!empty($options['country'])) {
            $hit = $this->matchCountry((string)$options['country'], $map);
            // An explicit override wins even if it isn't a known cluster value
            // (a community may set an exact custom value).
            return $hit !== null ? $hit : (string)$options['country'];
        }
        $nationality = isset($org['Organisation']['nationality']) ? trim((string)$org['Organisation']['nationality']) : '';
        if ($nationality !== '') {
            $hit = $this->matchCountry($nationality, $map);
            if ($hit !== null) {
                return $hit;
            }
        }
        $name = isset($org['Organisation']['name']) ? (string)$org['Organisation']['name'] : '';
        if ($name !== '') {
            $hit = $this->ccTldCountry($name, $map);
            if ($hit !== null) {
                return $hit;
            }
        }
        return null;
    }

    /**
     * Sector waterfall: explicit config → org.sector → null. No TLD path (a
     * TLD yields a country, never a sector). Returns the sector galaxy cluster
     * `value` (e.g. "Bank"), or null.
     */
    private function resolveSector($options, $org)
    {
        $map = $this->sectorMap();
        if (!empty($options['sector'])) {
            $hit = isset($map[strtolower(trim((string)$options['sector']))])
                ? $map[strtolower(trim((string)$options['sector']))]
                : null;
            return $hit !== null ? $hit : (string)$options['sector'];
        }
        $sector = isset($org['Organisation']['sector']) ? strtolower(trim((string)$org['Organisation']['sector'])) : '';
        if ($sector !== '' && isset($map[$sector])) {
            return $map[$sector];
        }
        return null;
    }

    /**
     * Match a raw country string (name / ISO2 / ISO3) to a country galaxy
     * cluster value. Case-insensitive. Returns the cluster value or null.
     */
    private function matchCountry($raw, array $map)
    {
        $lc = strtolower(trim($raw));
        if ($lc === '' || $lc === 'not specified') {
            return null;
        }
        if (isset($map['byValue'][$lc])) {
            return $map['byValue'][$lc];
        }
        $uc = strtoupper(trim($raw));
        if (isset($map['byIso'][$uc])) {
            return $map['byIso'][$uc];
        }
        if (isset($map['byIso3'][$uc])) {
            return $map['byIso3'][$uc];
        }
        return null;
    }

    /**
     * Resolve an org name's ccTLD suffix (e.g. "post.lu" → ".lu") to a country
     * cluster value via the country galaxy's tld map. Only a 2-letter ccTLD
     * after a dot is honoured (gTLDs like .com map to nothing).
     */
    private function ccTldCountry($name, array $map)
    {
        $name = strtolower(trim($name));
        $pos = strrpos($name, '.');
        if ($pos === false) {
            return null;
        }
        $tld = substr($name, $pos); // includes the leading dot, e.g. ".lu"
        if (strlen($tld) !== 3) {
            return null; // ccTLDs only (".xx")
        }
        return isset($map['byTld'][$tld]) ? $map['byTld'][$tld] : null;
    }

    /**
     * Build + memoise the country lookup maps from country.json (AD-07,
     * self-contained — no DB / galaxy-import dependency for the mapping):
     *   byValue ["andorra" => "andorra"], byIso ["AD" => "andorra"],
     *   byIso3 ["AND" => "andorra"], byTld [".ad" => "andorra"].
     */
    private function countryMaps()
    {
        static $maps = null;
        if ($maps !== null) {
            return $maps;
        }
        $maps = array('byValue' => array(), 'byIso' => array(), 'byIso3' => array(), 'byTld' => array());
        foreach ($this->loadClusterValues(self::COUNTRY_FILE) as $cluster) {
            if (empty($cluster['value'])) {
                continue;
            }
            $value = (string)$cluster['value'];
            $maps['byValue'][strtolower($value)] = $value;
            $meta = isset($cluster['meta']) && is_array($cluster['meta']) ? $cluster['meta'] : array();
            if (!empty($meta['ISO'])) {
                $maps['byIso'][strtoupper((string)$meta['ISO'])] = $value;
            }
            if (!empty($meta['ISO3'])) {
                $maps['byIso3'][strtoupper((string)$meta['ISO3'])] = $value;
            }
            if (!empty($meta['tld'])) {
                $maps['byTld'][strtolower((string)$meta['tld'])] = $value;
            }
        }
        return $maps;
    }

    /**
     * Build + memoise the sector lookup map [lc value => value] from
     * sector.json.
     */
    private function sectorMap()
    {
        static $map = null;
        if ($map !== null) {
            return $map;
        }
        $map = array();
        foreach ($this->loadClusterValues(self::SECTOR_FILE) as $cluster) {
            if (empty($cluster['value'])) {
                continue;
            }
            $value = (string)$cluster['value'];
            $map[strtolower($value)] = $value;
        }
        return $map;
    }

    /**
     * Read a misp-galaxy cluster file's `values` array, or [] on any error
     * (missing file / bad JSON) so resolution degrades to the next waterfall
     * tier rather than throwing.
     */
    private function loadClusterValues($file)
    {
        if (!is_file($file) || !is_readable($file)) {
            return array();
        }
        $decoded = json_decode((string)file_get_contents($file), true);
        return (is_array($decoded) && !empty($decoded['values']) && is_array($decoded['values']))
            ? $decoded['values']
            : array();
    }

    /**
     * Fetch the requesting user's own organisation meta (name / nationality /
     * sector) — queried directly (the session $user['Organisation'] doesn't
     * reliably carry nationality/sector). Empty array when no org.
     */
    private function myOrg($user)
    {
        if (empty($user['org_id'])) {
            return array();
        }
        $orgModel = ClassRegistry::init('Organisation');
        $org = $orgModel->find('first', array(
            'recursive' => -1,
            'conditions' => array('Organisation.id' => (int)$user['org_id']),
            'fields' => array('Organisation.id', 'Organisation.name', 'Organisation.nationality', 'Organisation.sector'),
        ));
        return is_array($org) ? $org : array();
    }

    // ---- shared helpers ----------------------------------------------------

    /**
     * Assemble one StatGrid row: the current-window count as `value`, and —
     * when a prior window exists — the (current − prior) delta as `change`
     * (StatGrid renders >0 as ▲, <0 as ▼, 0 as no badge). Each window count
     * is cached per metric (AD-06) under CACHE_PREFIX:<base>:cur|prior.
     */
    private function deltaRow($title, $icon, $cacheBase, $hasPrior, array $curBounds, array $priorBounds, callable $count, $drilldown = null)
    {
        $current = $this->cachedCount($cacheBase . ':cur', function () use ($count, $curBounds) {
            return $count($curBounds[0], $curBounds[1]);
        });
        $row = array('title' => $title, 'icon' => $icon, 'value' => $current);
        if ($hasPrior) {
            $prior = $this->cachedCount($cacheBase . ':prior', function () use ($count, $priorBounds) {
                return $count($priorBounds[0], $priorBounds[1]);
            });
            $row['change'] = $current - $prior;
        }
        if ($drilldown !== null) {
            $row['drilldown'] = $drilldown;
        }
        return $row;
    }

    /**
     * Get-or-compute an integer count, cached in Redis for CACHE_TTL under
     * CACHE_PREFIX:<key>. Degrades to a live compute when Redis is absent or
     * unreadable — caching never breaks a render.
     */
    private function cachedCount($key, callable $compute)
    {
        $fullKey = self::CACHE_PREFIX . ':' . $key;
        if ($this->redis !== null) {
            try {
                $hit = $this->redis->get($fullKey);
                if ($hit !== false && $hit !== null && is_numeric($hit)) {
                    return (int)$hit;
                }
            } catch (Exception $e) {
                // unreadable — fall through to live compute
            }
        }
        $value = (int)$compute();
        if ($this->redis !== null) {
            try {
                $this->redis->setex($fullKey, self::CACHE_TTL, $value);
            } catch (Exception $e) {
                // best-effort: a write failure must not break the render
            }
        }
        return $value;
    }

    /**
     * Build a `<field> >= $start AND <field> < $end` condition set (unix
     * seconds; either bound null = unbounded), matching the TrendingWidget
     * window convention (start inclusive, end exclusive).
     */
    private function timeConditions($field, $start, $end)
    {
        $conditions = array();
        if ($start !== null) {
            $conditions[$field . ' >='] = $start;
        }
        if ($end !== null) {
            $conditions[$field . ' <'] = $end;
        }
        return $conditions;
    }

    /**
     * Like timeConditions, but for a UTC DATETIME column (analyst-data
     * `modified`) rather than an epoch int — converts the unix-second bounds
     * to 'Y-m-d H:i:s' UTC strings via gmdate (the AnalystData modified field
     * is stored UTC; same convention as the W11 feed widget).
     */
    private function timeConditionsDatetime($field, $start, $end)
    {
        $conditions = array();
        if ($start !== null) {
            $conditions[$field . ' >='] = gmdate('Y-m-d H:i:s', $start);
        }
        if ($end !== null) {
            $conditions[$field . ' <'] = gmdate('Y-m-d H:i:s', $end);
        }
        return $conditions;
    }

    /**
     * Append a relative `<param>:<N>d` window filter to a relative index URL
     * for a finite window; all-time (-1) links to the bare index. The events
     * index resolves the "<N>d" delta via Event::resolveTimeDelta. Stays
     * relative so DashboardURLValidator (DD-03) accepts it.
     */
    private function indexDrilldown($base, $windowSeconds, $param)
    {
        if ($windowSeconds === -1) {
            return $base;
        }
        $days = max(1, (int)round($windowSeconds / 86400));
        return $base . '/' . $param . ':' . $days . 'd';
    }

    /**
     * Resolve the time window (seconds back from now) from config. Mirrors
     * TrendingWidget::parseWindow exactly: "<N>d" → N*86400; "-1" → -1
     * (all history); other → int seconds; empty → 7 days. The
     * CanonicalTypeAdapter has already translated P7D → "7d" upstream.
     */
    private function parseWindow($options)
    {
        $tw = isset($options['time_window']) ? $options['time_window'] : null;
        if (is_string($tw) && substr($tw, -1) === 'd') {
            return ((int)substr($tw, 0, -1)) * 24 * 60 * 60;
        }
        if ($tw === -1 || $tw === '-1') {
            return -1;
        }
        return empty($tw) ? (7 * 24 * 60 * 60) : (int)$tw;
    }

    /**
     * Best-effort Redis handle (prefix-free via RedisTool::init). Returns
     * null when Redis is unavailable so every metric degrades to live.
     */
    private function initRedis()
    {
        try {
            return RedisTool::init();
        } catch (Exception $e) {
            return null;
        }
    }
}
