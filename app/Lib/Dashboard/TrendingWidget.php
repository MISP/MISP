<?php

App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');

/**
 * TrendingWidget — the analyst dashboard's parametrised "what is rising"
 * engine (AD-W1 / AD-01..04). ONE widget, many dimensions: a `dimension`
 * config selects what to trend (vulnerabilities today; threat actors and
 * ATT&CK techniques added by later build phases). Each dimension supplies
 * its own per-dimension hooks — counting strategy, label resolver and
 * drill-down link builder — so a new dimension is a purely additive entry
 * in dimensions() plus its hook methods, never a new class.
 *
 * Renders via the `Trending` render kind (ranked-row list, Trending.ctp):
 * each row is a value, its distinct-event volume (bar + count) and — from
 * build phase B1.5 — a ▲/▼ momentum delta badge.
 *
 * Counting (AD-02): the metric is COUNT(DISTINCT event_id) — an event
 * carrying a value many times counts once, which resists per-org reporting
 * process-noise — computed off the narrow connector / attribute tables (no
 * event hydration) and constrained to the events the viewer may see
 * (ACL-correct; AD-09, unlike the global scale-counts of AD-06). Window
 * anchor is Event.timestamp / Attribute.timestamp (AD-05).
 *
 * Momentum (AD-03): each row carries a ▲/▼ badge = the floored % change of
 * its distinct-event count vs the immediately-preceding equal-length window
 * (count the current window AND the prior window via the same count hook,
 * with explicit [start, end] bounds). An eligibility floor (`min_count`)
 * suppresses the badge for low-volume rows so a 1→4 spike doesn't read as
 * "+300%". A value present now but absent in the prior window is flagged
 * "NEW". All-time (time_window = -1) has no prior window → no momentum. No
 * spike detection (deferred — AD-03).
 *
 * Cache (AD-04): lazy-loaded on render and cached PER-ORG (MISP's ACL atom)
 * for ~20 min via the WidgetCache `org` scope — same-org users share one
 * entry, site admins get a separate no-ACL bucket. Because the counts are
 * ACL-scoped (AD-09), a per-org key is both correct and shared; the source
 * is all events incl. unpublished (orgs collaborate pre-publication).
 */
class TrendingWidget
{
    public $title = 'Trending';
    public $category = 'events';
    public $render = 'Trending';
    public $width = 3;
    public $height = 4;

    public $params = array(
        'dimension' => 'Which dimension to trend. Currently: "vulnerability" '
            . '(CVE / GCVE / GHSA attribute identifiers), "threat-actor" '
            . '(misp-galaxy threat-actor clusters) and "mitre-attack-pattern" '
            . '(Enterprise ATT&CK techniques, sub-techniques rolled up to their '
            . 'parent) — the galaxy dimensions count distinct events carrying '
            . 'the cluster tag at event or attribute level. Default: '
            . 'vulnerability.',
        'time_window' => 'The time window, going back in seconds, to include '
            . '(e.g. "30d"; -1 = all historic data).',
        'threshold' => 'Limits the number of displayed rows. Default: 10.',
        'min_count' => 'Minimum current-window distinct-event count before a '
            . 'row may carry a rising/▲▼ momentum badge (kills small-N % '
            . 'noise). Default: 3.',
    );

    public $schema = array(
        // B9: promoted from a `$params`-only knob to a typed `enum` so the
        // configure form renders a native <select> (honouring `enum_labels`)
        // instead of an advanced JSON key. `enum` is a WidgetSchema scalar
        // type; CanonicalTypeAdapter injects this `default` when the key is
        // absent and passes the chosen value through unchanged. Pure additive
        // `$schema` edit — no platform/JS change. The option list MUST stay in
        // sync with the dimensions() registry below (a new dimension = a new
        // registry entry AND a new `enum`/`enum_labels` value here).
        'dimension' => array(
            'type' => 'enum',
            'enum' => array('vulnerability', 'threat-actor', 'mitre-attack-pattern'),
            'enum_labels' => array(
                'vulnerability' => 'Vulnerabilities (CVE / GCVE / GHSA)',
                'threat-actor' => 'Threat actors',
                'mitre-attack-pattern' => 'ATT&CK techniques',
            ),
            'default' => 'vulnerability',
            'help' => 'Which dimension to trend by distinct-event count.',
        ),
        'time_window' => array(
            'type' => 'time_window',
            'default' => 'P7D',
            'help' => 'Time window over which to aggregate (last N days/hours, '
                . 'or all time). Driven by the dashboard toolbar.',
        ),
        'threshold' => array(
            'type' => 'int',
            'default' => 10,
            'help' => 'Limits the number of displayed rows.',
        ),
        'min_count' => array(
            'type' => 'int',
            'default' => 3,
            'help' => 'Minimum current-window count before a row is flagged '
                . 'rising (kills small-N % noise).',
        ),
    );

    public $placeholder =
'{
    "dimension": "vulnerability",
    "time_window": "30d",
    "threshold": 15,
    "min_count": 3
}';

    public $description = 'Parametrised trending widget: ranks the values '
        . 'rising fastest in a dimension (vulnerabilities, …) by '
        . 'distinct-event count over a time window.';

    // Cache (AD-04): lazy-load on render, cache PER-ORG (the ACL atom) for
    // ~20 min — same-org users share one entry, site admins get the no-ACL
    // `sa:` bucket (WidgetCache 'org' scope, DD-20/21). Counts are
    // ACL-scoped (AD-09), so a per-org key is both correct and shared.
    public $cache_duration = 1200;
    public $cache_scope = 'org';

    /**
     * Per-dimension hook registry. Each new dimension (build phases
     * B4/B5/B6) adds one entry here plus its hook methods — purely additive.
     * Hooks:
     *   - title  : the dimension's human title (informational)
     *   - count  : method($user, $startTs, $endTs) => [valueKey => distinctEvents]
     *              ($startTs/$endTs are unix seconds or null = unbounded)
     *   - labels : method(array $valueKeys, array $options) =>
     *              [valueKey => ['label' => , 'title' => ?, 'drilldown' => ?]]
     */
    private function dimensions()
    {
        return array(
            'vulnerability' => array(
                'title' => 'Trending Vulnerabilities',
                'count' => 'countVulnerability',
                'labels' => 'labelsVulnerability',
            ),
            'threat-actor' => array(
                'title' => 'Trending Threat Actors',
                'count' => 'countThreatActor',
                'labels' => 'labelsThreatActor',
            ),
            'mitre-attack-pattern' => array(
                'title' => 'Trending Attack Techniques',
                'count' => 'countAttackPattern',
                'labels' => 'labelsAttackPattern',
            ),
        );
    }

    public function handler($user, $options = array())
    {
        $dimensions = $this->dimensions();
        $dimensionKey = (!empty($options['dimension'])
            && isset($dimensions[$options['dimension']]))
            ? $options['dimension']
            : 'vulnerability';
        $dimension = $dimensions[$dimensionKey];

        $threshold = (isset($options['threshold']) && (int)$options['threshold'] > 0)
            ? (int)$options['threshold']
            : 10;
        $minCount = (isset($options['min_count']) && (int)$options['min_count'] >= 0)
            ? (int)$options['min_count']
            : 3;
        $windowSeconds = $this->parseWindow($options);

        // The current window is [now - window, now]; the prior equal window
        // (AD-03 momentum baseline) is [now - 2*window, now - window]. The two
        // are non-overlapping (current uses `>=`, prior uses `<` the same
        // boundary). All-time (-1) has no upper bound and no prior window.
        $now = time();
        $hasMomentum = ($windowSeconds !== -1);
        if ($hasMomentum) {
            $curStart = $now - $windowSeconds;
            $curEnd = null;             // up to now
            $priorStart = $now - (2 * $windowSeconds);
            $priorEnd = $curStart;
        } else {
            $curStart = null;
            $curEnd = null;
        }

        // Current-window distinct-event counts per value (ACL-correct).
        $counts = $this->{$dimension['count']}($user, $curStart, $curEnd);
        if (empty($counts)) {
            return array();
        }

        // Volume rank: highest distinct-event count first; take the top N.
        arsort($counts);
        $counts = array_slice($counts, 0, $threshold, true);

        // Prior-window counts for the momentum delta (whole set; looked up
        // per row below). Skipped for all-time, which has no prior window.
        $priorCounts = $hasMomentum
            ? $this->{$dimension['count']}($user, $priorStart, $priorEnd)
            : array();

        // Resolve display labels / links for the top-N only (avoids
        // resolving the whole set — matters for galaxy dimensions, B5/B6).
        $labels = $this->{$dimension['labels']}(array_keys($counts), $options);

        $rows = array();
        foreach ($counts as $valueKey => $count) {
            $count = (int)$count;
            $meta = isset($labels[$valueKey]) ? $labels[$valueKey] : array();
            $row = array(
                'label' => isset($meta['label']) ? $meta['label'] : (string)$valueKey,
                'count' => $count,
            );
            // Momentum (AD-03): only flag rows that clear the eligibility
            // floor, so a tiny-volume row never reads as a big mover.
            if ($hasMomentum && $count >= $minCount) {
                $prior = isset($priorCounts[$valueKey]) ? (int)$priorCounts[$valueKey] : 0;
                if ($prior <= 0) {
                    // Present now, absent in the prior window → surging.
                    $row['badge'] = __('NEW');
                } else {
                    $deltaPct = (int)floor((($count - $prior) / $prior) * 100);
                    if ($deltaPct !== 0) {
                        $row['delta'] = $deltaPct;
                    }
                }
            }
            if (!empty($meta['title'])) {
                $row['title'] = $meta['title'];
            }
            if (!empty($meta['drilldown'])) {
                $row['drilldown'] = $meta['drilldown'];
            }
            // Optional leading glyph (galaxy dimensions resolve a Galaxy.icon
            // FA name; the value arm has none). Trending.ctp renders it via
            // the FontAwesome helper, falling back to no glyph when absent.
            if (!empty($meta['icon'])) {
                $row['icon'] = $meta['icon'];
            }
            $rows[] = $row;
        }
        return $rows;
    }

    /**
     * Resolve the time window (seconds back from now) from the config.
     * Mirrors the TrendingTags / TrendingAttributes parsing: a "<N>d" string
     * → N*86400; "-1" → -1 (all history); any other value → int seconds;
     * empty → 7 days.
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
     * ACL filter: given candidate event ids, return the subset the user may
     * see. Site-admins (createEventConditions() → []) see every candidate;
     * others are scoped by distribution / sharing-group / own-org. A narrow
     * Event-only query — no event hydration. Empty input → empty.
     */
    private function aclVisibleEventIds($user, array $candidateIds)
    {
        if (empty($candidateIds)) {
            return array();
        }
        $eventModel = ClassRegistry::init('Event');
        $conditions = $eventModel->createEventConditions($user);
        $conditions['Event.id'] = $candidateIds;
        return $eventModel->find('column', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => array('Event.id'),
        ));
    }

    // ---- dimension: vulnerability (attribute-value arm; AD-W2 / AD-09) ----

    /**
     * COUNT(DISTINCT event_id) per `vulnerability` attribute value (CVE /
     * GCVE / GHSA — one identifier-agnostic attribute type), ACL-scoped and
     * window-bounded by Attribute.timestamp (AD-05) between $startTs
     * (inclusive) and $endTs (exclusive); either bound null = unbounded.
     * Three narrow steps keep both the candidate set and the IN list bounded
     * by the window:
     *   (1) distinct events carrying an in-window vulnerability attribute,
     *   (2) ACL-filter those to the viewer's visible subset,
     *   (3) distinct-event count per value over that visible subset.
     */
    private function countVulnerability($user, $startTs, $endTs)
    {
        $attributeModel = ClassRegistry::init('MispAttribute');
        $base = array(
            'Attribute.type' => 'vulnerability',
            'Attribute.deleted' => 0,
        );
        if ($startTs !== null) {
            $base['Attribute.timestamp >='] = $startTs;
        }
        if ($endTs !== null) {
            $base['Attribute.timestamp <'] = $endTs;
        }

        // (1) candidate events: those with an in-window vulnerability attr.
        $candidateIds = $attributeModel->find('column', array(
            'recursive' => -1,
            'conditions' => $base,
            'fields' => array('Attribute.event_id'),
        ));
        $candidateIds = array_values(array_unique($candidateIds));

        // (2) ACL-filter the candidates.
        $visibleIds = $this->aclVisibleEventIds($user, $candidateIds);
        if (empty($visibleIds)) {
            return array();
        }

        // (3) distinct-event count per value over the visible subset.
        $conditions = $base;
        $conditions['Attribute.event_id'] = $visibleIds;
        $attributeModel->virtualFields['distinct_events'] = 0;
        $rows = $attributeModel->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => array(
                'Attribute.value1',
                'COUNT(DISTINCT Attribute.event_id) as Attribute__distinct_events',
            ),
            'group' => array('Attribute.value1'),
        ));
        unset($attributeModel->virtualFields['distinct_events']);

        $counts = array();
        foreach ($rows as $r) {
            $value = isset($r['Attribute']['value1']) ? $r['Attribute']['value1'] : '';
            if ($value === '' || $value === null) {
                continue;
            }
            $counts[$value] = (int)$r['Attribute']['distinct_events'];
        }
        return $counts;
    }

    /**
     * Vulnerability label hook: the identifier verbatim (CVE-… / GCVE-… /
     * GHSA-…) — these are attribute values, not galaxy clusters, so no
     * resolution is needed. Each row deep-links to the configured CVE lookup
     * (`MISP.cveurl`): the identifier is appended to the base directly, no
     * separator, mirroring `value_field.ctp:94` ({cveurl}{value}). The base
     * comes from `DashboardURLValidator::cveBaseUrl()` — the same value the
     * DD-03 gate allowlists — so the link is admitted by `Trending.ctp`'s
     * validator rather than silently dropped (analyst track AD-09; the
     * external-link survival required the B4 DD-03 relaxation, user signed
     * off 2026-06-02).
     */
    private function labelsVulnerability(array $valueKeys, array $options)
    {
        $cveUrl = DashboardURLValidator::cveBaseUrl();
        $labels = array();
        foreach ($valueKeys as $v) {
            $labels[$v] = array(
                'label' => (string)$v,
                'drilldown' => $cveUrl . (string)$v,
            );
        }
        return $labels;
    }

    // ---- dimension: threat-actor (galaxy tag arm; AD-W3 / AD-10) ----

    /**
     * The threat-actor cluster tag-id set: galaxy tags in the native
     * `misp-galaxy:threat-actor="…"` namespace (AD-10 — single galaxy, so an
     * actor is ~one cluster, sidestepping cross-galaxy identity merge). The
     * key per trended row IS the tag_id (not a cluster id), which keeps the
     * count robust to the tag_name → cluster row being non-1:1 (local forks /
     * duplicate galaxy imports — resolved to one cluster only at label time).
     *
     * @return int[]
     */
    private function threatActorTagIds()
    {
        $tagModel = ClassRegistry::init('Tag');
        return $tagModel->find('column', array(
            'recursive' => -1,
            'conditions' => array(
                'Tag.is_galaxy' => 1,
                'Tag.name LIKE' => 'misp-galaxy:threat-actor="%',
            ),
            'fields' => array('Tag.id'),
        ));
    }

    /**
     * COUNT(DISTINCT event_id) per threat-actor cluster tag (AD-W3 / AD-10) —
     * a thin wrapper over the shared tag-arm counter with the default identity
     * bucketing (one row per tag_id). See countDistinctEventsByTag() for the
     * ACL / window / union-distinct mechanism.
     */
    private function countThreatActor($user, $startTs, $endTs)
    {
        return $this->countDistinctEventsByTag(
            $user, $startTs, $endTs, $this->threatActorTagIds()
        );
    }

    /**
     * The shared ACL-correct, distinct-event count over the UNION of the two
     * tag arms (AD-02): events carrying one of $tagIds at the event level
     * (EventTag) OR on one of their attributes (AttributeTag). Used by every
     * galaxy dimension — threat actors (W3, one row per tag) and ATT&CK
     * techniques (W4, sub-techniques rolled up to a parent via $bucketMap).
     *
     * ACL-scoped (AD-09) and window-bounded per-source (AD-05): the event-tag
     * arm anchors on Event.timestamp, the attribute-tag arm on
     * Attribute.timestamp. Either $startTs (inclusive) / $endTs (exclusive)
     * bound null = unbounded.
     *
     * Why a custom count and not the in-tree `*Tag::countForTags()`:
     * `AttributeTag::countForTags()` skips ACL ("ignored for performance") and
     * counts occurrences, not distinct events — unusable here (AD-10). Instead
     * the same mechanism countVulnerability uses:
     *   (1) gather in-window (tag_id, event_id) occurrence pairs from both arms,
     *   (2) ACL-filter the union of their candidate events to the viewer's
     *       visible subset,
     *   (3) distinct-event count per BUCKET over that subset — a per-bucket
     *       event set dedupes an event reached via several tags (or tagged at
     *       BOTH levels) to one (union-distinct).
     *
     * @param array      $tagIds    the cluster tag-id set to gather over.
     * @param array|null $bucketMap tag_id => bucket key. null = identity, i.e.
     *                              bucket = tag_id (the W3 shape). W4 passes a
     *                              tag_id => parent-technique map so sub-
     *                              techniques fold into one parent row; a tag
     *                              absent from a non-null map is skipped (it has
     *                              no resolvable bucket — see attackPatternTag-
     *                              Buckets()).
     * @return array bucket key => distinct-event count
     */
    private function countDistinctEventsByTag($user, $startTs, $endTs, array $tagIds, $bucketMap = null)
    {
        if (empty($tagIds)) {
            return array();
        }

        // (1) in-window (tag_id, event_id) pairs from each arm. The narrow
        // connector tables are joined only to their anchor table to apply the
        // window (and Attribute.deleted) — no event/attribute hydration.
        $pairs = array();           // [ [tag_id, event_id], … ]
        $candidateIds = array();    // event_id => true (union over both arms)

        $eventTagModel = ClassRegistry::init('EventTag');
        $etConditions = array('EventTag.tag_id' => $tagIds);
        if ($startTs !== null) {
            $etConditions['Event.timestamp >='] = $startTs;
        }
        if ($endTs !== null) {
            $etConditions['Event.timestamp <'] = $endTs;
        }
        $etRows = $eventTagModel->find('all', array(
            'recursive' => -1,
            'fields' => array('EventTag.tag_id', 'EventTag.event_id'),
            'joins' => array(array(
                'table' => 'events',
                'alias' => 'Event',
                'type' => 'INNER',
                'conditions' => array('Event.id = EventTag.event_id'),
            )),
            'conditions' => $etConditions,
        ));
        foreach ($etRows as $r) {
            $tid = (int)$r['EventTag']['tag_id'];
            $eid = (int)$r['EventTag']['event_id'];
            $pairs[] = array($tid, $eid);
            $candidateIds[$eid] = true;
        }

        $attributeTagModel = ClassRegistry::init('AttributeTag');
        $atConditions = array(
            'AttributeTag.tag_id' => $tagIds,
            'Attribute.deleted' => 0,
        );
        if ($startTs !== null) {
            $atConditions['Attribute.timestamp >='] = $startTs;
        }
        if ($endTs !== null) {
            $atConditions['Attribute.timestamp <'] = $endTs;
        }
        $atRows = $attributeTagModel->find('all', array(
            'recursive' => -1,
            'fields' => array('AttributeTag.tag_id', 'AttributeTag.event_id'),
            'joins' => array(array(
                'table' => 'attributes',
                'alias' => 'Attribute',
                'type' => 'INNER',
                'conditions' => array('Attribute.id = AttributeTag.attribute_id'),
            )),
            'conditions' => $atConditions,
        ));
        foreach ($atRows as $r) {
            $tid = (int)$r['AttributeTag']['tag_id'];
            $eid = (int)$r['AttributeTag']['event_id'];
            $pairs[] = array($tid, $eid);
            $candidateIds[$eid] = true;
        }

        if (empty($pairs)) {
            return array();
        }

        // (2) ACL-filter the union of candidate events (AD-09; same mechanism
        // as the vulnerability arm).
        $visibleIds = $this->aclVisibleEventIds($user, array_keys($candidateIds));
        if (empty($visibleIds)) {
            return array();
        }
        $visible = array_fill_keys(array_map('intval', $visibleIds), true);

        // (3) distinct-event count per bucket over the visible subset; a
        // per-bucket event set unions every contributing tag and both arms, so
        // an event reached more than once (e.g. tagged with a technique AND its
        // sub-technique, W4) counts once. Bucket = $bucketMap[tag] when a map
        // is given (W4 parent roll-up), else the tag_id itself (W3).
        $eventsPerBucket = array();     // bucket => [event_id => true]
        foreach ($pairs as $pair) {
            list($tid, $eid) = $pair;
            if (!isset($visible[$eid])) {
                continue;
            }
            if ($bucketMap === null) {
                $bucket = $tid;
            } elseif (isset($bucketMap[$tid])) {
                $bucket = $bucketMap[$tid];
            } else {
                continue;               // tag with no resolvable bucket
            }
            $eventsPerBucket[$bucket][$eid] = true;
        }
        $counts = array();
        foreach ($eventsPerBucket as $bucket => $eventSet) {
            $counts[$bucket] = count($eventSet);
        }
        return $counts;
    }

    /**
     * Threat-actor label hook (the crux of a galaxy dimension): resolve each
     * trended tag_id to its galaxy cluster's display name + icon + synonyms,
     * and a drill-down to the in-app cluster view (AD-10). All bulk-resolved
     * (two queries total, top-N only) to avoid N+1.
     *
     * A tag_name maps to 1..N `galaxy_clusters` rows (local forks / duplicate
     * imports — 80/118 here do); pick ONE deterministically — shipped default
     * first, then newest version, then highest id — so the label and link are
     * stable. Counting is keyed by tag_id, so this pick affects only the
     * display, never the volume. Link = `/galaxy_clusters/view/<cluster_id>`
     * (relative, on-host → admitted by DD-03 with no relaxation, unlike W2's
     * external cveurl).
     */
    private function labelsThreatActor(array $valueKeys, array $options)
    {
        if (empty($valueKeys)) {
            return array();
        }

        // Bulk cluster resolve: tag_id → value + icon, via
        // galaxy_clusters.tag_name = tags.name (+ galaxies for the icon).
        $galaxyClusterModel = ClassRegistry::init('GalaxyCluster');
        $rows = $galaxyClusterModel->find('all', array(
            'recursive' => -1,
            'fields' => array(
                'Tag.id',
                'GalaxyCluster.id',
                'GalaxyCluster.value',
                'GalaxyCluster.default',
                'GalaxyCluster.version',
                'Galaxy.icon',
            ),
            'joins' => array(
                array(
                    'table' => 'tags',
                    'alias' => 'Tag',
                    'type' => 'INNER',
                    'conditions' => array(
                        'Tag.name = GalaxyCluster.tag_name',
                        'Tag.id' => $valueKeys,
                    ),
                ),
                array(
                    'table' => 'galaxies',
                    'alias' => 'Galaxy',
                    'type' => 'LEFT',
                    'conditions' => array('Galaxy.id = GalaxyCluster.galaxy_id'),
                ),
            ),
        ));

        // Keep the best cluster per tag_id (default desc, version desc, id
        // desc) — done in PHP to avoid ORDER BY on the reserved word `default`.
        $best = array();        // tag_id => [cluster_id, value, icon, rank tuple]
        foreach ($rows as $r) {
            $tagId = (int)$r['Tag']['id'];
            $cand = array(
                'cluster_id' => (int)$r['GalaxyCluster']['id'],
                'value' => (string)$r['GalaxyCluster']['value'],
                'icon' => isset($r['Galaxy']['icon']) ? (string)$r['Galaxy']['icon'] : '',
                'default' => (int)$r['GalaxyCluster']['default'],
                'version' => (int)$r['GalaxyCluster']['version'],
            );
            if (!isset($best[$tagId]) || $this->clusterOutranks($cand, $best[$tagId])) {
                $best[$tagId] = $cand;
            }
        }

        // Bulk synonyms for the chosen clusters (one query; hover tooltip).
        $clusterIds = array();
        foreach ($best as $c) {
            $clusterIds[$c['cluster_id']] = true;
        }
        $synonymsByCluster = array();
        if (!empty($clusterIds)) {
            $galaxyElementModel = ClassRegistry::init('GalaxyElement');
            $elements = $galaxyElementModel->find('all', array(
                'recursive' => -1,
                'fields' => array(
                    'GalaxyElement.galaxy_cluster_id',
                    'GalaxyElement.value',
                ),
                'conditions' => array(
                    'GalaxyElement.galaxy_cluster_id' => array_keys($clusterIds),
                    'GalaxyElement.key' => 'synonyms',
                ),
            ));
            foreach ($elements as $e) {
                $cid = (int)$e['GalaxyElement']['galaxy_cluster_id'];
                $synonymsByCluster[$cid][] = (string)$e['GalaxyElement']['value'];
            }
        }

        $labels = array();
        foreach ($valueKeys as $tagId) {
            $tagId = (int)$tagId;
            if (!isset($best[$tagId])) {
                // No cluster row (orphan tag) — fall back to the bare actor
                // name parsed out of the tag, so the row is never blank.
                $labels[$tagId] = array('label' => $this->actorNameFromTagId($tagId));
                continue;
            }
            $c = $best[$tagId];
            $meta = array(
                'label' => $c['value'] !== '' ? $c['value'] : $this->actorNameFromTagId($tagId),
                'drilldown' => '/galaxy_clusters/view/' . $c['cluster_id'],
            );
            if ($c['icon'] !== '') {
                $meta['icon'] = $c['icon'];
            }
            if (!empty($synonymsByCluster[$c['cluster_id']])) {
                // Dedupe: duplicate galaxy imports can leave repeated synonym
                // elements on one cluster, which would double the tooltip.
                $syn = array_values(array_unique($synonymsByCluster[$c['cluster_id']]));
                $meta['title'] = __('Synonyms: %s', implode(', ', $syn));
            }
            $labels[$tagId] = $meta;
        }
        return $labels;
    }

    /**
     * Deterministic cluster preference: shipped default over a fork, then the
     * newest version, then the highest id. True iff $a outranks $b.
     */
    private function clusterOutranks(array $a, array $b)
    {
        if ($a['default'] !== $b['default']) {
            return $a['default'] > $b['default'];
        }
        if ($a['version'] !== $b['version']) {
            return $a['version'] > $b['version'];
        }
        return $a['cluster_id'] > $b['cluster_id'];
    }

    /**
     * Last-ditch display name for a threat-actor tag with no resolvable
     * cluster: the value inside `misp-galaxy:threat-actor="<name>"`, or the
     * raw tag name if it doesn't parse.
     */
    private function actorNameFromTagId($tagId)
    {
        $tagModel = ClassRegistry::init('Tag');
        $name = $tagModel->find('column', array(
            'recursive' => -1,
            'conditions' => array('Tag.id' => (int)$tagId),
            'fields' => array('Tag.name'),
        ));
        $name = !empty($name) ? (string)$name[0] : (string)$tagId;
        if (preg_match('/="(.*)"$/', $name, $m)) {
            return $m[1];
        }
        return $name;
    }

    // ---- dimension: mitre-attack-pattern (ATT&CK techniques; AD-W4 / AD-11) ----

    /**
     * The Enterprise ATT&CK technique tag set and its sub-technique→parent
     * roll-up map (AD-11). Scope = the native `misp-galaxy:mitre-attack-
     * pattern="…"` namespace (galaxy type `mitre-attack-pattern`, the
     * Enterprise matrix — the mobile / ICS / ATLAS / pre / cmtmf attack-pattern
     * galaxies are separate namespaces and excluded, mirroring W3's single-
     * galaxy scope).
     *
     * The technique id is parsed from the tag NAME — every such tag is named
     * `<value> - T<id>` (e.g. `… - T1566.001`) — and NOT from a galaxy_elements
     * `external_id` element: on real data that element is unreliable for this
     * roll-up (it carries legacy ids such as `APP-19` for mobile-derived
     * techniques whose name still bears the canonical `T<id>`). AD-11 left the
     * exact mapping "open at build"; the name suffix is the consistent source.
     * The parent is the id with any `.NNN` sub-technique suffix stripped
     * (`T1566.001` → `T1566`), so several sub-technique tags fold into one
     * parent row (AD-11 Fork). Tags whose name yields no `T<id>` (the tactic
     * `TA00NN` tags + a few deprecated un-suffixed legacy names) are not
     * techniques and have nothing to roll up, so they are dropped.
     *
     * @return array [0 => int[] tagIds, 1 => array<int,string> tag_id => parentId]
     */
    private function attackPatternTagBuckets()
    {
        $tagModel = ClassRegistry::init('Tag');
        $rows = $tagModel->find('all', array(
            'recursive' => -1,
            'conditions' => array(
                'Tag.is_galaxy' => 1,
                'Tag.name LIKE' => 'misp-galaxy:mitre-attack-pattern="%',
            ),
            'fields' => array('Tag.id', 'Tag.name'),
        ));
        $bucketMap = array();
        foreach ($rows as $r) {
            $techId = $this->techniqueIdFromName($r['Tag']['name']);
            if ($techId === null) {
                continue;           // tactic / un-suffixed legacy name — skip
            }
            $bucketMap[(int)$r['Tag']['id']] = $this->parentTechniqueId($techId);
        }
        return array(array_keys($bucketMap), $bucketMap);
    }

    /**
     * COUNT(DISTINCT event_id) per ATT&CK *parent* technique (AD-W4 / AD-11):
     * reuses the shared union-distinct tag counter with the sub-technique→
     * parent bucket map, so an event tagged with a technique AND one of its
     * sub-techniques counts once for the parent.
     */
    private function countAttackPattern($user, $startTs, $endTs)
    {
        list($tagIds, $bucketMap) = $this->attackPatternTagBuckets();
        return $this->countDistinctEventsByTag($user, $startTs, $endTs, $tagIds, $bucketMap);
    }

    /**
     * Attack-technique label hook: resolve each trended *parent* technique id
     * (e.g. `T1566`) to its parent cluster — display `value` + `external_id`
     * ("Phishing (T1566)"), the galaxy `icon` (`map`) and a drill-down to the
     * in-app cluster view (AD-11). Bulk-resolved (one query, top-N only) to
     * avoid N+1.
     *
     * The parent cluster is matched by the technique id embedded in its
     * `galaxy_clusters.tag_name` (`… - T1566"`) — the same canonical source as
     * the roll-up, and resilient to the parent cluster having NO `tags` row
     * (only ~a third of clusters here do). A parent maps to 1..N cluster rows
     * (local forks); clusterOutranks() picks one deterministically (default
     * desc, version desc, id desc) — display-only, the count is keyed by the
     * parent id. The parent cluster resolves even when only sub-techniques were
     * tagged (AD-11), because the parent technique is itself a cluster. Link =
     * `/galaxy_clusters/view/<parent_cluster_id>` (relative, on-host → admitted
     * by DD-03 with no relaxation). A parent with no cluster row falls back to
     * the bare technique id, so the row is never blank.
     */
    private function labelsAttackPattern(array $valueKeys, array $options)
    {
        if (empty($valueKeys)) {
            return array();
        }

        // Match parent clusters by the `- T<id>"` suffix of their tag_name,
        // OR'd over the top-N parent ids (bounded by `threshold`). The closing
        // quote pins the match to the exact parent (a sub-technique tag_name
        // ends `…T1566.001"`, so `% - T1566"` never matches it).
        $suffixConds = array();
        foreach ($valueKeys as $pid) {
            $suffixConds[] = array('GalaxyCluster.tag_name LIKE' => '% - ' . $pid . '"');
        }
        $galaxyClusterModel = ClassRegistry::init('GalaxyCluster');
        $rows = $galaxyClusterModel->find('all', array(
            'recursive' => -1,
            'fields' => array(
                'GalaxyCluster.id',
                'GalaxyCluster.tag_name',
                'GalaxyCluster.value',
                'GalaxyCluster.default',
                'GalaxyCluster.version',
                'Galaxy.icon',
            ),
            'joins' => array(array(
                'table' => 'galaxies',
                'alias' => 'Galaxy',
                'type' => 'INNER',
                'conditions' => array(
                    'Galaxy.id = GalaxyCluster.galaxy_id',
                    'Galaxy.type' => 'mitre-attack-pattern',
                ),
            )),
            'conditions' => array('OR' => $suffixConds),
        ));

        // Keep the best cluster per parent id (default desc, version desc, id
        // desc), re-deriving the parent from each row's tag_name to bucket it.
        $best = array();        // parentId => [cluster_id, value, icon, rank…]
        foreach ($rows as $r) {
            $techId = $this->techniqueIdFromName($r['GalaxyCluster']['tag_name']);
            if ($techId === null) {
                continue;
            }
            $parentId = $this->parentTechniqueId($techId);
            $cand = array(
                'cluster_id' => (int)$r['GalaxyCluster']['id'],
                'value' => (string)$r['GalaxyCluster']['value'],
                'icon' => isset($r['Galaxy']['icon']) ? (string)$r['Galaxy']['icon'] : '',
                'default' => (int)$r['GalaxyCluster']['default'],
                'version' => (int)$r['GalaxyCluster']['version'],
            );
            if (!isset($best[$parentId]) || $this->clusterOutranks($cand, $best[$parentId])) {
                $best[$parentId] = $cand;
            }
        }

        $labels = array();
        foreach ($valueKeys as $pid) {
            if (!isset($best[$pid])) {
                // No parent cluster row — show the bare technique id.
                $labels[$pid] = array('label' => (string)$pid);
                continue;
            }
            $c = $best[$pid];
            $meta = array(
                'label' => $this->attackLabel($c['value'], $pid),
                'drilldown' => '/galaxy_clusters/view/' . $c['cluster_id'],
            );
            if ($c['icon'] !== '') {
                $meta['icon'] = $c['icon'];
            }
            $labels[$pid] = $meta;
        }
        return $labels;
    }

    /**
     * Parse the ATT&CK technique id (`T1566` / `T1566.001`) out of an attack-
     * pattern tag or cluster name (`misp-galaxy:mitre-attack-pattern="<value> -
     * T1566.001"`). The trailing-quote / end-of-string anchor pins the match to
     * the id at the very end of the name, so a stray `T<n>` inside the value
     * can't be mistaken for it. Returns null when there is no `T<id>` suffix
     * (tactic `TA00NN` — the `A` breaks `T\d` — or a deprecated un-suffixed
     * name).
     */
    private function techniqueIdFromName($name)
    {
        if (preg_match('/T(\d+(?:\.\d+)?)(?:"|$)/', (string)$name, $m)) {
            return 'T' . $m[1];
        }
        return null;
    }

    /**
     * The parent technique id of a (possibly sub-) technique id: strip a
     * trailing `.NNN` sub-technique suffix (`T1566.001` → `T1566`); a parent id
     * is returned unchanged.
     */
    private function parentTechniqueId($techId)
    {
        $dot = strpos($techId, '.');
        return $dot === false ? $techId : substr($techId, 0, $dot);
    }

    /**
     * Format a parent technique's display label as "<name> (<id>)" (AD-11),
     * deriving <name> from the cluster value by stripping its own trailing
     * ` - T<id>` suffix (cluster values are stored as "Phishing - T1566").
     * Falls back to the raw value, then the id, if the suffix isn't present.
     */
    private function attackLabel($clusterValue, $parentId)
    {
        $name = trim(preg_replace('/\s*-\s*T\d+(?:\.\d+)?$/', '', (string)$clusterValue));
        if ($name === '') {
            $name = (string)$clusterValue !== '' ? (string)$clusterValue : (string)$parentId;
        }
        return $name . ' (' . $parentId . ')';
    }
}
