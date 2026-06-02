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
            . '(CVE / GCVE / GHSA attribute identifiers) and "threat-actor" '
            . '(misp-galaxy threat-actor clusters, by distinct events carrying '
            . 'the cluster tag at event or attribute level). "mitre-attack-'
            . 'pattern" is added by a later build phase. Default: vulnerability.',
        'time_window' => 'The time window, going back in seconds, to include '
            . '(e.g. "30d"; -1 = all historic data).',
        'threshold' => 'Limits the number of displayed rows. Default: 10.',
        'min_count' => 'Minimum current-window distinct-event count before a '
            . 'row may carry a rising/▲▼ momentum badge (kills small-N % '
            . 'noise). Default: 3.',
    );

    public $schema = array(
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
     * COUNT(DISTINCT event_id) per threat-actor cluster tag, over the UNION of
     * the two tag arms (AD-02 / AD-10): events carrying the cluster tag at the
     * event level (EventTag) OR on one of their attributes (AttributeTag).
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
     *   (3) distinct-event count per tag over that subset — a per-tag event
     *       set dedupes an event tagged at BOTH levels to one (union-distinct).
     */
    private function countThreatActor($user, $startTs, $endTs)
    {
        $tagIds = $this->threatActorTagIds();
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

        // (3) distinct-event count per tag over the visible subset; a per-tag
        // event set unions the two arms so a doubly-tagged event counts once.
        $eventsPerTag = array();    // tag_id => [event_id => true]
        foreach ($pairs as $pair) {
            list($tid, $eid) = $pair;
            if (isset($visible[$eid])) {
                $eventsPerTag[$tid][$eid] = true;
            }
        }
        $counts = array();
        foreach ($eventsPerTag as $tid => $eventSet) {
            $counts[$tid] = count($eventSet);
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
}
