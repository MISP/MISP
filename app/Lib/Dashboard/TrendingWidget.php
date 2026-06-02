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
            . '(CVE / GCVE / GHSA attribute identifiers). Further dimensions '
            . '(threat-actor, mitre-attack-pattern) are added by later build '
            . 'phases. Default: vulnerability.',
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
}
