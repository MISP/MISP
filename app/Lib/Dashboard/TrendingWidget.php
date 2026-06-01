<?php

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
 * Momentum (AD-03) lands in B1.5; the per-org cache (AD-04) in B1.6 — until
 * then the widget computes live on every render.
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
    );

    public $placeholder =
'{
    "dimension": "vulnerability",
    "time_window": "30d",
    "threshold": 15
}';

    public $description = 'Parametrised trending widget: ranks the values '
        . 'rising fastest in a dimension (vulnerabilities, …) by '
        . 'distinct-event count over a time window.';

    /**
     * Per-dimension hook registry. Each new dimension (build phases
     * B4/B5/B6) adds one entry here plus its hook methods — purely additive.
     * Hooks:
     *   - title  : the dimension's human title (informational)
     *   - count  : method($user, $windowSeconds) => [valueKey => distinctEvents]
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
        $windowSeconds = $this->parseWindow($options);

        // Current-window distinct-event counts per value (ACL-correct).
        $counts = $this->{$dimension['count']}($user, $windowSeconds);
        if (empty($counts)) {
            return array();
        }

        // Volume rank: highest distinct-event count first; take the top N.
        arsort($counts);
        $counts = array_slice($counts, 0, $threshold, true);

        // Resolve display labels / links for the top-N only (avoids
        // resolving the whole set — matters for galaxy dimensions, B5/B6).
        $labels = $this->{$dimension['labels']}(array_keys($counts), $options);

        $rows = array();
        foreach ($counts as $valueKey => $count) {
            $meta = isset($labels[$valueKey]) ? $labels[$valueKey] : array();
            $row = array(
                'label' => isset($meta['label']) ? $meta['label'] : (string)$valueKey,
                'count' => (int)$count,
            );
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
     * window-bounded by Attribute.timestamp (AD-05). Three narrow steps keep
     * both the candidate set and the IN list bounded by the window:
     *   (1) distinct events carrying an in-window vulnerability attribute,
     *   (2) ACL-filter those to the viewer's visible subset,
     *   (3) distinct-event count per value over that visible subset.
     */
    private function countVulnerability($user, $windowSeconds)
    {
        $attributeModel = ClassRegistry::init('MispAttribute');
        $base = array(
            'Attribute.type' => 'vulnerability',
            'Attribute.deleted' => 0,
        );
        if ($windowSeconds !== -1) {
            $base['Attribute.timestamp >='] = time() - $windowSeconds;
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
     * resolution is needed. The cveurl drill-down link is added in B4.
     */
    private function labelsVulnerability(array $valueKeys, array $options)
    {
        $labels = array();
        foreach ($valueKeys as $v) {
            $labels[$v] = array('label' => (string)$v);
        }
        return $labels;
    }
}
