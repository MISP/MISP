<?php
class AttackWidget
{
    public $title = 'ATT&CK heatmap';
    public $category = 'events';
    public $render = 'Attack';
    public $description = 'Retrieve an ATT&CK (or ATT&CK like) heatmap for the current instance.';
    public $width = 3;
    public $height = 4;
    public $params = [
        'filters' => 'A list of event filters that scope which events feed the heatmap. (dictionary, prepending values with ! uses them as a negation). Uses the same filter vocabulary as the event index/restSearch (e.g. published, tags, org, type, value, from/to), but only EVENT-LEVEL ATT&CK galaxy tags are counted.',
        'time_window' => 'Recency window, going back in seconds, that should be included (also accepts the "30d" day form, or -1 for all historic data). Drives the `timestamp` filter and overrides any `timestamp` set in `filters`. Toolbar-reachable; default -1 (all time).'
    ];
    public $schema = [
        'time_window' => [
            'type' => 'time_window',
            'default' => -1,
            'help' => 'Recency window over which events feed the heatmap (last N days/hours, or all time). Toolbar-reachable; drives the `timestamp` filter (overrides any timestamp set in `filters`). Default: all historic data.',
        ],
    ];
    public $cacheLifetime = 1200;
    public $autoRefreshDelay = false;
    private $validFilterKeys = [
        'filters',
        'time_window'
    ];
    private $Event = null;
    private $Galaxy = null;
    public $placeholder =
'{
    "time_window": "30d",
    "filters": {
        "attackGalaxy": "mitre-attack-pattern",
        "published": [0,1]
    }
}';

    /**
     * Build the ATT&CK heatmap payload.
     *
     * Historically this proxied `Event::restSearch($user, 'attack', ...)`, which
     * fetched every matching event with all of its attributes fully hydrated just
     * to tally EVENT-LEVEL ATT&CK galaxy tags — pathologically slow on large
     * instances. We only need per-technique event counts, so instead we:
     *   1. resolve the requested ATT&CK galaxy + its matrix skeleton,
     *   2. resolve the matching events under the standard event ACL + filters via
     *      Event::filterEventIds() (no attribute/event hydration), and
     *   3. group-count the relevant galaxy cluster tags over those events.
     * The returned structure is identical to the `attack` restSearch export shape
     * (Galaxy::getMatrix + AttackExport::footer), so the renderer is unchanged.
     */
    public function handler($user, $options = array())
    {
        $this->Event = ClassRegistry::init('Event');
        $this->Galaxy = ClassRegistry::init('Galaxy');
        $filters = (isset($options['filters']) && is_array($options['filters'])) ? $options['filters'] : [];
        // AD-15/AD-12: the global `time_window` canonical drives the `timestamp`
        // lower bound so the heatmap re-scopes with the board's toolbar. A resolved
        // window OVERRIDES any timestamp set manually in `filters`; -1/all-time
        // leaves `filters` untouched (back-compat — the default, so existing
        // instances keep their prior unbounded behaviour).
        $since = $this->resolveTimeWindow($options);
        if ($since !== null) {
            $filters['timestamp'] = $since;
        }
        if (empty($filters)) {
            return null;
        }

        // 1) Resolve the ATT&CK (or ATT&CK-like) galaxy to chart. `attackGalaxy`
        //    selects the matrix; it is not an event filter.
        $attackGalaxy = empty($filters['attackGalaxy']) ? 'mitre-attack-pattern' : $filters['attackGalaxy'];
        $galaxy = $this->Galaxy->find('first', array(
            'recursive' => -1,
            'fields' => array('id', 'name'),
            'conditions' => array('Galaxy.type' => $attackGalaxy, 'Galaxy.namespace !=' => 'deprecated'),
        ));
        if (empty($galaxy)) {
            return null;
        }
        $galaxyId = $galaxy['Galaxy']['id'];
        $galaxyName = $galaxy['Galaxy']['name'];

        // 2) Matrix skeleton (tabs/columns + the renderable cluster cells).
        $matrixData = $this->Galaxy->getMatrix($user, $galaxyId);

        // 3) Score the techniques: distinct EVENT-LEVEL events carrying each cluster
        //    tag, restricted to events visible to the user (ACL) and matching the
        //    configured filters. We score exactly the tags that appear as matrix
        //    cells (i.e. that can actually render), rather than getMatrix's wider
        //    `matrixTags` set which also folds in deprecated-galaxy tag_names "for
        //    the stats" — those never map to a cell.
        $cellTags = $this->collectMatrixCellTags($matrixData['tabs']);
        $scores = $this->scoreTechniques($user, $filters, $cellTags);

        return $this->buildResult($user, $galaxyId, $galaxyName, $matrixData, $scores);
    }

    /**
     * Collect the distinct cluster tag_names that appear as cells in the matrix
     * (across every tab/column). These are the only techniques that can render, so
     * they form the universe we score.
     */
    private function collectMatrixCellTags(array $tabs)
    {
        $tagNames = [];
        foreach ($tabs as $columns) {
            foreach ($columns as $cells) {
                foreach ($cells as $cell) {
                    if (!empty($cell['tag_name'])) {
                        $tagNames[$cell['tag_name']] = true;
                    }
                }
            }
        }
        return array_keys($tagNames);
    }

    /**
     * Count, per relevant ATT&CK cluster tag, the number of distinct events that
     * (a) carry the tag at event level, and (b) are visible to the user and match
     * the supplied filters. Returns a map of cluster tag_name => event count.
     *
     * Reuses Event::filterEventIds() — the same ACL- and filter-aware resolver that
     * restSearch uses to determine matching events (createEventConditions for
     * org/role + distribution + sharing_group_id, plus the full event filter set) —
     * but never hydrates a single event or attribute.
     */
    private function scoreTechniques($user, $filters, array $cellTags)
    {
        if (empty($cellTags)) {
            return [];
        }
        $Tag = $this->Event->EventTag->Tag;
        // cluster tag_name => tag_id, for the tags actually present on this instance
        $tagIdByName = $Tag->find('list', array(
            'recursive' => -1,
            'fields' => array('Tag.name', 'Tag.id'),
            'conditions' => array('Tag.name' => $cellTags),
        ));
        if (empty($tagIdByName)) {
            return [];
        }

        $params = $filters;
        $eventIds = $this->Event->filterEventIds($user, $params);
        if (empty($eventIds)) {
            return [];
        }

        $EventTag = $this->Event->EventTag;
        $EventTag->virtualFields['event_count'] = 'COUNT(DISTINCT EventTag.event_id)';
        $countsByTagId = $EventTag->find('list', array(
            'recursive' => -1,
            'fields' => array('EventTag.tag_id', 'event_count'),
            'conditions' => array(
                'EventTag.event_id' => $eventIds,
                'EventTag.tag_id' => array_values($tagIdByName),
            ),
            'group' => array('EventTag.tag_id'),
        ));
        unset($EventTag->virtualFields['event_count']);

        $nameByTagId = array_flip($tagIdByName);
        $scores = [];
        foreach ($countsByTagId as $tagId => $count) {
            if (isset($nameByTagId[$tagId])) {
                $scores[$nameByTagId[$tagId]] = (int)$count;
            }
        }
        return $scores;
    }

    /**
     * Assemble the render payload — identical in shape to AttackExport::footer so
     * the `Attack` renderer (and any other consumer of the export shape) is unchanged.
     */
    private function buildResult($user, $galaxyId, $galaxyName, array $matrixData, array $scores)
    {
        $tabs = $matrixData['tabs'];
        $this->Galaxy->sortMatrixByScore($tabs, $scores);

        $maxScore = empty($scores) ? 0 : max($scores);

        $result = array(
            'target_type' => 'event',
            'columnOrders' => $matrixData['killChain'],
            'tabs' => $tabs,
            'scores' => $scores,
            'maxScore' => $maxScore,
            'pickingMode' => false,
        );

        App::uses('ColourGradientTool', 'Tools');
        $gradientTool = new ColourGradientTool();
        $colours = $gradientTool->createGradientFromValues($scores);
        if (!empty($colours)) {
            $result['colours'] = $colours['mapping'];
            $result['interpolation'] = $colours['interpolation'];
        }

        if ($galaxyId == $this->Galaxy->getMitreAttackGalaxyId()) {
            $result['defaultTabName'] = 'attack-enterprise';
            $result['removeTrailing'] = 2;
        }
        $result['galaxyName'] = $galaxyName;
        $result['galaxyId'] = $galaxyId;
        $result['matrixGalaxies'] = $this->Galaxy->getAllowedMatrixGalaxies($user);

        return $result;
    }

    /**
     * Resolve the `time_window` canonical into a `timestamp` lower bound (epoch
     * seconds), or null for "no bound" (all-time / unset / junk). Mirrors the
     * in-tree idiom (TrendingAttributesWidget / AttributeGeoMapWidget); the
     * CanonicalTypeAdapter has already translated the schema default / toolbar
     * value into the "<N>d" day form or seconds int before we get here.
     */
    private function resolveTimeWindow($options)
    {
        if (!isset($options['time_window']) || $options['time_window'] === '') {
            return null;
        }
        $raw = $options['time_window'];
        if (is_string($raw) && substr($raw, -1) === 'd') {
            $window = ((int)substr($raw, 0, -1)) * 24 * 60 * 60;
        } else {
            $window = (int)$raw;
        }
        if ($window <= 0) {
            // -1 (all-time sentinel) and any non-positive/junk value → no bound.
            return null;
        }
        return time() - $window;
    }
}
