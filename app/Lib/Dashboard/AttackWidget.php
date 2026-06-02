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
        'filters' => 'A list of restsearch filters to apply to the heatmap. (dictionary, prepending values with ! uses them as a negation)',
        'time_window' => 'Recency window, going back in seconds, that should be included (also accepts the "30d" day form, or -1 for all historic data). Drives the restSearch `timestamp` filter and overrides any `timestamp` set in `filters`. Toolbar-reachable; default -1 (all time).'
    ];
    public $schema = [
        'time_window' => [
            'type' => 'time_window',
            'default' => -1,
            'help' => 'Recency window over which events feed the heatmap (last N days/hours, or all time). Toolbar-reachable; drives the restSearch `timestamp` filter (overrides any timestamp set in `filters`). Default: all historic data.',
        ],
    ];
    public $cacheLifetime = 1200;
    public $autoRefreshDelay = false;
    private $validFilterKeys = [
        'filters',
        'time_window'
    ];
    private $Event = null;
    public $placeholder =
'{
    "time_window": "30d",
    "filters": {
        "attackGalaxy": "mitre-attack-pattern",
        "published": [0,1]
    }
}';

    public function handler($user, $options = array())
    {
        $this->Event = ClassRegistry::init('Event');
        $filters = (isset($options['filters']) && is_array($options['filters'])) ? $options['filters'] : [];
        // AD-15/AD-12: the global `time_window` canonical drives the restSearch
        // `timestamp` lower bound so the heatmap re-scopes with the board's
        // toolbar. A resolved window OVERRIDES any timestamp set manually in
        // `filters`; -1/all-time leaves `filters` untouched (back-compat — the
        // default, so existing instances keep their prior unbounded behaviour).
        $since = $this->resolveTimeWindow($options);
        if ($since !== null) {
            $filters['timestamp'] = $since;
        }
        if (empty($filters)) {
            return null;
        }
        $data = $this->Event->restSearch($user, 'attack', $filters);
        return JsonTool::decode($data->intoString());
    }

    /**
     * Resolve the `time_window` canonical into a restSearch `timestamp` lower
     * bound (epoch seconds), or null for "no bound" (all-time / unset / junk).
     * Mirrors the in-tree idiom (TrendingAttributesWidget / AttributeGeoMapWidget);
     * the CanonicalTypeAdapter has already translated the schema default / toolbar
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
