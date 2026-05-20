<?php

class EventStreamWidget
{
    public $title = 'Event Stream';
    public $category = 'events';
    public $render = 'Index';
    public $width = 4;
    public $height = 2;
    public $params = [
        'tags' => 'A list of tagnames to filter on. Comma separated list, prepend each tag with an exclamation mark to negate it.',
        'orgs' => 'A list of organisation names to filter on. Comma separated list, prepend each tag with an exclamation mark to negate it.',
        'published' => 'Boolean flag to filter on published events only',
        'limit' => 'How many events should be listed? Defaults to 5',
        'fields' => 'A list of fields that should be displayed. Valid fields: id, orgc, info, tags, threat_level, analysis, date. Default field selection ["id", "orgc", "info"]',
        'threat_level' => 'A list of threat levels (1=High, 2=Medium, 3=Low, 4=Undefined) to filter events by. Accepts an int array or single int. Empty / unset = no filter.',
        'analysis' => 'A list of analysis stages (0=Initial, 1=Ongoing, 2=Complete) to filter events by. Accepts an int array or single int. Empty / unset = no filter.',
        'sharing_group' => 'A list of SharingGroup.id values to filter events by. Accepts an int array or single int. Empty / unset = no filter; unauthorised IDs match no rows.',
        'galaxy_cluster' => 'Galaxy cluster filter: { tag_names: ["misp-galaxy:<type>=\\"<value>\\""], galaxy_types?: ["<type>", ...] }. Filters to events tagged with any of the listed cluster tag_names.',
    ];
    public $schema = [
        'threat_level' => [
            'type' => 'threat_level_filter',
            'help' => 'Filter events by threat level. Bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.',
        ],
        'analysis' => [
            'type' => 'analysis_filter',
            'help' => 'Filter events by analysis stage (Initial / Ongoing / Complete). Bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.',
        ],
        'sharing_group' => [
            'type' => 'sharing_group_filter',
            'help' => 'Filter events by sharing group. Bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.',
        ],
        'galaxy_cluster' => [
            'type' => 'galaxy_cluster_filter',
            'help' => 'Filter events by galaxy cluster. Pick a galaxy type, then search for clusters; selected clusters appear as removable chips. Bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.',
        ],
    ];
    public $description = 'Monitor incoming events based on your own filters.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 5;
    private $__default_fields = ['id', 'orgc', 'info'];

	public function handler($user, $options = array())
	{
        $this->Event = ClassRegistry::init('Event');
        $params = [
            'metadata' => 1,
            'limit' => 5,
            'page' => 1,
            'order' => 'Event.id DESC'
        ];
        $field_options = [
            'id' => [
                'name' => '#',
                'url' => Configure::read('MISP.baseurl') . '/events/view',
                'element' => 'links',
                'data_path' => 'Event.id',
                'url_params_data_paths' => 'Event.id'
            ],
            'orgc' => [
                'name' => 'Org',
                'data_path' => 'Orgc',
                'element' => 'org'
            ],
            'info' => [
                'name' => 'Info',
                'data_path' => 'Event.info',
            ],
            'tags' => [
                'name' => 'Tags',
                'data_path' => 'EventTag',
                'element' => 'tags',
                'scope' => 'feeds'
            ],
            'threat_level' => [
                'name' => 'Threat Level',
                'data_path' => 'ThreatLevel.name'
            ],
            'analysis' => [
                'name' => 'Analysis',
                'data_path' => 'Event.analysis',
                'element' => 'array_lookup_field',
                'arrayData' => [__('Initial'), __('Ongoing'), __('Complete')]
            ],
            'date' => [
                'name' => 'Date',
                'data_path' => 'Event.date'
            ],
        ];
        $fields = [];
        if (empty($options['fields'])) {
            $options['fields'] = $this->__default_fields;
        }
        foreach ($options['fields'] as $field) {
            if (!empty($field_options[$field])) {
                $fields[] = $field_options[$field];
            }
        }
        foreach (['published', 'limit', 'tags', 'orgs'] as $field) {
            if (!empty($options[$field])) {
                $params[$field] = $options[$field];
            }
        }
        // Phase 3 canonical filters — applied as PHP post-filters
        // because fetchEvent doesn't natively accept `threat_level_id`
        // or `analysis` as filter inputs (only as SELECT columns;
        // the set_filter_* helpers live in the restSearch dispatcher,
        // not fetchEvent). Both filters can only narrow visibility
        // (never expand it) so applying them post-fetch is ACL-safe.
        //
        // Pre-fetch overshoot: since the post-filters narrow AFTER
        // the LIMIT clause has been applied to the SQL, the user's
        // declared limit must be bumped up at fetch time and then
        // truncated client-side, otherwise the result count would
        // shrink unpredictably depending on which threat levels /
        // analysis stages happen to be most recent. Heuristic: fetch
        // max(200, limit * 10) if any canonical post-filter is set.
        // Users wanting guaranteed N matches for a rare level can
        // raise the widget's limit config.
        $rawLimit = isset($params['limit']) ? (int)$params['limit'] : 5;
        $coerceLevels = function ($raw) {
            $arr = is_array($raw) ? $raw : [$raw];
            $out = [];
            foreach ($arr as $v) {
                if (is_int($v)
                    || (is_string($v) && is_numeric($v))
                    || (is_float($v) && is_finite($v))) {
                    $out[] = (int)$v;
                }
            }
            return $out;
        };
        $allowedThreat   = !empty($options['threat_level']) ? $coerceLevels($options['threat_level']) : [];
        $allowedAnalysis = isset($options['analysis']) && $options['analysis'] !== ''
            ? $coerceLevels($options['analysis']) : [];
        $allowedSg       = !empty($options['sharing_group']) ? $coerceLevels($options['sharing_group']) : [];
        // galaxy_cluster_filter wire shape:
        //   { tag_names: string[], galaxy_types?: string[] }
        // Only tag_names is a query filter (galaxy_types is picker
        // scope state, preserved on the wire for round-trip but not
        // applied to the query).
        $allowedGcTags = [];
        if (isset($options['galaxy_cluster']) && is_array($options['galaxy_cluster'])
            && isset($options['galaxy_cluster']['tag_names']) && is_array($options['galaxy_cluster']['tag_names'])) {
            foreach ($options['galaxy_cluster']['tag_names'] as $tn) {
                if (is_string($tn) && $tn !== '') {
                    $allowedGcTags[$tn] = true;   // dedup via assoc-key
                }
            }
            $allowedGcTags = array_keys($allowedGcTags);
        }
        $hasPostFilter = !empty($allowedThreat) || !empty($allowedAnalysis) || !empty($allowedSg) || !empty($allowedGcTags);
        if ($hasPostFilter) {
            $params['limit'] = max(200, $rawLimit * 10);
        }
        $data = $this->Event->fetchEvent($user, $params);
        if (!empty($allowedThreat)) {
            $data = array_values(array_filter($data, function ($evt) use ($allowedThreat) {
                return isset($evt['Event']['threat_level_id'])
                    && in_array((int)$evt['Event']['threat_level_id'], $allowedThreat, true);
            }));
        }
        if (!empty($allowedAnalysis)) {
            $data = array_values(array_filter($data, function ($evt) use ($allowedAnalysis) {
                return isset($evt['Event']['analysis'])
                    && in_array((int)$evt['Event']['analysis'], $allowedAnalysis, true);
            }));
        }
        if (!empty($allowedSg)) {
            // Event.sharing_group_id is only set when distribution=4
            // (Sharing Group). Other distribution levels leave it
            // null / 0. The IN check naturally excludes those rows
            // — which is the right semantic: filtering "by sharing
            // group X" should not match events that aren't shared
            // via a sharing group at all.
            $data = array_values(array_filter($data, function ($evt) use ($allowedSg) {
                return isset($evt['Event']['sharing_group_id'])
                    && in_array((int)$evt['Event']['sharing_group_id'], $allowedSg, true);
            }));
        }
        if (!empty($allowedGcTags)) {
            // Event matches if any of its EventTag entries carries
            // a Tag.name in the allowedGcTags set. Tag.name is an
            // exact match against the cluster's tag_name (e.g.
            //   'misp-galaxy:mitre-attack-pattern="Phishing - T1566"').
            // Galaxy-type-only filtering (no specific clusters
            // picked) is NOT applied here — galaxy_types is picker
            // scope state per the canonical's shape.
            $allowedGcSet = array_flip($allowedGcTags);
            $data = array_values(array_filter($data, function ($evt) use ($allowedGcSet) {
                if (empty($evt['EventTag']) || !is_array($evt['EventTag'])) return false;
                foreach ($evt['EventTag'] as $et) {
                    $name = isset($et['Tag']['name']) ? (string)$et['Tag']['name'] : '';
                    if ($name !== '' && isset($allowedGcSet[$name])) {
                        return true;
                    }
                }
                return false;
            }));
        }
        if ($hasPostFilter) {
            $data = array_slice($data, 0, $rawLimit);
        }
        return [
            'data' => $data,
            'fields' => $fields
        ];
	}
}
