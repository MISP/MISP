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
    ];
    public $schema = [
        'threat_level' => [
            'type' => 'threat_level_filter',
            'help' => 'Filter events by threat level. Bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.',
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
        // Phase 3 threat_level_filter — applied as a PHP post-filter
        // because fetchEvent doesn't natively accept `threat_level_id`
        // as a filter input (only as a SELECT column; the
        // set_filter_threat_level_id helper lives in the restSearch
        // dispatcher, not fetchEvent). The filter can only narrow
        // visibility (never expand it) so applying it post-fetch is
        // ACL-safe.
        //
        // Pre-fetch overshoot: since the post-filter narrows AFTER
        // the LIMIT clause has been applied to the SQL, the user's
        // declared limit must be bumped up at fetch time and then
        // truncated client-side, otherwise the result count would
        // shrink unpredictably depending on which threat levels happen
        // to be most recent. Heuristic: fetch max(200, limit * 10).
        // For a uniform-distribution DB this gives ≥80% of declared
        // limit even in the worst single-level case; users wanting
        // guaranteed N matches can raise the limit config.
        $rawLimit = isset($params['limit']) ? (int)$params['limit'] : 5;
        $allowedLevels = [];
        if (!empty($options['threat_level'])) {
            $raw = is_array($options['threat_level'])
                ? $options['threat_level']
                : [$options['threat_level']];
            $allowedLevels = array_values(array_filter(
                array_map('intval', $raw),
                function ($v) { return $v > 0; }
            ));
        }
        if (!empty($allowedLevels)) {
            $params['limit'] = max(200, $rawLimit * 10);
        }
        $data = $this->Event->fetchEvent($user, $params);
        if (!empty($allowedLevels)) {
            $data = array_values(array_filter($data, function ($evt) use ($allowedLevels) {
                return isset($evt['Event']['threat_level_id'])
                    && in_array((int)$evt['Event']['threat_level_id'], $allowedLevels, true);
            }));
            $data = array_slice($data, 0, $rawLimit);
        }
        return [
            'data' => $data,
            'fields' => $fields
        ];
	}
}
