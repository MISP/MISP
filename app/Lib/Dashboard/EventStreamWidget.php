<?php

class EventStreamWidget
{
    public $title = 'Event Stream';
    public $render = 'Index';
    public $width = 4;
    public $height = 2;
    public $params = [
        'tags' => 'A list of tagnames to filter on. Comma separated list, prepend each tag with an exclamation mark to negate it.',
        'orgs' => 'A list of organisation names to filter on. Comma separated list, prepend each tag with an exclamation mark to negate it.',
        'published' => 'Boolean flag to filter on published events only',
        'limit' => 'How many events should be listed? Defaults to 5',
        'fields' => 'A list of fields that should be displayed. Valid fields: id, orgc, info, tags, threat_level, analysis, date. Default field selection ["id", "orgc", "info"]'
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
        $data = $this->Event->fetchEvent($user, $params);
        return [
            'data' => $data,
            'fields' => $fields
        ];
	}
}
