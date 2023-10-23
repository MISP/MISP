<?php

class TrendingAttributesWidget
{
    public $title = 'Trending Attribute values';
    public $render = 'BarChart';
    public $width = 3;
    public $height = 4;
    public $params = array(
        'time_window' => 'The time window, going back in seconds, that should be included. (allows for filtering by days - example: 5d. -1 Will fetch all historic data)',
        'exclude' => 'List of values to exclude - for example "8.8.8.8".',
        'threshold' => 'Limits the number of displayed attribute values. Default: 10',
        'type' => 'List of Attribute types to include',
        'category' => 'List of Attribute categories to exclude',
        'to_ids' => 'A list of to_ids settings accepted for the data displayed ([0], [1], [0,1])',
        'org_filter' => 'List of organisation filters to exclude events by, based on organisation meta-data (Organisation.sector, Organisation.type, Organisation.nationality). Pre-pending a value with a "!" negates it.'
    );
    private $validOrgFilters = [
        'sector',
        'type',
        'national',
        'uuid',
        'local'
    ];
    public $placeholder =
    '{
    "time_window": "7d",
    "threshold": 15,
    "org_filter": {
        "sector": ["Financial"]
    }
}';
    public $description = 'Widget showing the trending tags over the past x seconds, along with the possibility to include/exclude tags.';
    public $cacheLifetime = 3;

    private function getOrgList($options)
    {
        $organisationModel = ClassRegistry::init('Organisation');
        if (!empty($options['org_filter']) && is_array($options['org_filter'])) {
            foreach ($this->validOrgFilters as $filterKey) {
                if (isset($options['org_filter'][$filterKey])) {
                    if ($filterKey === 'local') {
                        $tempConditionBucket['Organisation.local'] = $options['org_filter']['local'];
                    } else {
                        if (!is_array($options['org_filter'][$filterKey])) {
                            $options['org_filter'][$filterKey] = [$options['org_filter'][$filterKey]];
                        }
                        $tempConditionBucket = [];
                        foreach ($options['org_filter'][$filterKey] as $value) {
                            if ($value[0] === '!') {
                                $tempConditionBucket['Organisation.' . $filterKey . ' NOT IN'][] = mb_substr($value, 1);
                            } else {
                                $tempConditionBucket['Organisation.' . $filterKey . ' IN'][] = $value;
                            }
                        }
                    }
                    if (!empty($tempConditionBucket)) {
                        $orgConditions[] = $tempConditionBucket;
                    }
                }
            }
            return $organisationModel->find('column', [
                'recursive' => -1,
                'conditions' => $orgConditions,
                'fields' => ['Organisation.id']
            ]);
        }
    }

	public function handler($user, $options = array())
	{
	    /** @var Event $eventModel */
        $attributeModel = ClassRegistry::init('Attribute');
        $threshold = empty($options['threshold']) ? 10 : $options['threshold'];
        if (is_string($options['time_window']) && substr($options['time_window'], -1) === 'd') {
            $time_window = ((int)substr($options['time_window'], 0, -1)) * 24 * 60 * 60;
        } else {
            $time_window = empty($options['time_window']) ? (7 * 24 * 60 * 60) : (int)$options['time_window'];
        }
        $conditions = $time_window === -1 ? [] : ['Attribute.timestamp >=' => time() - $time_window];
        $conditions['Attribute.deleted'] = 0;
        $conditionsToParse = ['type', 'category', 'to_ids'];
        foreach ($conditionsToParse as $parsedCondition) {
            if (!empty($options[$parsedCondition])) {
                $conditions['Attribute.' . $parsedCondition] = $options[$parsedCondition];
            }
        }
        if (!empty($options['exclude'])) {
            $conditions['Attribute.value1 NOT IN'] = $options['exclude'];
        }
        if (!empty($options['org_filter'])) {
            $conditions['Event.orgc_id IN'] = $this->getOrgList($options);
            if (empty($conditions['Event.orgc_id IN'])) {
                $conditions['Event.orgc_id IN'] = [-1];
            }
        }
        $attributeModel->virtualFields['frequency'] = 0;
        if (!empty($user['Role']['perm_site_admin'])) {
            $values = $attributeModel->find('all', [
                'recursive' => -1,
                'fields' => ['Attribute.value1', 'count(Attribute.value1) as Attribute__frequency'],
                'group' => ['Attribute.value1', ],
                'conditions' => $conditions,
                'contain' => ['Event.orgc_id'],
                'order' => 'count(Attribute.value1) desc',
                'limit' => empty($options['threshold']) ? 10 : $options['threshold']
            ]);
        } else {
            $conditions['AND'][] = [
                'OR' => [
                    'Event.orgc_id' => $user['org_id'],

                ]
            ];
            $values = $attributeModel->find('all', [
                'recursive' => -1,
                'fields' => ['Attribute.value1', 'count(Attribute.value1) as Attribute__frequency', 'Attribute.distribution', 'Attribute.sharing_group_id'],
                'group' => 'Attribute.value1',
                'contain' => [
                    'Event.org_id',
                    'Event.distribution',
                    'Event.sharing_group_id',
                    'Object.distribution',
                    'Object.sharing_group_id'
                ],
                'conditions' => $conditions,
                'order' => 'count(Attribute.value1) desc',
                'limit' => empty($options['threshold']) ? 10 : $options['threshold']
            ]);
        }
        $data = [];
        foreach ($values as $value) {
            $data[$value['Attribute']['value1']] = $value['Attribute']['frequency'];
        }
        return ['data' => $data];
	}
}
