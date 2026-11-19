<?php
class OrganisationListWidget
{
    public $title = 'Organisation list';
    public $category = 'orgs';
    public $render = 'BarChart';
    public $description = 'Counts organisations by nationality.';
    public $width = 3;
    public $height = 4;
    public $params = [
        'filter' => 'A list of filters by organisation meta information (sector, type, local (- expects a boolean or a list of boolean values)) to include. (dictionary, prepending values with ! uses them as a negation)',
        'limit' => 'Limits the number of displayed tags. Default: 10'
    ];
    public $schema = [
        'filter' => [
            'type' => 'org_meta_filter',
            'help' => 'Filter by organisation meta-data. This widget consumes sector / type / local only; name / nationality / uuid set via the toolbar are silently dropped by the widget\'s own validFilterKeys loop.',
        ],
    ];
    public $cacheLifetime = null;
    public $autoRefreshDelay = false;
    private $validFilterKeys = [
        'sector',
        'type',
        'local'
    ];
    public $placeholder =
'{
    "filter": {
        "type": "Member",
        "local": [0,1]
    }
}';
    private $Organisation = null;

    public $countryCodes = [];

    public function handler($user, $options = array())
    {
        App::uses('WidgetToolkit', 'Lib/Dashboard/Tools');
        $WidgetToolkit = new WidgetToolkit();
        $this->countryCodes = $WidgetToolkit->getCountryCodeMapping();
        $this->Organisation = ClassRegistry::init('Organisation');
        $conditions = [$this->Organisation->createConditions($user)];
        if (!empty($options['filter']) && is_array($options['filter'])) {
            foreach ($this->validFilterKeys as $filterKey) {
                $field = 'Organisation.' . $filterKey;
                foreach ((array)($options['filter'][$filterKey] ?? []) as $value) {
                    if (is_string($value) && $value === '') {
                        continue;
                    }
                    if (is_string($value) && $value[0] === '!') {
                        $conditions[$field . ' NOT IN'][] = mb_substr($value, 1);
                    } else {
                        $conditions[$field . ' IN'][] = $value;
                    }
                }
            }
        }
        $orgs = $this->Organisation->find('all', [
            'recursive' => -1,
            'fields' => ['Organisation.nationality', 'COUNT(*) AS frequency'],
            'conditions' => $conditions,
            'group' => ['Organisation.nationality']
        ]);
        $results = [];
        foreach ($orgs as $org) {
            $country = $org['Organisation']['nationality'];
            $label = $country === null || $country === ''
                ? __('Not specified')
                : ($this->countryCodes[$country] ?? $country);
            $results[$label] = ($results[$label] ?? 0) + $org[0]['frequency'];
        }
        arsort($results);
        return ['data' => $results];
    }
}
