<?php
class OrganisationListWidget
{
    public $title = 'Organisation list';
    public $render = 'BarChart';
    public $description = 'The countries represented via organisations on the current instance.';
    public $width = 3;
    public $height = 4;
    public $params = [
        'filter' => 'A list of filters by organisation meta information (sector, type, local (- expects a boolean or a list of boolean values)) to include. (dictionary, prepending values with ! uses them as a negation)',
        'limit' => 'Limits the number of displayed tags. Default: 10'
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
        $params = [
            'conditions' => [
                'Nationality !=' => ''
            ]
        ];
        if (!empty($options['filter']) && is_array($options['filter'])) {
            foreach ($this->validFilterKeys as $filterKey) {
                if (!empty($options['filter'][$filterKey])) {
                    if (!is_array($options['filter'][$filterKey])) {
                        $options['filter'][$filterKey] = [$options['filter'][$filterKey]];
                    }
                    $tempConditionBucket = [];
                    foreach ($options['filter'][$filterKey] as $value) {
                        if ($value[0] === '!') {
                            $tempConditionBucket['Organisation.' . $filterKey . ' NOT IN'][] = mb_substr($value, 1);
                        } else {
                            $tempConditionBucket['Organisation.' . $filterKey . ' IN'][] = $value;
                        }
                    }
                    if (!empty($tempConditionBucket)) {
                        $params['conditions']['AND'][] = $tempConditionBucket;
                    }
                }
            }
        }
        $this->Organisation = ClassRegistry::init('Organisation');
        $orgs = $this->Organisation->find('all', [
            'recursive' => -1,
            'fields' => ['Organisation.nationality', 'COUNT(Organisation.nationality) AS frequency'],
            'conditions' => $params['conditions'],
            'group' => ['Organisation.nationality']
        ]);
        $results = [];
        foreach($orgs as $org) {
            $country = $org['Organisation']['nationality'];
            $count = $org['0']['frequency'];
            if (isset($this->countryCodes[$country])) {
                $countryCode = $this->countryCodes[$country];
                $results[$countryCode] = $count;
            }
        }
        arsort($results);
        return ['data' => $results];
    }
}
