<?php

class OrgEvolutionLineWidget
{
    public $title = 'Evolution of orgs count (filterable)';
    public $render = 'MultiLineChart';
    public $width = 7;
    public $height = 6;
    public $description = 'A linechart of organisations joining.';
    private $tableDescription = null;
    public $cacheLifetime = null;
    public $autoRefreshDelay = false;
    public $params = [
        'filter' => 'A list of filters by organisation meta information (nationality, sector, type, name, uuid) to include. (dictionary, prepending values with ! uses them as a negation)',
        'start_date' => 'Start date, expressed in Y-m-d format (e.g. 2012-10-01)',
        'local' => 'Should the list only show local organisations? (boolean or list of booleans, defaults to 1. To get both sets, use [0,1])',
        'cumulative' => '(default: on), should the data counted cumulatively over time',
    ];
    private $validFilterKeys = [
        'nationality',
        'sector',
        'type',
        'name',
        'uuid'
    ];

    public $placeholder =
        '{
    "filter": {
        "sector": "financial"
    },
    "start_date": "2017-01",
}';

    private $Organisation = null;

    private function timeConditions($options)
    {
        if (!empty($options['start_date'])) {
            $condition = strtotime($options['start_date']);
        } else {
            $condition = strtotime('2012-10-01');
        }
        $datetime = new DateTime();
        $datetime->setTimestamp($condition);
        return $datetime->format('Y-m-d H:i:s');
    }

    public function handler($user, $options = array())
    {
        $this->Organisation = ClassRegistry::init('Organisation');
        $isCumulative = isset($options['cumulative']) && empty($options['cumulative']);
        $params = [
            'conditions' => [
                'AND' => ['Organisation.local' => !isset($options['local']) ? 1 : $options['local']]
            ],
            'limit' => 10,
            'recursive' => -1
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
        $timeConditions = $this->timeConditions($options);
        if ($timeConditions) {
            $params['conditions']['AND'][] = ['Organisation.date_created >=' => $timeConditions];
        }
        $raw = $this->Organisation->find('all', [
            'recursive' => -1,
            'conditions' => $params['conditions'],
            'fields' => ['DATE_FORMAT(date_created, "%Y-%m") AS date', 'count(id) AS count'],
            'group' => ['MONTH(date_created), YEAR(date_created)', 'date']
            
        ]);
        usort($raw, [$this, 'sortByCreationDate']);
        $raw_padded = [];
        $total = 0;
        $default_start_date = empty($raw) ? '2012-10-01' : ($raw[0][0]['date'] . '-01');
        $start = new DateTime(empty($options['start_date']) ? $default_start_date : $options['start_date']);
        $end = new DateTime(date('Y-m') . '-01');
        $interval = DateInterval::createFromDateString('1 month');
        $period = new DatePeriod($start, $interval, $end);
        foreach ($period as $dt) {
            $raw_padded[$dt->format('Y-m') . '-01'] = 0;
        }
        foreach ($raw as $datapoint) {
            $raw_padded[$datapoint[0]['date'] . '-01'] = (int)$datapoint[0]['count'];
        }
        $total = 0;
        foreach ($raw_padded as $date => $count) {
            $total += $count;
            if ($isCumulative) {
                $raw_padded[$date] = $count;
            } else {
                $raw_padded[$date] = $total;
            }
        }
        $data = [];
        foreach ($raw_padded as $date => $count) {
            $data['data'][] = [
              'Organisations' => (int)$count,
              'date' => $date
            ];
        }
        return $data;
    }

    private function sortByCreationDate($a, $b) {
        if ($a[0]['date'] > $b[0]['date']) { 
            return 1;
        } else {
            return -1;
        }
        return 0;
    }
}
