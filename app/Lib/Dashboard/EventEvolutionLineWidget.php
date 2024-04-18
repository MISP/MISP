<?php

class EventEvolutionLineWidget
{
    public $title = 'Evolution of published event count (filterable)';
    public $render = 'MultiLineChart';
    public $width = 7;
    public $height = 6;
    public $description = 'A linechart of event publishes.';
    public $cacheLifetime = null;
    public $autoRefreshDelay = false;
    public $params = [
        'filter' => 'A list of filters by organisation meta information (nationality, sector, type, name, uuid) to include. (dictionary, prepending values with ! uses them as a negation)',
        'start_date' => 'Start date, expressed in Y-m-d format (e.g. 2012-10-01)',
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
    private $Event = null;

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
        $this->Event = ClassRegistry::init('Event');
        $isCumulative = isset($options['cumulative']) && empty($options['cumulative']);
        $oparams = [
            'conditions' => [
                'AND' => ['Organisation.local' => !isset($options['local']) ? 1 : $options['local']]
            ],
            'limit' => 10,
            'recursive' => -1
        ];
        $eparams = [];
        $filteringOnOrg = false;
        if (!empty($options['filter']) && is_array($options['filter'])) {
            foreach ($this->validFilterKeys as $filterKey) {
                if (!empty($options['filter'][$filterKey])) {
                    $filteringOnOrg = true;
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
                        $oparams['conditions']['AND'][] = $tempConditionBucket;
                    }
                }
            }
        }
        $timeConditions = $this->timeConditions($options);
        if ($timeConditions) {
            $eparams['conditions']['AND'][] = ['Event.publish_timestamp >=' => strtotime($timeConditions)];
        }
        $org_ids = $this->Organisation->find('list', [
            'recursive' => -1,
            'conditions' => $oparams['conditions'],
            'fields' => ['id']
        ]);
        if ($filteringOnOrg) {
            $eparams['conditions']['AND']['Event.orgc_id IN'] = !empty($org_ids) ? $org_ids : [-1];
        }
        $this->Event->virtualFields = [
            'published_date' => null
        ];
        $raw = $this->Event->find('all', [
            'recursive' => -1,
            'conditions' => $eparams['conditions'],
            'fields' => ['DATE_FORMAT(FROM_UNIXTIME(Event.publish_timestamp), "%Y-%m") AS date', 'count(id) AS count'],
            'group' => ['MONTH(FROM_UNIXTIME(Event.publish_timestamp)), YEAR(FROM_UNIXTIME(Event.publish_timestamp))', 'DATE_FORMAT(FROM_UNIXTIME(Event.publish_timestamp), "%Y-%m")']
            
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
              'Events' => (int)$count,
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
