<?php

class CsseCovidTrendsWidget
{
    public $title = 'CSSE Covid-19 trends';
    public $render = 'MultiLineChart';
    public $width = 4;
    public $height = 5;
    public $params = array(
        'event_info' => 'Substring included in the info field of relevant CSSE COVID-19 events.',
        'type' => 'Type of data used for the widget - confirmed (default), death, recovered, mortality, active.',
        'insight' => 'Insight type - raw (default), growth, percent.',
        'countries' => 'List of countries to be included (using the names used by the reports, such as Belgium, US, Germany).',
        'timeframe' => 'Timeframe for events taken into account in days (going back from now, using the date field, default 10).'
    );
    public $description = 'Widget showing line charts for the evolution of the various case types.';
    public $placeholder =
'{
    "event_info": "%CSSE COVID-19 daily report%",
    "type": "confirmed",
    "insight": "raw",
    "countries": ["Luxembourg", "Germany", "Belgium", "France"],
    "timeframe": 20
}';

    private $__countryAliases = array(
        'Mainland China' => 'China',
        'Korea, South' => 'South Korea'
    );

    public $cacheLifetime = 600;
    public $autoRefreshDelay = false;

    private $__countries = array();

    public function handler($user, $options = array())
    {
        $this->Event = ClassRegistry::init('Event');
        if (!isset($options['insight']) || !isset($this->__insightFunctions[$options['insight']])) {
            $options['Insight'] = 'calculate_growth_rate';
        }
        if (empty($options['timeframe'])) {
            $options['timeframe'] = 10;
        }
        if (empty($options['countries'])) {
            $options['countries'] = array("Luxembourg", "Germany", "Belgium", "France");
        }
        if (empty($options['insight'])) {
            $options['insight'] = 'raw';
        }
        $event_info_condition = empty($options['event_info']) ? '%CSSE COVID-19 daily report%' : $options['event_info'];
        $params = array(
            'eventinfo' => $event_info_condition,
            'order' => 'date desc',
            'date' => (empty($options['timeframe']) ? 10 : $options['timeframe']) . 'd'
        );
        $eventIds = $this->Event->filterEventIds($user, $params);
        $eventIds = array_reverse($eventIds);
        $data = array();
        if (empty($options['type'])) {
            $options['type'] = 'confirmed';
        }
        if (!empty($eventIds)) {
            $previous = false;
            foreach ($eventIds as $eventId) {
                $params = array('eventid' => $eventId);
                $event = $this->Event->fetchEvent($user, $params);
                if (!empty($event)) {
                    $data[$event[0]['Event']['date']] = $this->__handleEvent($event[0], $options, $previous);
                }
                $previous = $data[$event[0]['Event']['date']];
            }
        }
        $startDate = date('Y-m-d', strtotime('-' . intval($options['timeframe']) . ' days'));
        //$data = call_user_func_array((array($this, $this->__insightFunctions[$options['Insight']]), array($startDate));
        $data = array('data' => $data);
        $data['insight'] = empty($options['insight']) ? 'raw' : $options['insight'];
        foreach ($data['data'] as $date => $day) {
            $data['data'][$date]['date'] = $date;
            foreach ($this->__countries as $country => $temp) {
                if (empty($data['data'][$date][$country][$data['insight']])) {
                    $data['data'][$date][$country][$data['insight']] = 0;
                }
            }
        }
        $data['data'] = array_values($data['data']);
        $formulaData = array(
            'insight' => array(
                'raw' => '',
                'growth' => 'daily increase in ',
                'percent' => 'percentage wise daily increase in '
            ),
            'type' => array(
                'confirmed' => 'confirmed cases',
                'death' => 'mortalities',
                'recovered' => 'recoveries',
                'mortality' => 'mortality rate',
                'active' => 'active cases'
            )
        );
        $data['formula'] = sprintf(
            '%s%s',
            (isset($options['insight']) && !empty($formulaData[$options['insight']])) ?
                $formulaData['insight'][$options['insight']] :
                $formulaData['insight']['raw'],
            (isset($options['type']) && !empty($formulaData['type'][$options['type']])) ?
                $formulaData['type'][$options['type']] :
                $formulaData['type']['confirmed']
        );
        $data['formula'] = ucfirst($data['formula']);
        foreach ($data['data'] as &$day) {
            foreach ($day as $key => &$countryData) {
                if ($key !== 'date') {
                    $countryData = $countryData[$options['insight']];
                }
            }
        }
        return $data;
    }

    private function __handleEvent($event, $options, $previous)
    {
        $data = array();
        if (!empty($event['Object'])) {
            $data = $this->__handleObjects($data, $event['Object'], $options, $previous);
        }
        $data['date'] = $event['Event']['date'];
        return $data;
    }

    private function __handleObjects($data, $objects, $options, $previous)
    {
        foreach ($objects as $object) {
            if ($object['name'] === 'covid19-csse-daily-report') {
                $temp = $this->__interpretObject($object, $previous);
                $data = $this->__rearrangeResults($data, $temp, $options, $previous);
            }
        }
        if ($options['type'] === 'mortality') {
            foreach ($data as $k => $v) {
                $data[$k]['mortality'] = round(100 * (empty($v['death']) ? 0 : $v['death']) / $v['confirmed'], 2);
            }
        }
        if (!empty($options['insight']) && $options['insight'] !== 'raw') {
            if ($options['insight'] == 'growth') {
                foreach ($data as $k => $countryData) {
                    foreach ($countryData as $type => &$value) {
                        if (!isset($previous[$k][$type])) {
                            $previous[$k][$type] = $data[$k][$type];
                        }
                        $data[$k]['growth'] = $data[$k][$type] - $previous[$k][$type];
                    }
                }
            } else if ($options['insight'] == 'percent') {
                foreach ($data as $k => $countryData) {
                    foreach ($countryData as $type => &$value) {
                        if (empty($previous[$k][$type])) {
                            $previous[$k][$type] = $data[$k][$type];
                        }
                        if (!empty($previous[$k][$type])) {
                            $data[$k]['percent'] = 100 * ($data[$k][$type] - $previous[$k][$type]) / $previous[$k][$type];
                        }
                    }
                }
            }
        } else {
            foreach ($data as $k => &$countryData) {
                $data[$k]['raw'] = $data[$k][$options['type']];
            }
        }
        return $data;
    }

    private function __rearrangeResults($data, $temp, $options, $previous)
    {
        $country = $temp['country-region'];
        if (!in_array($country, $options['countries'])) {
            return $data;
        }
        $this->__countries[$country] = 1;
        if ($options['type'] === 'mortality') {
            foreach (array('confirmed', 'death') as $type) {
                if (!empty($temp[$type])) {
                    $data[$country][$type] = (empty($data[$country][$type]) ? $temp[$type] : ($data[$country][$type] + $temp[$type]));
                }
            }
        } else if ($options['type'] === 'active') {
            if (empty($data[$country]['active'])) {
                $data[$country]['active'] = 0;
            }
            $data[$country]['active'] =
                $data[$country]['active'] +
                (empty($temp['confirmed']) ? 0 : $temp['confirmed']) -
                (empty($temp['death']) ? 0 : $temp['death']) -
                (empty($temp['recovered']) ? 0 : $temp['recovered']);
        } else {
            $type = $options['type'];
            if (!empty($temp[$type])) {
                $data[$country][$type] = (empty($data[$country][$type]) ? $temp[$type] : ($data[$country][$type] + $temp[$type]));
            }
        }
        return $data;
    }

    private function __interpretObject($object, $previous)
    {
        $temp = array();
        $validFields = array('country-region', 'confirmed', 'death', 'recovered');
        foreach ($object['Attribute'] as $attribute) {
            if (in_array($attribute['object_relation'], $validFields)) {
                if ($attribute['object_relation'] !== 'country-region') {
                    $attribute['value'] = intval($attribute['value']);
                } else {
                    if (isset($this->__countryAliases[$attribute['value']])) {
                        $attribute['value'] = $this->__countryAliases[$attribute['value']];
                    }
                }
                $temp[$attribute['object_relation']] = $attribute['value'];
            }
        }
        return $temp;
    }
}
