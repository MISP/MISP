<?php

class CsseCovidMapWidget
{
    public $title = 'CSSE Covid-19 map';
    public $category = 'custom';
    public $render = 'WorldMap';
    public $width = 3;
    public $height = 4;
    public $params = array(
        'event_info' => 'World map based on the countries with infections.',
        'type' => 'Type of data used for the widget (confirmed, death, recovered).',
        'logarithmic' => 'Use a log10 scale for the graph (set via 0/1).'
    );
    public $schema = array();
    public $description = 'Widget mapping the countries showing confirmed cases of COVID-19.';
    public $placeholder =
'{
    "event_info": "%CSSE COVID-19 daily report%",
    "type": "confirmed",
    "logarithmic": 1
}';

    public $countryCodes = array();
    public $countryCodesReversed = array();

    public function handler($user, $options = array())
    {
        App::uses('WidgetToolkit', 'Lib/Dashboard/Tools');
        $WidgetToolkit = new WidgetToolkit();
        $this->countryCodes = $WidgetToolkit->getCountryCodeMapping();
        $this->countryCodesReversed = array_flip($this->countryCodes);
        $this->Event = ClassRegistry::init('Event');
        $event_info_condition = empty($options['event_info']) ? '%CSSE COVID-19 daily report%' : $options['event_info'];
        $params = array(
            'eventinfo' => $event_info_condition,
            'order' => 'date desc',
            'limit' => 1,
            'page' => 1
        );
        $eventIds = $this->Event->filterEventIds($user, $params);
        $params['eventid'] = $eventIds;
        $data = array();
        if (empty($options['type'])) {
            $options['type'] = 'confirmed';
        }
        if (!empty($eventIds)) {
            $events = $this->Event->fetchEvent($user, $params);
            $data = $this->__handleEvents($events, $options);
            arsort($data);
        }
        $data = array('data' => $data);
        if (!empty($options['type']) && $options['type'] === 'mortality') {
            $data['output_decorator'] = 'percentage';
        }
        if (!empty($options['logarithmic'])) {
            $data['logarithmic'] = array();
            foreach ($data['data'] as $k => $v) {
                if ($v == 0) {
                    $value = 0;
                } else if ($v <= 1) {
                    $value = 0.2;
                } else {
                    $value = log10($v);
                }
                $data['logarithmic'][$k] = $value;
            }
        }
        $data['scope'] = Inflector::humanize($options['type']);
        $data['colour_scale'] = json_encode(array('#F08080', '#8B0000'), true);
        return $data;
    }

    private function __handleEvents($events, $options)
    {
        $data = array();
        if (!empty($events)) {
            foreach ($events as $event) {
                if (!empty($event['Object'])) {
                    $data = $this->__handleObjects($data, $event['Object'], $options);
                }
            }
        }
        return $data;
    }

    private function __handleObjects($data, $objects, $options)
    {
        foreach ($objects as $object) {
            if ($object['name'] === 'covid19-csse-daily-report') {
                $temp = $this->__interpretObject($object);
                $data = $this->__rearrangeResults($data, $temp, $options);
            }
        }
        if ($options['type'] === 'mortality') {
            foreach ($data as $k => $v) {
                $data[$k] = round(100 * (empty($v['death']) ? 0 : $v['death']) / $v['confirmed'], 2);
            }
        }
        return $data;
    }

    private function __rearrangeResults($data, $temp, $options)
    {
        $country = $temp['country-region'];
        $type = $options['type'];
        if (!empty($temp[$type])) {
            $data[$country] = (empty($data[$country]) ? $temp[$type] : ($data[$country] + $temp[$type]));
        }
        return $data;
    }

    private function __interpretObject($object)
    {
        $temp = array();
        $validFields = array('country-region', 'confirmed', 'death', 'recovered');
        foreach ($object['Attribute'] as $attribute) {
            if (in_array($attribute['object_relation'], $validFields)) {
                if ($attribute['object_relation'] === 'country-region') {
                    if (!empty($this->countryCodes[$attribute['value']])) {
                        $temp[$attribute['object_relation']] = $this->countryCodes[$attribute['value']];
                    } elseif (isset($this->countryCodesReversed[$attribute['value']])) {
                        $temp[$attribute['object_relation']] = $attribute['value'];
                    } else {
                        $temp[$attribute['object_relation']] = 'XX';
                    }
                } else {
                    $attribute['value'] = intval($attribute['value']);
                    $temp[$attribute['object_relation']] = $attribute['value'];
                }
            }
        }
        return $temp;
    }
}
