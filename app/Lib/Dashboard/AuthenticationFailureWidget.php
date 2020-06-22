<?php

class AuthenticationFailureWidget
{
    public $title = 'Authentication Failure Data';
    public $render = 'BarChart';
    public $width = 3;
    public $height = 10;
    public $params = array(
        'event_info' => 'Substring included in the info field of relevant Authentication Failure events.',
        'type' => 'Type of data used for the widget (sshd, etc.).'
    );
    public $description = 'Widget visualising authentication failures collected in d4.';
    public $placeholder =
'{
    "event_info": "%Authentication Failure Daily Event%",
    "type": "sshd",
    "absciss": "username"
}';

    public function handler($user, $options = array())
    {
        $this->Event = ClassRegistry::init('Event');
        $event_info_condition = empty($options['event_info']) ? '%Authentication Failure Daily Event%' : $options['event_info'];
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
            $options['type'] = 'sshd';
        }
        if (empty($options['absciss'])) {
            $options['absciss'] = 'username';
        }
        if (!empty($eventIds)) {
            $events = $this->Event->fetchEvent($user, $params);
            $data = $this->__handleEvents($events, $options);
            arsort($data);
        }

        $data = array('data' => $data);

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
            if ($object['name'] === 'authentication-failure-report') {
                $temp = $this->__interpretObject($object);
                $data = $this->__rearrangeResults($data, $temp, $options);
            }
        }

        return $data;
    }

    private function __rearrangeResults($data, $temp, $options)
    {
        $target = $temp[$options['absciss']];
        $type = $options['type'];
        if ($temp['type'] === $type || $type === 'all' ) {
            $data[$target] = $temp['total'];
        }

        return $data;
    }

    private function __interpretObject($object)
    {
        $temp = array();
        $validFields = array('type', 'username', 'total', 'ip-dst', 'ip-src');
        foreach ($object['Attribute'] as $attribute) {
            if (in_array($attribute['object_relation'], $validFields)) {
                if ($attribute['object_relation'] == 'total') {
                    $attribute['value'] = (int)($attribute['value']);
                }
                $temp[$attribute['object_relation']] = $attribute['value'];
            }
        }

        return $temp;
    }
}
