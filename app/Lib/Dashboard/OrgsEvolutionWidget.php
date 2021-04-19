<?php

class OrgsEvolutionWidget
{
    public $title = 'Evolution of orgs count';
    public $render = 'MultiLineChart';
    public $width = 7;
    public $height = 6;
    public $description = 'A graph to show the evolution of total users over time. The distinction between remote and local org for all datapoints is based on the current state as there is no historical data for it.';
    public $cacheLifetime = 10;
    public $autoRefreshDelay = false;
    public $params = array(
        'days' => 'Number of days to consider for the graph, takes priority over months and weeks. There will be a data entry for each day. Value between 1 and 180.',
        'weeks' => 'Number of days to consider for the graph, takes priority over months. There will be a data entry for each week. Value between 1 and 180.',
        'months' => 'Number of days to consider for the graph. There will be a data entry for each month. Value between 1 and 180.',
    );

    public $placeholder =
        '{
    "days": "30",
    "widget_config": {
        "enable_total": "1"
    }
}';

    public function handler($user, $options = array())
    {
        $this->Organisation = ClassRegistry::init('Organisation');

        $currentTime = strtotime("now");
        $endOfDay = strtotime("tomorrow", $currentTime) - 1;
        if (!empty($options['days'])) {
            $limit = (int)($options['days']);
            $delta = 'day';
        } else if (!empty($options['weeks'])) {
            $limit = (int)($options['weeks']);
            $delta = 'week';
        } else if (!empty($options['months'])) {
            $limit = (int)($options['months']);
            $delta = 'month';
        } else {
            $limit = 30;
            $delta = 'day';
        }

        if ($limit <= 0 || $limit > 180) {
            throw new InvalidArgumentException("Number of days, weeks or months must be a number between 1 and 180.");
        }

        $data = array();
        $data['data'] = array();
        // Add total users data for all timestamps
        for ($i = 0; $i < $limit; $i++) {
            $itemTime = strtotime('- ' . $i . $delta, $endOfDay);
            //Separate time for db query as date_created is stored in DateTime string
            $itemTimeDateTime = date('Y-m-d H:i:s', $itemTime);
            $item = array();
            $item['date'] = strftime('%Y-%m-%d', $itemTime);
            $item['local orgs'] = $this->localOrgsAtTime($itemTimeDateTime);
            $item['remote orgs'] = $this->remoteOrgsAtTime($itemTimeDateTime);
            $data['data'][] = $item;
        }

        return $data;
    }

    private function localOrgsAtTime($time)
    {
        return $this->Organisation->find('count', array(
            'recursive' => -1,
            'conditions' => array(
                'date_created <=' => $time,
                'local' => 1
            )
        ));
    }

    private function remoteOrgsAtTime($time)
    {
        return $this->Organisation->find('count', array(
            'recursive' => -1,
            'conditions' => array(
                'date_created <=' => $time,
                'local' => 0
            )
        ));
    }

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
