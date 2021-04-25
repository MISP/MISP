<?php


class UsersEvolutionWidget
{
    public $title = 'Evolution of user count';
    public $render = 'MultiLineChart';
    public $width = 7;
    public $height = 6;
    public $description = 'A graph to show the evolution of total users over time';
    public $cacheLifetime = 10;
    public $autoRefreshDelay = false;
    public $params = array(
        'days' => 'Number of days to consider for the graph, takes priority over months and weeks. There will be a data entry for each day. Value between 1 and 180.',
        'weeks' => 'Number of days to consider for the graph, takes priority over months. There will be a data entry for each week. Value between 1 and 180.',
        'months' => 'Number of days to consider for the graph. There will be a data entry for each month. Value between 1 and 180.',
    );

    public $placeholder =
        '{
    "days": "30"
}';

    public function handler($user, $options = array())
    {
        $this->User = ClassRegistry::init('User');

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
            $item = array();
            $item['date'] = strftime('%Y-%m-%d', $itemTime);
            $item['users'] = $this->usersAtTime($itemTime);
            $data['data'][] = $item;
        }

        return $data;
    }

    private function usersAtTime($time)
    {
        return $this->User->find('count', array(
            'recursive' => -1,
            'conditions' => array(
                'OR' => array(
                    array('date_created' => null),
                    array('date_created <=' => $time),
                )
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
