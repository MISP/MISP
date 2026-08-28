<?php


class UsersEvolutionWidget
{
    public $title = 'Evolution of user count';
    public $category = 'system';
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
    public $schema = array();

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

        // Users without a creation date are counted in every bucket, exactly as the
        // previous per-bucket `date_created IS NULL OR date_created <= $time` condition did.
        $undatedUsers = $this->User->find('count', array(
            'recursive' => -1,
            'conditions' => array('date_created' => null)
        ));
        $creationTimes = $this->User->find('column', array(
            'recursive' => -1,
            'conditions' => array('NOT' => array('date_created' => null)),
            'fields' => array('User.date_created')
        ));
        $creationTimes = array_map('intval', $creationTimes);
        sort($creationTimes);

        $data = array();
        $data['data'] = array();
        // $itemTime strictly decreases with every iteration, so a single backwards
        // moving pointer yields the number of users created at or before each bucket.
        $pointer = count($creationTimes);
        // Add total users data for all timestamps
        for ($i = 0; $i < $limit; $i++) {
            $itemTime = strtotime('- ' . $i . $delta, $endOfDay);
            while ($pointer > 0 && $creationTimes[$pointer - 1] > $itemTime) {
                $pointer--;
            }
            $item = array();
            $item['date'] = strftime('%Y-%m-%d', $itemTime);
            $item['users'] = $undatedUsers + $pointer;
            $data['data'][] = $item;
        }

        return $data;
    }

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
