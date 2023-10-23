<?php

class APIActivityWidget
{
    public $title = 'API Activity';
    public $render = 'SimpleList';
    public $width = 2;
    public $height = 2;
    public $params = [
        'filter' => 'A list of filters by organisation meta information (sector, type, nationality, id, uuid) to include. (dictionary, prepending values with ! uses them as a negation)',
        'limit' => 'Limits the number of displayed APIkeys. (-1 will list all) Default: -1',
        'days' => 'How many days back should the list go - for example, setting 7 will only show contributions in the past 7 days. (integer)',
        'month' => 'Who contributed most this month? (boolean)',
        'previous_month' => 'Who contributed most the previous, finished month? (boolean)',
        'year' => 'Which contributed most this year? (boolean)',
        'start_date' => 'The ISO 8601 date format at which to start',
        'end_date' => 'The ISO 8601 date format at which to end. (Leave empty for today)',
    ];
    public $description = 'Basic widget showing some server statistics in regards to MISP.';
    public $cacheLifetime = 10;
    public $autoRefreshDelay = null;
    private $User = null;
    private $AuthKey = null;


    private function getDates($options)
    {
        if (!empty($options['days'])) {
            $begin = new DateTime(date('Y-m-d', strtotime(sprintf("-%s days", $options['days']))));
        } else if (!empty($options['month'])) {
            $begin = new DateTime(date('Y-m-d', strtotime('first day of this month 00:00:00', time())));
        } else if (!empty($options['previous_month'])) {
            $begin = new DateTime(date('Y-m-d', strtotime('first day of last month 00:00:00', time())));
            $end = new DateTime(date('Y-m-d', strtotime('last day of last month 23:59:59', time())));
        } else if (!empty($options['year'])) {
            $begin = new DateTime(date('Y-m-d', strtotime('first day of this year 00:00:00', time())));
        } else if (!empty($options['start_date'])) {
            $begin = new DateTime($options['start_date']);
            if (!empty($options['end_date'])) {
                $end = new DateTime($options['end_date']);
            }
        } else {
            $begin = new DateTime(date('Y-m-d', strtotime('-7 days', time())));;
        }

        $end = isset($end) ? $end : new DateTime();
        $dates = new DatePeriod(
            $begin,
            new DateInterval('P1D'),
            $end
        );
        $results = [];
        foreach ($dates as $date) {
            $results[] = $date->format('Ymd');
        }
        return $results;
    }

	public function handler($user, $options = array())
	{
        $this->User = ClassRegistry::init('User');
        $this->AuthKey = ClassRegistry::init('AuthKey');
        $redis = $this->User->setupRedis();
        if (!$redis) {
            throw new NotFoundException(__('No redis connection found.'));
        }

        $params = ['conditions' => []];
        $dates = $this->getDates($options);
        $pipe = $redis->pipeline();
        foreach ($dates as $date) {
            $pipe->zrange('misp:authkey_log:' . $date, 0, -1, true);
        }
        $temp = $pipe->exec();
        $raw_results = [];
        $counts = [];
        foreach ($dates as $k => $date) {
            $raw_results[$date] = $temp[$k];
            if (!empty($temp[$k])) {
                foreach ($temp[$k] as $key => $count) {
                    if (isset($counts[$key])) {
                        $counts[$key] += (int)$count;
                    } else {
                        $counts[$key] = (int)$count;
                    }
                }
            }
        }
        arsort($counts);
        $this->AuthKey->Behaviors->load('Containable');
        $temp_apikeys = array_flip(array_keys($counts));
        foreach ($temp_apikeys as $apikey => $value) {
            $temp_apikeys[$apikey] = $this->AuthKey->find('first', [
                'conditions' => [
                    'AuthKey.authkey_start' => substr($apikey, 0, 4),
                    'AuthKey.authkey_end' => substr($apikey, 4)
                ],
                'fields' => ['AuthKey.authkey_start', 'AuthKey.authkey_end', 'AuthKey.id', 'User.id', 'User.email'],
                'recursive' => 1
            ]);
        }
        $results = [];
        $baseurl = empty(Configure::read('MISP.external_baseurl')) ? h(Configure::read('MISP.baseurl')) : Configure::read('MISP.external_baseurl');
        foreach ($counts as $key => $junk) {
            $data = $temp_apikeys[$key];
            if (!empty($data)) {
                $results[] = [
                    'html_title' => sprintf(
                        '<a href="%s/auth_keys/view/%s">%s</a>',
                        h($baseurl),
                        h($data['AuthKey']['id']),
                        $key
                    ),
                    'html' => sprintf(
                        '%s (<a href="%s/admin/users/view/%s">%s</a>)',
                        h($counts[$key]),
                        h($baseurl),
                        h($data['User']['id']),
                        h($data['User']['email'])
                    )
                ];
            } else {
                $results[] = [
                    'title' => $key,
                    'html' => sprintf(
                        '%s (<span class="red" title="%s">%s</span>)',
                        h($counts[$key]),
                        __('An unknown key can be caused by the given key having been permanently deleted or falsely mis-identified (for the purposes of this widget) on instances using legacy API key authentication.'),
                        __('Unknown key')
                    )
                ];
            }
        }
        return $results;
	}

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
