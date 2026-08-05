<?php

/**
 * Logins widget (dashboard v2).
 *
 * Top users by login count in the configured date range — site-admin
 * surface for "who's been active here lately".  Reuses UserList
 * (DD-35) for the row contract: avatar (org-logo / initials chip) +
 * email + org·role meta + count badge + drilldown to user view.
 *
 * Reworked from SimpleList to UserList in DD-42.  Data source is
 * unchanged: a `Log.action='login'` aggregation grouped by user_id,
 * with a second User->find resolving org + role for the renderer.
 *
 * Site-admin only.
 */
class LoginsWidget
{
    public $title = 'Logins';
    public $category = 'system';
    public $render = 'UserList';
    public $width = 3;
    public $height = 4;
    public $params = [
        'filter' => 'A list of filters by organisation meta information (sector, type, nationality, id, uuid) to include. (dictionary, prepending values with ! uses them as a negation)',
        'limit' => 'Limits the number of displayed users. (-1 will list all) Default: -1',
        'days' => 'How many days back should the list go - for example, setting 7 will only show logins in the past 7 days. (integer)',
        'month' => 'Who logged in most this month? (boolean)',
        'previous_month' => 'Who logged in most the previous, finished month? (boolean)',
        'year' => 'Who logged in most this year? (boolean)',
        'start_date' => 'The ISO 8601 date format at which to start',
        'end_date' => 'The ISO 8601 date format at which to end. (Leave empty for today)',
    ];
    public $schema = [
        'filter' => [
            'type' => 'org_meta_filter',
            'help' => 'Filter by organisation meta-data (sector, type, nationality, id, uuid). Each entry may have "!" prefix to negate.',
        ],
        'date_range' => [
            'type' => 'date_range',
            'help' => 'Date range covering the login window. Canonical 1-to-N expansion writes top-level start_date / end_date keys at translate time — legacy configs with those keys keep working unchanged.',
        ],
    ];
    public $description = 'Top users by login count in the configured date range. Site-admin only.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 600;

    /** @var User */
    private $User = null;
    /** @var Log */
    private $Log = null;

    private function getDates($options)
    {
        if (!empty($options['days'])) {
            $begin = date('Y-m-d H:i:s', strtotime(sprintf("-%s days", $options['days'])));
        } else if (!empty($options['month'])) {
            $begin = date('Y-m-d H:i:s', strtotime('first day of this month 00:00:00', time()));
        } else if (!empty($options['previous_month'])) {
            $begin = date('Y-m-d H:i:s', strtotime('first day of last month 00:00:00', time()));
            $end = date('Y-m-d H:i:s', strtotime('last day of last month 23:59:59', time()));
        } else if (!empty($options['year'])) {
            $begin = date('Y-m-d', strtotime('first day of this year 00:00:00', time()));
        } else if (!empty($options['start_date'])) {
            $begin = date($options['start_date']);
            $end = [];
            if (!empty($options['end_date'])) {
                $end = date($options['end_date']);
            }
        } else {
            $begin = date('Y-m-d H:i:s', strtotime('-7 days', time()));
        }
        $params = [];
        if (!empty($end)) {
            $params['Log.created <='] = $end;
        }
        if (!empty($begin)) {
            $params['Log.created >='] = $begin;
        }
        return $params;
    }

    public function handler($user, $options = array())
    {
        $this->User = ClassRegistry::init('User');
        $this->Log = ClassRegistry::init('Log');
        $conditions = $this->getDates($options);
        $conditions['Log.action'] = 'login';
        // Cake's `AS Log__count` alias needs a matching virtualField
        // declaration to land in $log['Log']['count']. Carried from
        // the pre-DD-42 handler verbatim.
        $this->Log->virtualFields['count'] = 0;

        $logs = $this->Log->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['Log.user_id', 'COUNT(Log.id) AS Log__count'],
            'group' => ['Log.user_id'],
        ]);
        $counts = [];
        foreach ($logs as $log) {
            $uid = (int)$log['Log']['user_id'];
            if ($uid > 0) {
                $counts[$uid] = (int)$log['Log']['count'];
            }
        }
        arsort($counts);

        if (empty($counts)) {
            return [[
                'type' => 'header',
                'value' => __('No logins in this period.'),
            ]];
        }

        $users = $this->User->find('all', [
            'recursive' => -1,
            'conditions' => ['User.id' => array_keys($counts)],
            'fields' => ['User.id', 'User.email'],
            'contain' => [
                'Organisation' => ['fields' => ['id', 'name', 'uuid']],
                'Role' => ['fields' => ['name']],
            ],
        ]);
        $byId = [];
        foreach ($users as $u) {
            $byId[(int)$u['User']['id']] = $u;
        }

        $total = array_sum($counts);
        $userCount = count($counts);
        // Compose the header from two separate __n calls so each
        // number gets its own plural agreement (a single combined
        // __n key only switches plural on the first number).
        $usersLabel  = sprintf(__n('%d user',  '%d users',  $userCount), $userCount);
        $loginsLabel = sprintf(__n('%d login', '%d logins', $total),     $total);
        $rows = [[
            'type' => 'header',
            'value' => $usersLabel . ' · ' . $loginsLabel,
        ]];
        foreach ($counts as $uid => $count) {
            $u = isset($byId[$uid]) ? $byId[$uid] : null;
            if (!$u) {
                // User was deleted between the login and now; surface
                // the count so the total still reconciles but flag the
                // row as a deleted account.
                $rows[] = [
                    'type' => 'user',
                    'name' => sprintf(__('user #%d (deleted)'), $uid),
                    'meta' => '',
                    'badge' => $count,
                    'muted' => true,
                ];
                continue;
            }
            $orgName = isset($u['Organisation']['name']) ? (string)$u['Organisation']['name'] : '';
            $roleName = isset($u['Role']['name']) ? (string)$u['Role']['name'] : '';
            $metaParts = array_values(array_filter([$orgName, $roleName], 'strlen'));
            $rows[] = [
                'type' => 'user',
                'name' => (string)$u['User']['email'],
                'meta' => implode(' · ', $metaParts),
                'badge' => $count,
                'org' => [
                    'id' => isset($u['Organisation']['id']) ? (int)$u['Organisation']['id'] : null,
                    'name' => $orgName,
                    'uuid' => isset($u['Organisation']['uuid']) ? (string)$u['Organisation']['uuid'] : '',
                ],
                'drilldown' => '/admin/users/view/' . (int)$uid,
            ];
        }
        return $rows;
    }

    public function checkPermissions($user)
    {
        return !empty($user['Role']['perm_site_admin']);
    }
}
