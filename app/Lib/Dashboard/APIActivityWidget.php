<?php

/**
 * API Activity widget (dashboard v2).
 *
 * Top API keys by request count in the configured date range, with
 * their owner.  Site-admin surface for "which keys are hot, and is
 * anything unrecognised hitting the API."
 *
 * Reworked from SimpleList to UserList in DD-42.  Data source is
 * unchanged: a Redis pipeline reads `misp:authkey_log:<YYYYMMDD>`
 * zranges per day, sums the counts, then looks up each key's owner
 * via the AuthKey model.  Per-row contract:
 *   - Known key  : avatar = owner org logo / initials chip; name =
 *                  owner email; meta = "key <prefix> · <role>"; badge
 *                  = count; drilldown = /auth_keys/view/<id>
 *                  (drilldown points at the KEY so admin can revoke
 *                  / inspect; owner identity is in the primary line).
 *   - Unknown key: DD-41 glyph slot, token = 'warn'; name = key
 *                  prefix; meta = "Unknown key"; badge = count;
 *                  muted = true.  An unknown key can be left over
 *                  from a permanently-deleted entry or a legacy-auth
 *                  mis-identification on instances using legacy
 *                  API-key authentication.
 *
 * Site-admin only.
 */
class APIActivityWidget
{
    public $title = 'API Activity';
    public $category = 'system';
    public $render = 'UserList';
    public $width = 3;
    public $height = 4;
    public $params = [
        'filter' => 'A list of filters by organisation meta information (sector, type, nationality, id, uuid) to include. (dictionary, prepending values with ! uses them as a negation)',
        'limit' => 'Limits the number of displayed APIkeys. (-1 will list all) Default: -1',
        'days' => 'How many days back should the list go - for example, setting 7 will only show API activity in the past 7 days. (integer)',
        'month' => 'Which keys were busiest this month? (boolean)',
        'previous_month' => 'Which keys were busiest the previous, finished month? (boolean)',
        'year' => 'Which keys were busiest this year? (boolean)',
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
            'help' => 'Date range covering the activity window. Canonical 1-to-N expansion writes top-level start_date / end_date keys at translate time — legacy configs with those keys keep working unchanged.',
        ],
    ];
    public $description = 'Top API keys by request count in the configured date range, with their owner. Site-admin only.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 30;

    /** @var User */
    private $User = null;
    /** @var AuthKey */
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
            $begin = new DateTime(date('Y-m-d', strtotime('-7 days', time())));
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

        $dates = $this->getDates($options);
        $pipe = $redis->pipeline();
        foreach ($dates as $date) {
            $pipe->zrange('misp:authkey_log:' . $date, 0, -1, true);
        }
        $temp = $pipe->exec();
        $counts = [];
        foreach ($dates as $k => $date) {
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

        if (empty($counts)) {
            return [[
                'type' => 'header',
                'value' => __('No API activity in this period.'),
            ]];
        }

        // Look up each key in AuthKey.  authkey_start is the first 4
        // chars of the live key, authkey_end the last 4 — both stored
        // for legacy-auth bookkeeping.
        $this->AuthKey->Behaviors->load('Containable');
        $resolved = [];
        foreach (array_keys($counts) as $apikey) {
            $resolved[$apikey] = $this->AuthKey->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'AuthKey.authkey_start' => substr($apikey, 0, 4),
                    'AuthKey.authkey_end' => substr($apikey, 4),
                ],
                'fields' => [
                    'AuthKey.id', 'AuthKey.authkey_start', 'AuthKey.authkey_end',
                    'AuthKey.user_id',
                ],
                'contain' => [
                    'User' => [
                        'fields' => ['User.id', 'User.email'],
                        'Organisation' => ['fields' => ['id', 'name', 'uuid']],
                        'Role' => ['fields' => ['name']],
                    ],
                ],
            ]);
        }

        $unknownCount = 0;
        foreach ($resolved as $apikey => $data) {
            if (empty($data)) {
                $unknownCount++;
            }
        }
        $total = array_sum($counts);
        $keyCount = count($counts);
        // Compose the header from separate __n calls so each number
        // gets its own plural agreement (combined __n only plurals
        // the first number).
        $keysLabel = sprintf(__n('%d key', '%d keys', $keyCount), $keyCount);
        $reqLabel  = sprintf(__n('%d request', '%d requests', $total), $total);
        $header = $keysLabel . ' · ' . $reqLabel;
        if ($unknownCount > 0) {
            $header .= ' · ' . sprintf(__n('%d unknown', '%d unknown', $unknownCount), $unknownCount);
        }

        $rows = [[
            'type' => 'header',
            'value' => $header,
        ]];

        foreach ($counts as $apikey => $count) {
            $data = isset($resolved[$apikey]) ? $resolved[$apikey] : null;
            if (empty($data)) {
                // Unknown — DD-41 glyph slot carries the "this is
                // anomalous" signal; legacy <span class="red"> +
                // native-title-tooltip pattern is dropped.
                $rows[] = [
                    'type' => 'user',
                    'glyph' => 'warn',
                    'name' => (string)$apikey,
                    'meta' => __('Unknown key — left over from a deleted entry, or legacy-auth mis-identification'),
                    'badge' => $count,
                    'muted' => true,
                ];
                continue;
            }
            $owner = isset($data['User']) ? $data['User'] : [];
            $email = isset($owner['email']) ? (string)$owner['email'] : '';
            $orgName = isset($owner['Organisation']['name']) ? (string)$owner['Organisation']['name'] : '';
            $roleName = isset($owner['Role']['name']) ? (string)$owner['Role']['name'] : '';
            $keyPrefix = isset($data['AuthKey']['authkey_start']) ? (string)$data['AuthKey']['authkey_start'] : substr($apikey, 0, 4);
            $metaParts = array_values(array_filter([
                'key ' . $keyPrefix,
                $orgName,
                $roleName,
            ], 'strlen'));
            $rows[] = [
                'type' => 'user',
                'name' => $email !== '' ? $email : (__('user #%d', isset($owner['id']) ? (int)$owner['id'] : 0)),
                'meta' => implode(' · ', $metaParts),
                'badge' => $count,
                'org' => [
                    'id' => isset($owner['Organisation']['id']) ? (int)$owner['Organisation']['id'] : null,
                    'name' => $orgName,
                    'uuid' => isset($owner['Organisation']['uuid']) ? (string)$owner['Organisation']['uuid'] : '',
                ],
                'drilldown' => '/auth_keys/view/' . (int)$data['AuthKey']['id'],
            ];
        }
        return $rows;
    }

    public function checkPermissions($user)
    {
        return !empty($user['Role']['perm_site_admin']);
    }
}
