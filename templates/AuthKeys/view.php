<?php
$keyUsageCsv = null;
if (isset($keyUsage)) {
    $todayString = date('Y-m-d');
    $today = strtotime($todayString);
    $startDate = key($keyUsage); // oldest date for sparkline
    $startDate = strtotime($startDate) - (3600 * 24 * 3);
    $keyUsageCsv = 'Date,Close\n';
    for ($date = $startDate; $date <= $today; $date += (3600 * 24)) {
        $dateAsString = date('Y-m-d', $date);
        $keyUsageCsv .= $dateAsString . ',' . (isset($keyUsage[$dateAsString]) ? $keyUsage[$dateAsString] : 0) . '\n';
    }
} else {
    $lastUsed = null;
    $uniqueIps = null;
}

echo $this->element(
    'genericElements/SingleViews/single_view',
    [
    'title' => 'Auth key view',
    'data' => $entity,
    'fields' => [
        [
            'key' => __('ID'),
            'path' => 'id'
        ],
        [
            'key' => __('UUID'),
            'path' => 'uuid',
        ],
        [
            'key' => __('Auth Key'),
            'path' => 'AuthKey',
            'type' => 'authkey'
        ],
        [
            'key' => __('User'),
            'path' => 'User.id',
            'pathName' => 'User.email',
            'model' => 'users',
            'type' => 'model'
        ],
        [
            'key' => __('Comment'),
            'path' => 'comment'
        ],
        [
            'key' => __('Allowed IPs'),
            'type' => 'custom',
            'function' => function (\App\Model\Entity\AuthKey $authKey) {
                if (is_array($authKey->allowed_ips)) {
                    return implode("<br />", array_map('h', $authKey->allowed_ips));
                }
                return __('All');
            }
        ],
        [
            'key' => __('Created'),
            'path' => 'created',
            'type' => 'datetime'
        ],
        [
            'key' => __('Expiration'),
            'path' => 'expiration',
            'type' => 'expiration'
        ],
        [
            'key' => __('Read only'),
            'path' => 'read_only',
            'type' => 'boolean'
        ],
        [
            'key' => __('Key usage'),
            'type' => 'sparkline',
            'path' => 'id',
            'csv' => [
                'data' => $keyUsageCsv,
            ],
            'requirement' => isset($keyUsage),
        ],
        [
            'key' => __('Last used'),
            'raw' => $lastUsed ? $this->Time->time($lastUsed) : __('Not used yet'),
            'requirement' => isset($keyUsage),
        ],
        [
            'key' => __('Seen IPs'),
            'path' => 'unique_ips',
            'type' => 'authkey_pin'
        ]
    ],
    ]
);
