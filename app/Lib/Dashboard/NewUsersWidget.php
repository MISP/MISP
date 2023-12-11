<?php

class NewUsersWidget
{
    public $title = 'New users';
    public $render = 'Index';
    public $width = 7;
    public $height = 6;
    public $description = 'A list of the latest new users.';
    private $tableDescription = null;
    public $cacheLifetime = null;
    public $autoRefreshDelay = false;
    public $params = [
        'limit' => 'Maximum number of joining users shown. (integer, defaults to 10 if not set)',
        'filter' => 'A list of filters for the organisations (nationality, sector, type, name, uuid) to include. (dictionary, prepending values with ! uses them as a negation)',
        'days' => 'How many days back should the list go - for example, setting 7 will only show the organisations that were added in the past 7 days. (integer)',
        'month' => 'Which organisations have been added this month? (boolean)',
        'previous_month' => 'Who contributed most the previous, finished month? (boolean)',
        'year' => 'Which organisations have been added this year? (boolean)',
        'start_date' => 'The ISO 8601 date format at which to start',
        'end_date' => 'The ISO 8601 date format at which to end. (Leave empty for today)',
        'fields' => 'Which fields should be displayed, by default all are selected. Pass a list with the following options: [id, email, Organisation.name, Role.name, date_created]'
    ];
    private $validFilterKeys = [
        'id',
        'email',
        'Organisation.name',
        'Role.name',
        'date_created'
    ];

    public $placeholder =
        '{
    "limit": 10,
    "filter": {
       "Organisation.name": [
            "!FSB",
            "!GRU",
            "!Kaspersky"
       ],
       "email": [
            "!andras.iklody@circl.lu"
       ],
       "Role.name": [
            "Publisher",
            "User"
       ]
    },
    "year": true
}';

    private $User = null;

    private function timeConditions($options)
    {
        $limit = empty($options['limit']) ? 10 : $options['limit'];
        if (!empty($options['days'])) {
            $condition = strtotime(sprintf("-%s days", $options['days']));
            $this->tableDescription = __('The %d newest users created in the past %d days', $limit, (int)$options['days']);
        } else if (!empty($options['month'])) {
            $condition = strtotime('first day of this month 00:00:00', time());
            $this->tableDescription = __('The %d newest users created during the current month', $limit);
        } else if (!empty($options['previous_month'])) {
            $condition = strtotime('first day of last month 00:00:00', time());
            $end_condition = strtotime('last day of last month 23:59:59', time());
            $this->tableDescription = __('The %d newest organisations created during the previous month', $limit);
        } else if (!empty($options['year'])) {
            $condition = strtotime('first day of this year 00:00:00', time());
            $this->tableDescription = __('The %d newest users created during the current year', $limit);
        } else if (!empty($options['start_date'])) {
            $condition = strtotime($options['start_date'], time());
            $end_condition = [];
            if (empty($options['end_date'])) {
                $end_condition = time();
            } else {
                $end_condition = strtotime($options['end_date'], time());
            }
            $this->tableDescription = __('The %d newest organisations created since %s', $limit, $options['start_date']);
        } else {
            $this->tableDescription = __('The %d newest users created', $limit);
            return null;
        }
        $conditions = [];
        if (!empty($condition)) {
            $datetime = new DateTime();
            $datetime->setTimestamp($condition);
            $conditions['Organisation.date_created >='] = $datetime->format('Y-m-d H:i:s');
        }
        if (!empty($end_condition)) {
            $datetime = new DateTime();
            $datetime->setTimestamp($end_condition);
            $conditions['Organisation.date_created <='] = $datetime->format('Y-m-d H:i:s');
        }
        return $conditions;
    }

    public function handler($user, $options = array())
    {
        $this->User = ClassRegistry::init('User');
        $field_options = [
            'id' => [
                'name' => '#',
                'url' => empty($user['Role']['perm_site_admin']) ? null : Configure::read('MISP.baseurl') . '/admin/users/view',
                'element' => 'links',
                'data_path' => 'User.id',
                'url_params_data_paths' => 'User.id'
            ],
            'date_created' => [
                'name' => 'Creation date',
                'data_path' => 'User.date_created'
            ],
            'email' => [
                'name' => 'E-mail',
                'data_path' => 'User.email',
            ],
            'Organisation.name' => [
                'name' => 'Organisation',
                'data_path' => 'Organisation.name',
            ],
            'Role.name' => [
                'name' => 'Role',
                'data_path' => 'Role.name',
            ]
        ];
        $params = [
            'conditions' => [],
            'limit' => 10,
            'recursive' => -1
        ];
        if (!empty($options['filter']) && is_array($options['filter'])) {
            foreach ($this->validFilterKeys as $filterKey) {
                if (!empty($options['filter'][$filterKey])) {
                    if (!is_array($options['filter'][$filterKey])) {
                        $options['filter'][$filterKey] = [$options['filter'][$filterKey]];
                    }
                    $tempConditionBucket = [];
                    foreach ($options['filter'][$filterKey] as $value) {
                        $filterName = strpos($filterKey, '.') ? $filterKey : 'User.' . $filterKey;
                        if ($value[0] === '!') {
                            $tempConditionBucket[$filterName . ' NOT IN'][] = mb_substr($value, 1);
                        } else {
                            $tempConditionBucket[$filterName . ' IN'][] = $value;
                        }
                    }
                    if (!empty($tempConditionBucket)) {
                        $params['conditions']['AND'][] = $tempConditionBucket;
                    }
                }
            }
        }
        $timeConditions = $this->timeConditions($options);
        if ($timeConditions) {
            $params['conditions']['AND'][] = $timeConditions;
        }
        if (isset($options['fields'])) {
            $fields = [];
            foreach ($options['fields'] as $field) {
                if (isset($field_options[$field])) {
                    $fields[$field] = $field_options[$field];
                }
            }
        } else {
            $fields = $field_options;
        }

        // redact e-mails for non site admins unless specifically allowed
        if (
            empty($user['Role']['perm_site_admin']) &&
            !Configure::read('Security.disclose_user_emails') &&
            isset($fields['email'])
        ) {
                unset($fields['email']);
        }
        $data = $this->User->find('all', [
            'recursive' => -1,
            'contain' => ['Organisation.name', 'Role.name'],
            'conditions' => $params['conditions'],
            'limit' => isset($options['limit']) ? $options['limit'] : 10,
            'fields' => array_keys($fields),
            'order' => 'User.date_created DESC'
        ]);

        foreach ($data as &$u) {
            if (empty($u['User']['date_created'])) {
                continue;
            }
            $tempDate = new DateTime();
            $tempDate->setTimestamp($u['User']['date_created']);
            $u['User']['date_created'] = $tempDate->format('Y-m-d H:i:s');
        }

        return [
            'data' => $data,
            'fields' => $fields,
            'description' => $this->tableDescription
        ];
    }
}
