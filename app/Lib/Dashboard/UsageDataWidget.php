<?php
class UsageDataWidget
{
    public $title = 'Usage data';
    public $render = 'SimpleList';
    public $width = 2;
    public $height = 5;
    public $description = 'Shows usage data / statistics.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = false;
    public $params = [
        'filter' => 'A list of filters by organisation meta information (nationality, sector, type, name, uuid) to include. (dictionary, prepending values with ! uses them as a negation)',
        'start_date' => 'The ISO 8601 date format for which to show changes',
        'end_date' => 'The ISO 8601 date format for which to show changes. (Leave empty for today)',
    ];
    private $User = null;
    private $Event = null;
    private $Correlation = null;
    private $Thread = null;
    private $AuthKey = null;
    private $redis = null;
    
    private $validFilterKeys = [
        'nationality',
        'sector',
        'type',
        'name',
        'uuid'
    ];

    private $validFields = [
        'Events',
        'Attributes',
        'Attributes / event',
        'Correlations',
        'Active proposals',
        'Users',
        'Users with PGP keys',
        'Organisations',
        'Local organisations',
        'Event creator orgs',
        'Average users / org',
        'Discussion threads',
        'Discussion posts'
    ];

    public function handler($user, $options = array()) {
        $this->User = ClassRegistry::init('User');
        $this->redis = $this->User->setupRedis();
        if (!$this->redis) {
            throw new NotFoundException(__('No redis connection found.'));
        }
        $this->Event = ClassRegistry::init('Event');
        $this->Thread = ClassRegistry::init('Thread');
        $this->Correlation = ClassRegistry::init('Correlation');
        $thisMonth = strtotime('first day of this month');
        $hasDateRange = !empty($options['start_date']);
        $orgConditions = [];
        $orgIdList = null;
        if (!empty($options['filter']) && is_array($options['filter'])) {
            foreach ($this->validFilterKeys as $filterKey) {
                if (!empty($options['filter'][$filterKey])) {
                    if (!is_array($options['filter'][$filterKey])) {
                        $options['filter'][$filterKey] = [$options['filter'][$filterKey]];
                    }
                    $tempConditionBucket = [];
                    foreach ($options['filter'][$filterKey] as $value) {
                        if ($value[0] === '!') {
                            $tempConditionBucket['Organisation.' . $filterKey . ' NOT IN'][] = mb_substr($value, 1);
                        } else {
                            $tempConditionBucket['Organisation.' . $filterKey . ' IN'][] = $value;
                        }
                    }
                    if (!empty($tempConditionBucket)) {
                        $orgConditions[] = $tempConditionBucket;
                    }
                }
            }
            $orgIdList = $this->User->Organisation->find('column', [
                'recursive' => -1,
                'conditions' => $orgConditions,
                'fields' => ['Organisation.id']
            ]);
        }
        $eventsCount = $this->getEventsCount($orgConditions, $orgIdList, $thisMonth);
        $attributesCount = $this->getAttributesCount($orgConditions, $orgIdList, $thisMonth);
        $usersCount = $this->getUsersCount($orgConditions, $orgIdList, $thisMonth);
        $usersCountPgp = $this->getUsersCountPgp($orgConditions, $orgIdList, $thisMonth);
        $localOrgsCount = $this->getLocalOrgsCount($orgConditions, $orgIdList, $thisMonth);


        $threadCount = $this->Thread->find('count', array('conditions' => array('Thread.post_count >' => 0), 'recursive' => -1));
        $threadCountMonth = $this->Thread->find('count', array('conditions' => array('Thread.date_created >' => date("Y-m-d H:i:s", $thisMonth), 'Thread.post_count >' => 0), 'recursive' => -1));

        $postCount = $this->Thread->Post->find('count', array('recursive' => -1));
        $postCountMonth = $this->Thread->Post->find('count', array('conditions' => array('Post.date_created >' => date("Y-m-d H:i:s", $thisMonth)), 'recursive' => -1));

        //Monhtly data is not added to the widget at the moment, could optionally add these later and give user choice?

        $statistics = [
            'Events' => [
                'title' => 'Events',
                'value' => $eventsCount,
                'change' => $hasDateRange ? $this->getEventsCountDateRange($orgConditions, $orgIdList, $options) : $this->getEventsCountMonth($orgConditions, $orgIdList, $thisMonth)
            ],
            'Attributes' => [
                'title' => 'Attributes',
                'value' => $attributesCount,
                'change' => $hasDateRange ? $this->getAttributesCountDateRange($orgConditions, $orgIdList, $options) : $this->getAttributesCountMonth($orgConditions, $orgIdList, $thisMonth)
            ],
            'Attributes / event' => [
                'title' => 'Attributes / event',
                'value' => $eventsCount ? round($attributesCount / $eventsCount) : 0
            ],
            'Correlations' => [
                'title' => 'Correlations',
                'value' => $this->getCorrelationsCount($orgConditions, $orgIdList, $thisMonth)
            ],
            'Active proposals' => [
                'title' => 'Active proposals',
                'value' => $this->getProposalsCount($orgConditions, $orgIdList, $thisMonth)
            ],
            'Users' => [
                'title' => 'Users',
                'value' => $usersCount,
                'change' => $hasDateRange ? $this->getUsersCountDateRange($orgConditions, $orgIdList, $options) : $this->getUsersCountMonth($orgConditions, $orgIdList, $thisMonth)
            ],
            'Users with PGP keys' => [
                'title' => 'Users with PGP keys',
                'value' => sprintf(
                    '%s (%s %%)',
                    $usersCountPgp,
                    $usersCount ? round(100* ($usersCountPgp / $usersCount), 1) : 0
                )
            ],
            'Organisations' => [
                'title' => 'Organisations',
                'value' => $this->getOrgsCount($orgConditions, $orgIdList, $thisMonth),
                'change' => $hasDateRange ? $this->getOrgsCountDateRange($orgConditions, $orgIdList, $options) : $this->getOrgsCountMonth($orgConditions, $orgIdList, $thisMonth)
            ],
            'Local organisations' => [
                'title' => 'Local organisations',
                'value' => $localOrgsCount,
                'change' => $hasDateRange ? $this->getLocalOrgsCountDateRange($orgConditions, $orgIdList, $options) : $this->getLocalOrgsCountMonth($orgConditions, $orgIdList, $thisMonth)
            ],
            'Event creator orgs' => [
                'title' => 'Event creator orgs', 'value' => $this->getContributingOrgsCount($orgConditions, $orgIdList, $thisMonth)
            ],
            'Average users / org' => [
                'title' => 'Average users / org', 'value' => (!empty($localOrgsCount) ? round($usersCount / $localOrgsCount, 1) : 'N/A')
            ],
            'Discussion threads' => [
                'title' => 'Discussions threads',
                'value' => $this->getThreadsCount($orgConditions, $orgIdList, $thisMonth),
                'change' => $hasDateRange ? $this->getThreadsCountDateRange($orgConditions, $orgIdList, $options) : $this->getThreadsCountMonth($orgConditions, $orgIdList, $thisMonth)
            ],
            'Discussion posts' => [
                'title' => 'Discussion posts',
                'value' => $this->getPostsCount($orgConditions, $orgIdList, $thisMonth),
                'change' => $hasDateRange ? $this->getPostsCountDateRange($orgConditions, $orgIdList, $options) : $this->getPostsCountMonth($orgConditions, $orgIdList, $thisMonth)
            ]
        ];
        if(!empty(Configure::read('Security.advanced_authkeys'))){
            $this->AuthKey = ClassRegistry::init('AuthKey');
            $authkeysCount = $this->AuthKey->find('count', array('recursive' => -1));
            $statistics[] = array('title' => 'Advanced authkeys', 'value' => $authkeysCount);
        }
        return $statistics;
    }

    private function prepareDateRangeConditions(array $options, $datefield, $convertToTimestamp = false): array
    {
        $timeConditions = [];
        if (!empty($options['start_date'])) {
            $sd = new DateTime($options['start_date']);
            $timeConditions[sprintf('%s >=', $datefield)] = $convertToTimestamp? $sd->getTimestamp() : $sd->format('Y-m-d H:i:s');
            if (!empty($options['end_date'])) {
                $ed = new DateTime($options['end_date']);
                $timeConditions[sprintf('%s <=', $datefield)] = $convertToTimestamp? $ed->getTimestamp() : $ed->format('Y-m-d H:i:s');
            }
        }
        return $timeConditions;
    }

    private function getEventsCount($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = [];
        if (!empty($orgIdList)) {
            $conditions['AND'][] = ['Event.orgc_id IN' => $orgIdList];
        }
        return $this->Event->find('count', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
    }

    private function getCorrelationsCount($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = [];
        if (!empty($orgIdList)) {
            $conditions['AND']['OR'][] = ['Correlation.org_id IN' => $orgIdList];
            $conditions['AND']['OR'][] = ['Correlation.1_org_id IN' => $orgIdList];
        }
        return $this->Correlation->find('count', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
    }

    private function getEventsCountMonth($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = ['Event.timestamp >' => $thisMonth];
        if (!empty($orgIdList)) {
            $conditions['AND'][] = ['Event.orgc_id IN' => $orgIdList];
        }
        return $this->Event->find('count', [
            'conditions' => $conditions,
            'recursive' => -1
        ]);
    }

    private function getEventsCountDateRange($orgConditions, $orgIdList, $options)
    {
        $conditions = $this->prepareDateRangeConditions($options, 'Event.timestamp', true);
        if (!empty($orgIdList)) {
            $conditions['AND'][] = ['Event.orgc_id IN' => $orgIdList];
        }
        return $this->Event->find('count', [
            'conditions' => $conditions,
            'recursive' => -1
        ]);
    }

    private function getAttributesCount($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = ['Attribute.deleted' => 0];
        if (!empty($orgIdList)) {
            $conditions['AND'][] = ['Event.orgc_id IN' => $orgIdList];
        }
        $hash = hash('sha256', json_encode($orgIdList));
        $count = $this->redis->get('misp:dashboard:attribute_count:' . $hash);
        if (empty($count)) {
            $count = $this->Event->Attribute->find('count', [
                'conditions' => $conditions,
                'contain' => ['Event'],
                'recursive' => -1,
                'ignoreIndexHint' => 'deleted'
            ]);
            $this->redis->setEx('misp:dashboard:attribute_count:' . $hash, 3600, $count);
        }
        return $count;
    }

    private function getAttributesCountMonth($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = ['Attribute.timestamp >' => $thisMonth, 'Attribute.deleted' => 0];
        if (!empty($orgIdList)) {
            $conditions['AND'][] = ['Event.orgc_id IN' => $orgIdList];
        }
        return $this->Event->Attribute->find('count', [
            'conditions' => $conditions,
            'contain' => 'Event.orgc_id',
            'recursive' => -1
        ]);
    }

    private function getAttributesCountDateRange($orgConditions, $orgIdList, $options)
    {
        $conditions = $this->prepareDateRangeConditions($options, 'Attribute.timestamp', true);
        $conditions['Attribute.deleted'] = 0;
        if (!empty($orgIdList)) {
            $conditions['AND'][] = ['Event.orgc_id IN' => $orgIdList];
        }
        return $this->Event->Attribute->find('count', [
            'conditions' => $conditions,
            'contain' => 'Event.orgc_id',
            'recursive' => -1
        ]);
    }

    private function getOrgsCount($orgConditions, $orgIdList, $thisMonth)
    {
        return $this->User->Organisation->find('count', [
            'conditions' => [
                'AND' => $orgConditions
            ]
        ]);
    }

    private function getOrgsCountMonth($orgConditions, $orgIdList, $thisMonth)
    {
        $datetime = new DateTime();
        $datetime->setTimestamp($thisMonth);
        $thisMonth = $datetime->format('Y-m-d H:i:s');
        return $this->User->Organisation->find('count', [
            'conditions' => [
                'AND' => $orgConditions,
                'Organisation.date_created >' => $thisMonth
            ]
        ]);
    }

    private function getOrgsCountDateRange($orgConditions, $orgIdList, $options)
    {
        return $this->User->Organisation->find('count', [
            'conditions' => [
                'AND' => $orgConditions,
                $this->prepareDateRangeConditions($options, 'Organisation.date_created'),
            ]
        ]);
    }

    private function getLocalOrgsCount($orgConditions, $orgIdList, $thisMonth)
    {
        return $this->User->Organisation->find('count', [
            'conditions' => [
                'Organisation.local' => 1,
                'AND' => $orgConditions
            ]
        ]);
    }

    private function getLocalOrgsCountMonth($orgConditions, $orgIdList, $thisMonth)
    {
        $datetime = new DateTime();
        $datetime->setTimestamp($thisMonth);
        $thisMonth = $datetime->format('Y-m-d H:i:s');
        return $this->User->Organisation->find('count', [
            'conditions' => [
                'Organisation.local' => 1,
                'AND' => $orgConditions,
                'Organisation.date_created >' => $thisMonth
            ]
        ]);
    }

    private function getLocalOrgsCountDateRange($orgConditions, $orgIdList, $options)
    {
        return $this->User->Organisation->find('count', [
            'conditions' => [
                'Organisation.local' => 1,
                'AND' => $orgConditions,
                $this->prepareDateRangeConditions($options, 'Organisation.date_created'),
            ]
        ]);
    }

    private function getProposalsCount($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = ['deleted' => 0];
        if (!empty($orgIdList)) {
            $conditions['ShadowAttribute.org_id IN'] = $orgIdList;
        }
        return $this->Event->ShadowAttribute->find('count', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
    }

    private function getUsersCount($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = [];
        if (!empty($orgIdList)) {
            $conditions['User.org_id IN'] = $orgIdList;
        }
        return $this->User->find('count', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
    }

    private function getUsersCountMonth($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = ['User.date_created >' => $thisMonth];
        if (!empty($orgIdList)) {
            $conditions['User.org_id IN'] = $orgIdList;
        }
        return $this->User->find('count', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
    }

    private function getUsersCountDateRange($orgConditions, $orgIdList, $options)
    {
        $conditions = $this->prepareDateRangeConditions($options, 'User.date_created', true);
        if (!empty($orgIdList)) {
            $conditions['User.org_id IN'] = $orgIdList;
        }
        return $this->User->find('count', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
    }

    private function getUsersCountPgp($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = ['User.gpgkey !=' => ''];
        if (!empty($orgIdList)) {
            $conditions['User.org_id IN'] = $orgIdList;
        }
        return $this->User->find('count', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
    }

    private function getContributingOrgsCount($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = [];
        if ($orgConditions) {
            $conditions['AND'][] = ['Event.orgc_id IN' => (!empty($orgIdList) ? $orgIdList : [-1])];
        }
        return $this->Event->find('count', [
            'recursive' => -1,
            'group' => ['Event.orgc_id'],
            'conditions' => $conditions
        ]);
    }

    private function getThreadsCount($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = ['Thread.post_count >' => 0];
        if ($orgConditions) {
            $conditions['AND'][] = ['Thread.org_id IN' => (!empty($orgIdList) ? $orgIdList : [-1])];
        }
        return $this->Thread->find('count', [
            'conditions' => $conditions,
            'recursive' => -1
        ]);
    }

    private function getThreadsCountMonth($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = [
            'Thread.post_count >' => 0,
            'Thread.date_created >=' => $thisMonth
        ];
        if ($orgConditions) {
            $conditions['AND'][] = ['Thread.org_id IN' => (!empty($orgIdList) ? $orgIdList : [-1])];
        }
        return $this->Thread->find('count', [
            'conditions' => $conditions,
            'recursive' => -1
        ]);
    }

    private function getThreadsCountDateRange($orgConditions, $orgIdList, $options)
    {
        $conditions = $this->prepareDateRangeConditions($options, 'Thread.date_created');
        $conditions['Thread.post_count >'] = 0;
        if ($orgConditions) {
            $conditions['AND'][] = ['Thread.org_id IN' => (!empty($orgIdList) ? $orgIdList : [-1])];
        }
        return $this->Thread->find('count', [
            'conditions' => $conditions,
            'recursive' => -1
        ]);
    }

    private function getPostsCount($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = [];
        if ($orgConditions) {
            $conditions['AND'][] = ['User.org_id IN' => (!empty($orgIdList) ? $orgIdList : [-1])];
        }
        return $this->Thread->Post->find('count', [
            'conditions' => $conditions,
            'contain' => ['User.org_id'],
            'recursive' => -1
        ]);
    }

    private function getPostsCountMonth($orgConditions, $orgIdList, $thisMonth)
    {
        $conditions = [
            'Post.date_created >=' => $thisMonth
        ];
        if ($orgConditions) {
            $conditions['AND'][] = ['User.org_id IN' => (!empty($orgIdList) ? $orgIdList : [-1])];
        }
        return $this->Thread->Post->find('count', [
            'conditions' => $conditions,
            'contain' => ['User.org_id'],
            'recursive' => -1
        ]);
    }

    private function getPostsCountDateRange($orgConditions, $orgIdList, $options)
    {
        $conditions = $this->prepareDateRangeConditions($options, 'Post.date_created');
        if ($orgConditions) {
            $conditions['AND'][] = ['User.org_id IN' => (!empty($orgIdList) ? $orgIdList : [-1])];
        }
        return $this->Thread->Post->find('count', [
            'conditions' => $conditions,
            'contain' => ['User.org_id'],
            'recursive' => -1
        ]);
    }

    
/* There is nothing sensitive in here.
    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
*/
}
