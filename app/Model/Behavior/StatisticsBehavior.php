<?php

class StatisticsBehavior extends ModelBehavior
{
    public function getStatisticsUsageForModel(Model $Model, array $scopes, array $options = []): array
    {
        $defaultOptions = [
            'limit' => 5,
            'includeOthers' => true,
            'ignoreNull' => true,
        ];
        $options = $this->getOptions($defaultOptions, $options);
        $stats = [];
        foreach ($scopes as $scope) {
            $conditions = $Model->getColumnType($scope) == 'boolean' ? 
                [
                    "{$Model->name}.{$scope} IS NOT NULL",
                    "{$Model->name}.{$scope} != ''"
                ]:
                [];
            $queryTopUsage = [
                'fields' => [
                    "{$Model->name}.{$scope}",
                    "COUNT({$Model->name}.id) as c"
                ],
                'conditions' => $conditions,
                'group' => [$scope],
                'order' => ['c' => 'DESC'],
                'limit' => $options['limit'],
                'page' => 1
            ];
            $topUsage = [];
            $temp = $Model->find('all', $queryTopUsage);
            foreach($temp as $element) {
                $topUsage[$element[$Model->name][$scope]] = intval($element[0]['c']);
            }
            $stats[$scope] = $topUsage;
            if (
                !empty($options['includeOthers']) && !empty($topUsage) &&
                $Model->getColumnType($scope) == 'boolean'  // No need to get others as we only have 2 possibilities already considered
            ) {
                if (!empty($options['ignoreNull'])) {
                    $conditions = [
                        "{$Model->name}.{$scope} IS NOT NULL",
                        "{$Model->name}.{$scope} != ''",
                        "{$Model->name}.{$scope} NOT IN" => array_keys($topUsage)
                    ];
                } else {
                    $conditions = [
                        'OR' => [
                            [
                                "{$Model->name}.{$scope} NOT IN" => array_keys($topUsage)
                            ],
                            [
                                "{$Model->name}.{$scope} IS NULL"
                            ],
                            [
                                "{$Model->name}.{$scope} = ''"
                            ]
                        ]
                        
                    ];
                }
                $othersUsage = $Model->find('all', [
                    'fields' => [
                        "COUNT({$Model->name}.id) as c"
                    ],
                    'conditions' => $conditions
                ]);
                if (!empty($othersUsage)) {
                    $stats[$scope][] = [
                        $scope => __('Others'),
                        'count' => $othersUsage[0]['c'],
                    ];
                }
            }
        }
        return $stats;
    }

    private function getOptions($defaults = [], $options = []): array
    {
        return array_merge($defaults, $options);
    }

    // Move this into a tool
    public function getActivityStatisticsForModel(object $table, int $days = 30): array
    {
        $statistics = [];
        if ($table->hasBehavior('Timestamp')) {
            if ($table->getSchema()->getColumnType('created') == 'datetime') {
                $statistics['created'] = $this->getActivityStatistic($table, $days, 'created');
            }
            if ($table->getSchema()->getColumnType('modified') == 'datetime') {
                $statistics['modified'] = $this->getActivityStatistic($table, $days, 'modified');
            }
        }
        return $statistics;
    }

    public function getActivityStatistic(Model $Model, int $days = 30, string $field = 'modified', bool $includeTimeline = true): array
    {
        $statistics = [];
        $statistics['days'] = $days;
        $statistics['amount'] = $table->find()->all()->count();
        if ($table->behaviors()->has('Timestamp') && $includeTimeline) {
            $statistics['timeline'] = $this->buildTimeline($table, $days, $field);
            $statistics['variation'] = $table->find()->where(["{$field} >" => FrozenTime::now()->subDays($days)])->all()->count();
        } else {
            $statistics['timeline'] = [];
            $statistics['variation'] = 0;
        }
        return $statistics;
    }

    public function buildTimeline(Model $Model, int $days = 30, string $field = 'modified'): array
    {
        $timeline = [];
        $authorizedFields = ['modified', 'created'];
        if ($table->behaviors()->has('Timestamp')) {
            if (!in_array($field, $authorizedFields)) {
                throw new MethodNotAllowedException(__('Cannot construct timeline for field `{0}`', $field));
            }
            $days = $days - 1;
            $query = $table->find();
            $query->select(
                [
                    'count' => $query->func()->count('id'),
                    'date' => "DATE({$field})",
                ]
            )
                ->where(["{$field} >" => FrozenTime::now()->subDays($days)])
                ->group(['date'])
                ->order(['date']);
            $data = $query->all()->toArray();
            $interval = new \DateInterval('P1D');
            $period = new \DatePeriod(FrozenTime::now()->subDays($days), $interval, FrozenTime::now()->addDays(1));
            foreach ($period as $date) {
                $timeline[$date->format("Y-m-d")] = [
                    'time' => $date->format("Y-m-d"),
                    'count' => 0
                ];
            }
            foreach ($data as $entry) {
                $timeline[$entry->date]['count'] = $entry->count;
            }
            $timeline = array_values($timeline);
        }
        return $timeline;
    }
}
