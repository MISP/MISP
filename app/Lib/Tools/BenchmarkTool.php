<?php

/**
 * Get filter parameters from index searches
 */

class BenchmarkTool
{
    /** @var Model */
    public $Model;

    /** @var int days, 0 keeps everything */
    private $retention = 0;

    /** @var Redis */
    private $redis;

    const BENCHMARK_SCOPES = ['user', 'endpoint', 'user_agent'];
    const BENCHMARK_FIELDS = ['time', 'sql_time', 'sql_queries', 'memory'];
    const BENCHMARK_UNITS = [
        'time' => 's',
        'sql_time' => 'ms',
        'sql_queries' => '',
        'memory' => 'MB'
    ];

    const NAMESPACE = 'misp:benchmark:';

    function __construct(Model $model)
    {
        $this->Model = $model;
        $this->redis = RedisTool::init();
        $this->retention = (int)Configure::read('Plugin.Benchmarking_retention');
    }

    public function getSettings()
    {
        return [
            'scope' => self::BENCHMARK_SCOPES,
            'field' => self::BENCHMARK_FIELDS,
            'average' => [0, 1],
            'aggregate' => [0, 1]
        ];
    }

    public function getUnits()
    {
        return self::BENCHMARK_UNITS;
    }

    public function startBenchmark()
    {
        return microtime(true);
    }

    public function stopBenchmark(array $options)
    {
        $startTime = $options['start_time'];
        $sql = $this->Model->getDataSource()->getLog(false, false);

        if (!empty($options['user'])) {
            $benchmarkData = [
                'user' => $options['user'],
                'endpoint' => $options['controller'] . '/' . $options['action'],
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                'sql_queries' => $sql['count'],
                'sql_time' => isset($options['sql_time']) ? $options['sql_time'] : $sql['time'],
                'time' => (microtime(true) - $startTime),
                'memory' => (int)(memory_get_peak_usage(true) / 1024 / 1024),
                //'date' => date('Y-m-d', strtotime("-3 days"))
                'date' => date('Y-m-d')
            ];
        } else {
            $benchmarkData = [
                'user' => 'SYSTEM',
                'endpoint' => $options['controller'] . '/' . $options['action'],
                'user_agent' => 'CLI',
                'sql_queries' => $sql['count'],
                'sql_time' => $sql['time'],
                'time' => (microtime(true) - $startTime),
                'memory' => (int)(memory_get_peak_usage(true) / 1024 / 1024),
                //'date' => date('Y-m-d', strtotime("-3 days"))
                'date' => date('Y-m-d')
            ];
        }
        $this->pushBenchmarkDataToRedis($benchmarkData);
    }

    private function pushBenchmarkDataToRedis($benchmarkData)
    {
        $date = $benchmarkData['date'];
        $dayKeys = [];
        $pipeline = $this->redis->pipeline();
        $pipeline->sAdd(
            self::NAMESPACE . 'days',
            $date
        );
        foreach (self::BENCHMARK_SCOPES as $scope) {
            $pipeline->sAdd(
                self::NAMESPACE . $scope . ':list',
                $benchmarkData[$scope]
            );
            $pipeline->zIncrBy(
                $dayKeys[] = self::NAMESPACE . $scope . ':count:' . $date,
                1,
                $benchmarkData[$scope]
            );
            foreach (self::BENCHMARK_FIELDS as $field) {
                $pipeline->zIncrBy(
                    $dayKeys[] = self::NAMESPACE . $scope . ':' . $field . ':' . $date,
                    $benchmarkData[$field],
                    $benchmarkData[$scope]
                );
            }
            $pipeline->zIncrBy(
                $dayKeys[] = self::NAMESPACE . $scope . ':endpoint:' . $date . ':' . $benchmarkData['user'],
                1,
                $benchmarkData['endpoint']
            );
        }
        if ($this->retention > 0) {
            $expireAt = strtotime($date . ' +' . $this->retention . ' days');
            foreach ($dayKeys as $key) {
                $pipeline->expireAt($key, $expireAt);
            }
        }
        $pipeline->exec();
    }

    /**
     * Every day collection actually wrote something for, oldest first.
     *
     * Records outlive the plugin being switched off, so a view needs this to
     * tell "never collected" apart from "collected until <date>, then stopped".
     *
     * @return array
     */
    public function getRecordedDays()
    {
        $days = $this->liveDays();
        sort($days);
        return $days;
    }

    /**
     * The recorded days still within the retention; expired ones leave the set.
     *
     * @return array
     */
    private function liveDays()
    {
        $days = $this->redis->smembers(self::NAMESPACE . 'days') ?: [];
        if ($this->retention > 0) {
            $cutoff = date('Y-m-d', strtotime('-' . $this->retention . ' days'));
            $expired = array_filter($days, fn($day) => $day <= $cutoff);
            if (!empty($expired)) {
                $this->redis->sRem(self::NAMESPACE . 'days', ...$expired);
                $days = array_values(array_diff($days, $expired));
            }
        }
        return $days;
    }

    public function getTopList(string $scope, string $field, array $days = [], $limit = 10, $average = false, $aggregate = false)
    {
        $results = [];
        if (is_string($days)) {
            $days = [$days];
        }
        foreach ($days as $day) {
            $temp = $this->redis->zrevrange(self::NAMESPACE . $scope . ':' . $field . ':' . $day, 0, $limit, true);
            foreach ($temp as $k => $v) {
                if ($average) {
                    $divisor = $this->redis->zscore(self::NAMESPACE . $scope . ':count:' . $day, $k);
                    // zscore answers false for a member the count set never saw.
                    if (empty($divisor)) {
                        continue;
                    }
                    if ($aggregate) {
                        $results['aggregate'][$k] = empty($results['aggregate'][$k]) ? ($v / $divisor) : ($results['aggregate'][$k] + ($v / $divisor));
                    } else {
                        $results[$day][$k] = round($v / $divisor, 3);
                    }
                } else {
                    if ($aggregate) {
                        $results['aggregate'][$k] = empty($results['aggregate'][$k]) ? $v : ($results['aggregate'][$k] + $v);
                    } else {
                        $results[$day][$k] = $v;
                    }
                }
            }
        }
        if ($aggregate && $average && !empty($results['aggregate'])) {
            $count_days = max(1, count($days));
            foreach ($results['aggregate'] as $k => $result) {
                $results['aggregate'][$k] = round($result / $count_days, 3);
            }
        }
        return $results;
    }

    public function getAllTopLists(?array $days = null, $limit = 10, $average = false, $aggregate = false, $scope_filter = [])
    {
        if ($days === null) {
            $days = $this->liveDays();
        }
        $results = [];
        foreach (self::BENCHMARK_SCOPES as $scope) {
            if (empty($scope_filter) || in_array($scope, $scope_filter)) {
                foreach (self::BENCHMARK_FIELDS as $field) {
                    $results[$scope][$field] = $this->getTopList($scope, $field, $days, $limit, $average, $aggregate);
                }
            }
        }
        return $results;
    }
}
