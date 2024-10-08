<?php

/**
 * Get filter parameters from index searches
 */

class BenchmarkTool
{
    /** @var Model */
    public $Model;

    /** @var int */
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
        $startTime = microtime(true);
        $this->retention = Configure::check('Plugin.benchmark_retention') ? Configure::read('Plugin.benchmark_retention') : 0;
        return $startTime;
    }

    public function stopBenchmark(array $options)
    {
        $startTime = $options['start_time'];
        $sql = $this->Model->getDataSource()->getLog(false, false);

        if (!empty($options['user'])) {
            $benchmarkData = [
                'user' => $options['user'],
                'endpoint' => $options['controller'] . '/' . $options['action'],
                'user_agent' => $_SERVER['HTTP_USER_AGENT'],
                'sql_queries' => $sql['count'],
                'sql_time' => $sql['time'],
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
        $pipeline = $this->redis->pipeline();
        $pipeline->sAdd(
            self::NAMESPACE . 'days',
            $benchmarkData['date']
        );
        foreach (self::BENCHMARK_SCOPES as $scope) {
            $pipeline->sAdd(
                self::NAMESPACE . $scope . ':list',
                $benchmarkData[$scope]
            );
            $pipeline->zIncrBy(
                self::NAMESPACE . $scope . ':count:' . $benchmarkData['date'],
                1,
                $benchmarkData[$scope]
            );
            foreach (self::BENCHMARK_FIELDS as $field) {
                $pipeline->zIncrBy(
                    self::NAMESPACE . $scope . ':' . $field . ':' . $benchmarkData['date'],
                    $benchmarkData[$field],
                    $benchmarkData[$scope]
                );
            }
            $pipeline->zIncrBy(
                self::NAMESPACE . $scope . ':endpoint:' . $benchmarkData['date'] . ':' . $benchmarkData['user'],
                1,
                $benchmarkData['endpoint']
            );
        }
        $pipeline->exec();
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
                    if ($aggregate) {
                        $results['aggregate'][$k] = empty($results['aggregate'][$k]) ? ($v / $divisor) : ($results['aggregate'][$k] + ($v / $divisor));
                    } else {
                        $results[$day][$k] = (int)($v / $divisor);
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
        if ($aggregate && $average) {
            $count_days = count($days);
            foreach ($results['aggregate'] as $k => $result) {
                $results['aggregate'][$k] = (int)($result / $count_days);
            }
        }
        return $results;
    }

    public function getAllTopLists(array $days = null, $limit = 10, $average = false, $aggregate = false, $scope_filter = [])
    {
        if ($days === null) {
            $days = $this->redis->smembers(self::NAMESPACE . 'days');
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
