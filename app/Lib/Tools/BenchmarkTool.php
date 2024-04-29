<?php

/**
 * Get filter parameters from index searches
 */

class BenchmarkTool
{
    /** @var Model */
    public $Model;
    
    /** @var redis */
    public $redis;

    /** @var retention */
    private $retention = 0;

    const BENCHMARK_SCOPES = ['user', 'endpoint', 'user_agent'];
    const BENCHMARK_FIELDS = ['time', 'sql_time', 'sql_queries', 'memory'];
    const BENCHMARK_UNITS = [
        'time' => 's',
        'sql_time' => 'ms',
        'sql_queries' => '',
        'memory' => 'MB'
    ];

    public $namespace = 'misp:benchmark:';

    function __construct(Model $model) {
        $this->Model = $model;
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
        $start_time = microtime(true);
        $this->redis = $this->Model->setupRedis();
        $this->retention = Configure::check('Plugin.benchmark_retention') ? Configure::read('Plugin.benchmark_retention') : 0;
        return $start_time;
    }

    public function stopBenchmark(array $options)
    {
        $start_time = $options['start_time'];
        if (!empty($options['user'])) {
            $sql = $this->Model->getDataSource()->getLog(false, false);
            $benchmarkData = [
                'user' => $options['user'],
                'endpoint' => $options['controller'] . '/' . $options['action'],
                'user_agent' => $_SERVER['HTTP_USER_AGENT'],
                'sql_queries' => $sql['count'],
                'sql_time' => $sql['time'],
                'time' => (microtime(true) - $start_time),
                'memory' => (int)(memory_get_peak_usage(true) / 1024 / 1024),
                //'date' => date('Y-m-d', strtotime("-3 days"))
                'date' => date('Y-m-d')
            ];
            $this->pushBenchmarkDataToRedis($benchmarkData);
        } else {
            $sql = $this->Model->getDataSource()->getLog(false, false);
            $benchmarkData = [
                'user' => 'SYSTEM',
                'endpoint' => $options['controller'] . '/' . $options['action'],
                'user_agent' => 'CLI',
                'sql_queries' => $sql['count'],
                'sql_time' => $sql['time'],
                'time' => (microtime(true) - $start_time),
                'memory' => (int)(memory_get_peak_usage(true) / 1024 / 1024),
                //'date' => date('Y-m-d', strtotime("-3 days"))
                'date' => date('Y-m-d')
            ];
            $this->pushBenchmarkDataToRedis($benchmarkData);
        }
    }

    private function pushBenchmarkDataToRedis($benchmarkData)
    {
        $this->redis = $this->Model->setupRedis();
        $this->redis->pipeline();
        $this->redis->sAdd(
            $this->namespace . 'days',
            $benchmarkData['date']
        );
        foreach (self::BENCHMARK_SCOPES as $scope) {
            $this->redis->sAdd(
                $this->namespace . $scope . ':list',
                $benchmarkData[$scope]
            );
            $this->redis->zIncrBy(
                $this->namespace . $scope . ':count:' . $benchmarkData['date'],
                1,
                $benchmarkData[$scope]
            );
            foreach (self::BENCHMARK_FIELDS as $field) {
                $this->redis->zIncrBy(
                    $this->namespace . $scope . ':' . $field . ':' . $benchmarkData['date'],
                    $benchmarkData[$field],
                    $benchmarkData[$scope]
                );
            }
            $this->redis->zIncrBy(
                $this->namespace . $scope . ':endpoint:' . $benchmarkData['date'] . ':' . $benchmarkData['user'],
                1,
                $benchmarkData['endpoint']
            );
        }
        $this->redis->exec();
    }

    public function getTopList(string $scope, string $field, array $days = [], $limit = 10, $average = false, $aggregate = false)
    {
        if (empty($this->redis)) {
            $this->redis = $this->Model->setupRedis();
        }
        $results = [];
        if (is_string($days)) {
            $days = [$days];
        }
        foreach ($days as $day) {
            $temp = $this->redis->zrevrange($this->namespace . $scope . ':' . $field . ':' . $day, 0, $limit, true);
            foreach ($temp as $k => $v) {
                if ($average) {
                    $divisor = $this->redis->zscore($this->namespace . $scope . ':count:' . $day, $k);
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
        if (empty($this->redis)) {
            $this->redis = $this->Model->setupRedis();
        }
        if ($days === null) {
            $days = $this->redis->smembers($this->namespace . 'days');
        }
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
