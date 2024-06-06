<?php


class BenchmarkTopListWidget
{
    public $title = 'Benchmark top list';
    public $render = 'MultiLineChart';
    public $width = 3;
    public $height = 3;
    public $description = 'A graph showing the top list for a given scope and field in the captured metrics.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 30;
    public $params = array(
        'days' => 'Number of days to consider for the graph. There will be a data entry for each day (assuming the benchmarking has been enabled). Defaults to returning all data.',
        'weeks' => 'Number of weeks to consider for the graph. There will be a data entry for each day (assuming the benchmarking has been enabled). Defaults to returning all data.',
        'months' => 'Number of months to consider for the graph. There will be a data entry for each day (assuming the benchmarking has been enabled). Defaults to returning all data.',
        'scope' => 'The scope of the benchmarking refers to what was being tracked. The following scopes are valid: user, endpoint, user_agent',
        'field' => 'The individual metric to be queried from the benchmark results. Valid values are: time, sql_time, sql_queries, memory, endpoint',
        'average' => 'If you wish to view the averages per scope/field, set this variable to true. It will divide the result by the number of executions recorded for the scope/field combination for the given day.'
    );
    public $Benchmark;
    public $User;

    public $placeholder =
        '{
    "days": "30",
    "scope": "endpoints",
    "field": "sql_time"
}';

    public function handler($user, $options = array())
    {
        $this->User = ClassRegistry::init('User');
        $currentTime = strtotime("now");
        $endOfDay = strtotime("tomorrow", $currentTime) - 1;
        if (!empty($options['days'])) {
            $limit = (int)($options['days']);
            $delta = 'day';
        } else if (!empty($options['weeks'])) {
            $limit = (int)($options['weeks']);
            $delta = 'week';
        } else if (!empty($options['months'])) {
            $limit = (int)($options['months']);
            $delta = 'month';
        } else {
            $limit = 30;
            $delta = 'day';
        }
        $axis_info = [
            'time' => 'Total time taken (ms)',
            'sql_time' => 'SQL time taken (ms)',
            'sql_queries' => 'Queries (#)',
            'memory' => 'Memory (MB)',
            'endpoint' => 'Queries to endpoint (#)'
        ];
        $y_axis = $axis_info[isset($options['field']) ? $options['field'] : 'time'];
        $data = ['y-axis' => $y_axis];
        $data['data'] = array();
        // Add total users data for all timestamps
        
        for ($i = 0; $i < $limit; $i++) {
            $itemTime = strtotime('- ' . $i . $delta, $endOfDay);
            $item = array();
            $date = strftime('%Y-%m-%d', $itemTime);
            $item = $this->getData($date, $options);
            if (!empty($item)) {
                $item['date'] = $date;
                $data['data'][] = $item;
            }
        }
        $keys = [];
        foreach ($data['data'] as $day_data) {
            foreach ($day_data as $key => $temp) {
                $keys[$key] = 1;
            }
        }
        $keys = array_keys($keys);
        foreach ($data['data'] as $k => $day_data) {
            foreach ($keys as $key) {
                if (!isset($day_data[$key])) {
                    $data['data'][$k][$key] = 0;
                }
            }
            foreach ($day_data as $key => $temp) {
                $keys[$key] = 1;
            }
        }
        return $data;
    }

    private function getData($time, $options)
    {
        $dates = [$time];
        $this->Benchmark = new BenchmarkTool($this->User);
        $result = $this->Benchmark->getTopList(
            isset($options['scope']) ? $options['scope'] : 'endpoint',
            isset($options['field']) ? $options['field'] : 'memory',
            $dates,
            isset($options['limit']) ? $options['limit'] : 5,
            isset($options['average']) ? $options['average'] : false,
        );
        if (!empty($result)) {
            return $result[$time];
        }
        return false;
    }

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
