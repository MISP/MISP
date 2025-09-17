<?php
App::uses('MysqlExtended', 'Model/Datasource/Database');
App::uses('RedisTool', 'Tools');

/**
 * Overrides the default MySQL database implementation to support the following features:
 * - Set query hints to optimize queries
 */
class MysqlObserverExtended extends MysqlExtended
{
    public $supports = [
        'indexHints' => true,
        'ignoreIndexHints' => true,
        'reverseJoin' => true,
        'straightJoin' => true,
        'insertMulti' => true,
    ];

    public static $totalSqlTimeMs = 0;

    protected $Redis;

    /**
     * - Do not call microtime when not necessary
     * - Count query count even when logging is disabled
     *
     * @param string $sql
     * @param array $options
     * @param array $params
     * @return mixed
     */
    public function execute($sql, $options = [], $params = [])
    {
        $log = $options['log'] ?? $this->fullDebug;
        $logQM = false;
        if (Configure::read('Plugin.Benchmarking_enable')) {
            $log = true;
            if (Configure::read('Plugin.Benchmarking_log_query_metrics')) {
                $this->Redis = RedisTool::init();
                $logQM = true;
            }
        }
        $current_controller = empty(Configure::read('CurrentController')) ? 'Unknown' : preg_replace('/[^a-zA-Z0-9_]/', '', Configure::read('CurrentController')) . ' :: ';
        $current_action = empty(Configure::read('CurrentAction')) ? 'Unknown' : preg_replace('/[^a-zA-Z0-9_]/', '', Configure::read('CurrentAction'));
        $comment = sprintf(
            '%s%s%s',
            empty(Configure::read('CurrentUserId')) ? '' : sprintf(
                '[User: %s] ',
                intval(Configure::read('CurrentUserId'))
            ),
            $current_controller,
            $current_action
        );
        $sql = '/* ' . $comment . ' */ ' . $sql;
        if ($log) {
            $t = microtime(true);
            $this->_result = $this->_execute($sql, $params);
            $this->took = round((microtime(true) - $t) * 1000);
            if ($logQM) {
                if ($this->took > (Configure::check('Plugin.Benchmarking_slow_log_threshold') ? Configure::read('Plugin.Benchmarking_slow_log_threshold') : 5000)) {
                    $key = 'misp:slowlog:' . uniqid();
                    $payload = $this->took . '|' . $sql;
                    $this->Redis->set($key, $payload);
                    $this->Redis->expire($key, Configure::check('Plugin.Benchmarking_slow_query_retention') ? Configure::read('Plugin.Benchmarking_slow_query_retention') : 259200);
                }
                self::$totalSqlTimeMs += $this->took;
            }
            $this->numRows = $this->affected = $this->lastAffected();
            $this->logQuery($sql, $params);
        } else {
            $this->_result = $this->_execute($sql, $params);
            $this->_queriesCnt++;
        }

        return $this->_result;
    }
}
