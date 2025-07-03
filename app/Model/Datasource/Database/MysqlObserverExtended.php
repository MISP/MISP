<?php
App::uses('MysqlExtended', 'Model/Datasource/Database');

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
        if (Configure::read('Plugin.Benchmarking_enable')) {
            $log = true;
        }
        $comment = sprintf(
            '%s%s%s',
            empty(Configure::read('CurrentUserId')) ? '' : sprintf(
                '[User: %s] ',
                intval(Configure::read('CurrentUserId'))
            ),
            empty(Configure::read('CurrentController')) ? '' : preg_replace('/[^a-zA-Z0-9_]/', '', Configure::read('CurrentController')) . ' :: ',
            empty(Configure::read('CurrentAction')) ? '' : preg_replace('/[^a-zA-Z0-9_]/', '', Configure::read('CurrentAction'))
        );
        $sql = '/* ' . $comment . ' */ ' . $sql;
        if ($log) {
            $t = microtime(true);
            $this->_result = $this->_execute($sql, $params);
            $this->took = round((microtime(true) - $t) * 1000);
            $this->numRows = $this->affected = $this->lastAffected();
            $this->logQuery($sql, $params);
        } else {
            $this->_result = $this->_execute($sql, $params);
            $this->_queriesCnt++;
        }

        return $this->_result;
    }
}
