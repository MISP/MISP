<?php
    App::uses('Mysql', 'Model/Datasource/Database');

    /*
     * Overrides the default MySQL database implementation to prepend all queries with debug comments
     * - Lightweight and doesn't affect default operations, like a protoss observer it remains cloaked
     *   whilst trying to help detect potential bugs burrowed in our queries
     */
    class MysqlObserver extends Mysql {
        public function execute($sql, $options = array(), $params = array()) {
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
            return parent::execute($sql, $options, $params);
        }
    }
