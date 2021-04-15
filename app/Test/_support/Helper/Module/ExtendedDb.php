<?php

namespace Helper\Module;

class ExtendedDb extends \Codeception\Module\Db
{
    /**
     * Performs a lightweight cleanup by just running a custom sql file.
     */
    protected function cleanUpDatabases()
    {
        foreach ($this->getDatabases() as $databaseKey => $databaseConfig) {
            if (!$databaseConfig['cleanup_queries']) {
                $this->_cleanup($databaseKey, $databaseConfig);
            } else {
                $this->_runCustomCleanupQuery($databaseKey, $databaseConfig);
            }
        }
    }

    private function _runCustomCleanupQuery($databaseKey, $databaseConfig)
    {
        $databaseKey = empty($databaseKey) ?  self::DEFAULT_DATABASE : $databaseKey;
        $databaseConfig = empty($databaseConfig) ?  $this->config : $databaseConfig;

        if (!$databaseConfig['cleanup']) {
            return;
        }

        foreach ($databaseConfig['cleanup_queries'] as $cleanUpQuery) {
            $this->drivers[$databaseKey]->executeQuery($cleanUpQuery, []);
        }
    }
}
