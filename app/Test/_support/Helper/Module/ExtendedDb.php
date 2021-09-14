<?php

declare(strict_types=1);

namespace Helper\Module;

class ExtendedDb extends \Codeception\Module\Db
{
    /**
     * Performs a lightweight cleanup by just running a custom sql file.
     */
    protected function cleanUpDatabases(): void
    {
        foreach ($this->getDatabases() as $databaseKey => $databaseConfig) {
            if (!isset($databaseConfig['cleanup_queries'])) {
                $this->_cleanup($databaseKey, $databaseConfig);
            } else {
                $this->_runCustomCleanupQuery($databaseKey, $databaseConfig);
            }
        }
    }

    /**
     * @param string $databaseKey
     * @param array<mixed> $databaseConfig
     * 
     * @return void
     */
    private function _runCustomCleanupQuery(string $databaseKey, array $databaseConfig): void
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
