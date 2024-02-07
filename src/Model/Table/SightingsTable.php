<?php

namespace App\Model\Table;

use App\Lib\Tools\ServerSyncTool;
use App\Model\Table\AppTable;

class SightingsTable extends AppTable
{
    /**
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return int Number of saved sighting.
     * @throws Exception
     */
    public function pullSightings(array $user, ServerSyncTool $serverSync)
    {
        // TODO: [3.x-MIGRATION] Implement pullSightings() method.

        return 0;
    }

    /**
     * Push sightings to remote server.
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return array
     * @throws Exception
     */
    public function pushSightings(array $user, ServerSyncTool $serverSync)
    {
        // TODO: [3.x-MIGRATION] Implement pushSightings() method.

        return [];
    }
}
