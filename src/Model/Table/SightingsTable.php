<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use App\Lib\Tools\ServerSyncTool;

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
}
