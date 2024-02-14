<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use App\Lib\Tools\ServerSyncTool;

class ShadowAttributesTable extends AppTable
{
    /**
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return int
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public function pullProposals(array $user, ServerSyncTool $serverSync)
    {
        // TODO: [3.x-MIGRATION] Implement pullProposals() method.

        return 0;
    }
}
