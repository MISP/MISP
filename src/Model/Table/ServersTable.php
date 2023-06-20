<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Core\Configure;

class ServersTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
    }

    public function captureServer($server, $user)
    {
        if (isset($server[0])) {
            $server = $server[0];
        }
        if ($server['url'] == Configure::read('MISP.baseurl')) {
            return 0;
        }
        $existingServer = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['url' => $server['url']]
            ]
        )->disableHydration()->first();
        // unlike with other capture methods, if we find a server that we don't know
        // we don't want to save it.
        if (empty($existingServer)) {
            return false;
        }
        return $existingServer['id'];
    }

    public function fetchServer($id)
    {
        if (empty($id)) {
            return false;
        }
        $conditions = ['Servers.id' => $id];
        if (!is_numeric($id)) {
            $conditions = ['OR' => [
                'LOWER(Servers.name)' => strtolower($id),
                'LOWER(Servers.url)' => strtolower($id)
            ]];
        }
        $server = $this->find(
            'all',
            [
            'conditions' => $conditions,
            'recursive' => -1
            ]
        )->disableHydration()->first();
        return (empty($server)) ? false : $server;
    }
}
