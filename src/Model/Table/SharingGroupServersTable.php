<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class SharingGroupServersTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'Servers',
            [
                'foreignKey' => 'server_id',
                'propertyName' => 'Server',
            ]
        );

        $this->belongsTo(
            'SharingGroups',
            [
                'foreignKey' => 'sharing_group_id',
            ]
        );
    }

    public function updateServersForSG($id, $new_servers, $old_servers, $roaming, $user)
    {
        // Check first if we need to handle the servers at all, or if we should just delete all servers from the SG (depending on the checkbox in the "MISP instances" tab).
        if (!$roaming) {
            foreach ($new_servers as $server) {
                $SgS = [
                    'sharing_group_id' => $id,
                    'server_id' => $server['id'],
                    'all_orgs' => $server['all_orgs']
                ];
                $server_name = 'server (' . $server['id'] . ')';
                if ($server['id'] == 0) {
                    $server_name = 'the local server';
                }

                $found = false;
                // If there is a match between a new server and an old server, keep the server in $found and unset it in the old server array.
                foreach ($old_servers as $k => $old_server) {
                    if ($old_server['server_id'] == $server['id']) {
                        $found = $old_servers[$k];
                        unset($old_servers[$k]);
                        break;
                    }
                }

                // If we have not found the server previously, create a new sharing group server object.
                // Otherwise, if we have found it check whether the extended field has been altered, if not just continue without saving
                if (!$found) {
                    $isChange = false;
                } else {
                    if ($found['all_orgs'] == $SgS['all_orgs']) {
                        continue;
                    }
                    $isChange = true;
                    $SgS['id'] = $found['id'];
                }

                if ($isChange) {
                    $SgSEntity = $this->get($SgS['id']);
                } else {
                    $SgSEntity = $this->newEmptyEntity();
                }
                $SgSEntity = $this->patchEntity($SgSEntity, $SgS);

                if ($this->save($SgSEntity)) {
                    if ($isChange) {
                        // TODO: [3.x-MIGRATION] Make sure these log entries are picked up correctly by the auditlog
                        // $this->loadLog()->createLogEntry($user, 'edit', 'SharingGroupServer', $this->id, 'Sharing group (' . $id . '): Modified access rights for users on ' . $server_name . '.', ($server['all_orgs'] ? 'All organisations on server ' . $server['id'] . ' are now part of the sharing group.' : 'Organisations on ' . $server_name . ' are now not part of the sharing group unless they are present in the list of organisations.'));
                    } else {
                        // $this->loadLog()->createLogEntry($user, 'add', 'SharingGroupServer', $this->id, 'Sharing group (' . $id . '): Added server (' . $server['id'] . ').', ucfirst($server_name) . ' added to Sharing group.' . ($server['all_orgs'] ? ' Sharing group visible to all organisations on the server.' : ''));
                    }
                }
            }
            // We are left with some "old orgs" that are not in the new list. This means that they can be safely deleted.
            foreach ($old_servers as $old_server) {
                $SgSEntity = $this->get($old_server['id']);
                if ($this->SharingGroup->SharingGroupServer->delete($SgSEntity)) {
                    // $this->loadLog()->createLogEntry($user, 'delete', 'SharingGroupServer', $old_server['id'], 'Sharing group (' . $id . '): Removed server(' . $old_server['server_id'] . ').', 'Server (' . $old_server['server_id'] . ') removed from Sharing group.');
                }
            }
        } else {
            $this->deleteAll(['sharing_group_id' => $id], false);
        }
    }
}
