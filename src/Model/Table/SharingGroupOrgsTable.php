<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class SharingGroupOrgsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'Organisations',
            [
                'foreignKey' => 'org_id',
                'propertyName' => 'Organisation',
            ]
        );

        $this->belongsTo(
            'SharingGroups',
            [
                'foreignKey' => 'sharing_group_id',
            ]
        );
    }

    public function updateOrgsForSG($id, $new_orgs, $old_orgs, $user)
    {
        // Loop through all of the organisations we want to add.
        foreach ($new_orgs as $org) {
            $SgO = array(
                'sharing_group_id' => $id,
                'org_id' => $org['id'],
                'extend' => $org['extend']
            );
            $found = false;
            // If there is a match between a new org and an old org, keep the org in $found and unset it in the old org array.
            foreach ($old_orgs as $k => $old_org) {
                if ($old_org['org_id'] == $org['id']) {
                    $found = $old_orgs[$k];
                    unset($old_orgs[$k]);
                    break;
                }
            }
            // If we have not found the org previously, create a new sharing group org object.
            // Otherwise, if we have found it check whether the extended field has been altered, if not just continue without saving
            if (!$found) {
                $isChange = false;
            } else {
                if ($found['extend'] == $SgO['extend']) {
                    continue;
                }
                $SgO['id'] = $found['id'];
                $isChange = true;
            }

            if ($isChange) {
                $SgOEntity = $this->get($SgO['id']);
            } else {
                $SgOEntity = $this->newEmptyEntity();
            }
            $SgOEntity = $this->patchEntity($SgOEntity, $SgO);

            if ($this->save($SgOEntity)) {
                if ($isChange) {
                    // TODO: [3.x-MIGRATION] Make sure these log entries are picked up correctly by the auditlog
                    // $this->loadLog()->createLogEntry($user, 'edit', 'SharingGroupOrg', $this->id, 'Sharing group (' . $id . '): Modified right to alter sharing group for organisation (' . $org['id'] . ').', ($org['extend'] ? 'Organisation (' . $org['id'] . ') can now extend the sharing group.' : 'Organisation (' . $org['id'] . ') can no longer extend the sharing group.'));
                } else {
                    // $this->loadLog()->createLogEntry($user, 'add', 'SharingGroupOrg', $this->id, 'Sharing group (' . $id . '): Added organisation (' . $org['id'] . ').', 'Organisation (' . $org['id'] . ') added to Sharing group.' . ($org['extend'] ? ' Organisation (' . $org['id'] . ') can extend the sharing group.' : ''));
                }
            }
        }
        // We are left with some "old orgs" that are not in the new list. This means that they can be safely deleted.
        foreach ($old_orgs as $old_org) {
            $SgOEntity = $this->get($old_org['id']);
            if ($this->delete($SgOEntity)) {
                // $this->loadLog()->createLogEntry($user, 'delete', 'SharingGroupOrg', $old_org['id'], 'Sharing group (' . $id . '): Removed organisation (' . $old_org['id'] . ').', 'Organisation (' . $org['id'] . ') removed from Sharing group.');
            }
        }
    }
}
