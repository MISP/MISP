<?php
App::uses('AppModel', 'Model');
class SharingGroupOrg extends AppModel
{
    public $actsAs = array('Containable');

    public $belongsTo = array(
            'SharingGroup' => array(
                    'className' => 'SharingGroup',
                    'foreignKey' => 'sharing_group_id'
            ),
            'Organisation' => array(
                    'className' => 'Organisation',
                    'foreignKey' => 'org_id',
                    //'conditions' => array('SharingGroupElement.organisation_uuid' => 'Organisation.uuid')
            )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
    }

    public function updateOrgsForSG($id, $new_orgs, $old_orgs, $user)
    {
        $log = ClassRegistry::init('Log');
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
                $this->create();
                $isChange = false;
            } else {
                if ($found['extend'] == $SgO['extend']) {
                    continue;
                }
                $SgO['id'] = $found['id'];
                $isChange = true;
            }
            if ($this->save($SgO)) {
                $log->create();
                if ($isChange) {
                    $log->createLogEntry($user, 'edit', 'SharingGroupOrg', $this->id, 'Sharing group (' . $id . '): Modified right to alter sharing group for organisation (' . $org['id'] . ').', ($org['extend'] ? 'Organisation (' . $org['id'] . ') can now extend the sharing group.' : 'Organisation (' . $org['id'] . ') can no longer extend the sharing group.'));
                } else {
                    $log->createLogEntry($user, 'add', 'SharingGroupOrg', $this->id, 'Sharing group (' . $id . '): Added organisation (' . $org['id'] . ').', 'Organisation (' . $org['id'] . ') added to Sharing group.' . ($org['extend'] ? ' Organisation (' . $org['id'] . ') can extend the sharing group.' : ''));
                }
            }
        }
        // We are left with some "old orgs" that are not in the new list. This means that they can be safely deleted.
        foreach ($old_orgs as $old_org) {
            if ($this->delete($old_org['id'])) {
                $log->create();
                $log->createLogEntry($user, 'delete', 'SharingGroupOrg', $old_org['id'], 'Sharing group (' . $id . '): Removed organisation (' . $old_org['id'] . ').', 'Organisation (' . $org['id'] . ') removed from Sharing group.');
            }
        }
    }

    public function fetchAllAuthorised($org_id)
    {
        $sgs = $this->find('all', array(
            'conditions' => array('org_id' => $org_id),
            'recursive' => -1,
            'fields' => array('org_id', 'sharing_group_id'),
        ));
        $ids = array();
        foreach ($sgs as $sg) {
            $ids[] = $sg['SharingGroupOrg']['sharing_group_id'];
        }
        return $ids;
    }

    // pass a sharing group ID and an organisation ID, returns true if it has a matching attached organisation object
    public function checkIfAuthorised($id, $org_id)
    {
        $sg = $this->find('first', array(
                'conditions' => array('sharing_group_id' => $id, 'org_id' => $org_id),
                'recursive' => -1,
                'fields' => array('id'),
        ));
        if (!empty($sg)) {
            return true;
        }
        return false;
    }
}
