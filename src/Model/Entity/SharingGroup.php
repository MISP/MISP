<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\Locator\LocatorAwareTrait;

class SharingGroup extends AppModel
{
    use LocatorAwareTrait;

    protected $_accessible = [
        '*' => true,
        'id' => false,
        'created' => false
    ];

    protected $_accessibleOnNew = [
        'created' => true
    ];

    protected $_virtual = ['org_count'];

    protected function _getOrgCount()
    {
        if (isset($this->SharingGroupOrg)) {
            return count($this->SharingGroupOrg);
        }
        $SharingGroupOrgsTable = $this->fetchTable('SharingGroupOrgs');

        return $SharingGroupOrgsTable->find()->where(['SharingGroupOrgs.sharing_group_id' => $this->id])->count();
        return $SharingGroupOrgsTable->find(
            'all',
            [
            'conditions' => ['SharingGroupOrgs.sharing_group_id = id']
            ]
        )->count();
    }
}
