<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\Locator\LocatorAwareTrait;

class SharingGroup extends AppModel
{
    use LocatorAwareTrait;

    protected $_virtual = ['org_count'];

    protected function _getOrgCount()
    {
        $SharingGroupOrgsTable = $this->fetchTable('SharingGroupOrgs');

        return $SharingGroupOrgsTable->find(
            'all',
            [
            'conditions' => ['SharingGroupOrgs.sharing_group_id = id']
            ]
        )->count();
    }
}
