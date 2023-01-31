<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\Entity;
use Cake\ORM\TableRegistry;

class Organisation extends AppModel
{
    protected $_accessible = [
        '*' => true,
        'id' => false,
        'date_created' => false
    ];

    protected $_accessibleOnNew = [
        'date_created' => true
    ];

    protected function _getUserCount()
    {
        $users = TableRegistry::getTableLocator()->get('Users');
        $user_count = $users->find('all')->where(['org_id' => $this->id])->count();
        return $user_count;
    }

    public function rearrangeForAPI(): void
    {

    }
}
