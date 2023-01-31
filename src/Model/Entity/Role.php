<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\Entity;

class Role extends AppModel
{
    public $virtualFields = array(
        'permission' => "CASE WHEN (Role.perm_add AND Role.perm_modify AND Role.perm_publish) THEN '3' WHEN (Role.perm_add AND Role.perm_modify_org) THEN '2' WHEN (Role.perm_add) THEN '1' ELSE '0' END",
    );

    protected function _getPermission()
    {
        if ($this->perm_add && $this->perm_modify && $this->perm_publish) {
            return 3;
        } else if ($this->perm_add && $this->perm_modify_org) {
            return 2;
        } else if ($this->perm_add) {
            return 1;
        }
        return 0;
    }
}
