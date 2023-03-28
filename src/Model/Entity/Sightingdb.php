<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\Entity;

class Sightingdb extends AppModel
{
    public $virtualFields = [];

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
