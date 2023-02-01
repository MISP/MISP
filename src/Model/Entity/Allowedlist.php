<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\Entity;
use Cake\ORM\TableRegistry;

class Allowedlist extends AppModel
{
    protected $_accessible = [
        '*' => true,
        'id' => false
    ];
}
