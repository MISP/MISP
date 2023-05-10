<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class EventBlocklist extends AppModel
{
    protected $_accessible = [
        '*' => true,
        'id' => false
    ];
}
