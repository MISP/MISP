<?php

namespace Tags\Model\Entity;

use App\Model\Entity\AppModel;

class Tagged extends AppModel {

    protected $_accessible = [
        'id' => false,
        '*' => true,
    ];

}
