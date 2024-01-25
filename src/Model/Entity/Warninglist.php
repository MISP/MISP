<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\Entity;

class Warninglist extends AppModel
{
    public const CATEGORY_FALSE_POSITIVE = 'false_positive',
        CATEGORY_KNOWN = 'known';

    public const TLDS = array(
        'TLDs as known by IANA'
    );
}
