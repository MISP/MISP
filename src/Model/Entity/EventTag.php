<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class EventTag extends AppModel
{
    protected function _getEventCount()
    {
        return $this->EventTags->find('all')->count();
    }
}
