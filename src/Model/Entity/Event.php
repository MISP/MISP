<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Event extends AppModel
{
    public const NO_PUSH_DISTRIBUTION = 'distribution',
        NO_PUSH_SERVER_RULES = 'push_rules';

    public const ANALYSIS_LEVELS = [
        0 => 'Initial', 1 => 'Ongoing', 2 => 'Completed'
    ];
}
