<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Job extends AppModel
{
    public const STATUS_WAITING = 1,
        STATUS_RUNNING = 2,
        STATUS_FAILED = 3,
        STATUS_COMPLETED = 4;

    public const WORKER_EMAIL = 'email',
        WORKER_PRIO = 'prio',
        WORKER_DEFAULT = 'default',
        WORKER_CACHE = 'cache',
        WORKER_UPDATE = 'update';
}
