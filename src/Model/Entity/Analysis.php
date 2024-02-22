<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Analysis extends AppModel
{
    public const INITIAL = '1';
    public const ONGOING = '2';
    public const COMPLETED = '3';

    public const DESCRIPTIONS = [
        self::INITIAL => 'Initial',
        self::ONGOING => 'Ongoing',
        self::COMPLETED => 'Completed',
    ];

    public const ALL = [
        self::INITIAL,
        self::ONGOING,
        self::COMPLETED,
    ];
}
