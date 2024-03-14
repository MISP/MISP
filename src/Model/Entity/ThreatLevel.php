<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class ThreatLevel extends AppModel
{
    public const HIGH = '1';
    public const MEDIUM = '2';
    public const LOW = '3';
    public const UNDEFINED = '4';

    public const DESCRIPTIONS = [
        self::HIGH => 'High',
        self::MEDIUM => 'Medium',
        self::LOW => 'Low',
        self::UNDEFINED => 'Undefined',
    ];

    public const ALL = [
        self::HIGH,
        self::MEDIUM,
        self::LOW,
        self::UNDEFINED,
    ];
}
