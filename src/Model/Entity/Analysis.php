<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Analysis extends AppModel
{
    public const INITIAL = '0';
    public const ONGOING = '1';
    public const COMPLETED = '2';

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

    public const LONG_DESCRIPTIONS = [
        self::INITIAL => '*Initial* means the event has just been created',
        self::ONGOING => '*Ongoing* means that the event is being populated',
        self::COMPLETED => '*Complete* means that the event\'s creation is complete'
    ];

    public const FORM_DESCRIPTIONS = [
        0 => 'Event has just been created and is in an initial state',
        1 => 'The analysis is still ongoing',
        2 => 'The event creator considers the analysis complete'
    ];
}
