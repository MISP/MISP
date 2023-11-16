<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Distribution extends AppModel
{

    public const ORGANISATION_ONLY = '0';
    public const COMMUNITY_ONLY = '1';
    public const CONNECTED_COMMUNITIES = '2';
    public const ALL_COMMUNITIES = '3';
    public const SHARING_GROUP = '4';
    public const INHERIT_EVENT = '5';

    public const DESCRIPTIONS = [
        self::ORGANISATION_ONLY => 'Your organisation only',
        self::COMMUNITY_ONLY => 'This community only',
        self::CONNECTED_COMMUNITIES => 'Connected communities',
        self::ALL_COMMUNITIES => 'All communities',
        self::SHARING_GROUP => 'Sharing group',
        self::INHERIT_EVENT => 'Inherit event',
    ];

    public const ALL = [
        self::ORGANISATION_ONLY,
        self::COMMUNITY_ONLY,
        self::CONNECTED_COMMUNITIES,
        self::ALL_COMMUNITIES,
        self::SHARING_GROUP,
        self::INHERIT_EVENT,
    ];
}
