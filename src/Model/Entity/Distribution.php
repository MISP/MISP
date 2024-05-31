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

    public const SHORT_DESCRIPTIONS = [
        self::ORGANISATION_ONLY => 'Organisation',
        self::COMMUNITY_ONLY => 'Community',
        self::CONNECTED_COMMUNITIES => 'Connected',
        self::ALL_COMMUNITIES => 'All',
        self::SHARING_GROUP => ' sharing Group'
    ];

    public const LONG_DESCRIPTIONS = [
        self::ORGANISATION_ONLY => 'This field determines the current distribution of the event',
        self::COMMUNITY_ONLY => 'This field determines the current distribution of the event',
        self::CONNECTED_COMMUNITIES => 'This field determines the current distribution of the event',
        self::ALL_COMMUNITIES => 'This field determines the current distribution of the event',
        self::SHARING_GROUP => 'This field determines the current distribution of the event',
        self::INHERIT_EVENT => 'This field determines the current distribution of the event',
    ];

    public const FORM_DESCRIPTIONS = [
        self::ORGANISATION_ONLY => "This setting will only allow members of your organisation on this server to see it.",
        self::COMMUNITY_ONLY => "Organisations that are part of this MISP community will be able to see the event.",
        self::CONNECTED_COMMUNITIES => "Organisations that are either part of this MISP community or part of a directly connected MISP community will be able to see the event.",
        self::ALL_COMMUNITIES => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next.",
        self::SHARING_GROUP => "This distribution of this event will be handled by the selected sharing group.",
        self::INHERIT_EVENT => "",
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
