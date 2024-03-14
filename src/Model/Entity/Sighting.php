<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Sighting extends AppModel
{
    public const ONE_DAY = 86400; // in seconds

    // Possible values of `Plugin.Sightings_policy` setting
    public const SIGHTING_POLICY_EVENT_OWNER = 0,
        SIGHTING_POLICY_SIGHTING_REPORTER = 1,
        SIGHTING_POLICY_EVERYONE = 2,
        SIGHTING_POLICY_HOST_ORG = 3; // the same as SIGHTING_POLICY_EVENT_OWNER, but also sightings from host org are visible

    public const TYPE = array(
        0 => 'sighting',
        1 => 'false-positive',
        2 => 'expiration'
    );
}
