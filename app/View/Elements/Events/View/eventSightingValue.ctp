<?php
$ownOrgSightingsCount = 0;
if (isset($event['Sighting'])) {
    $meOrgId = $this->get('me')['org_id'];
    foreach ($event['Sighting'] as $sighting) {
        if (isset($sighting['org_id']) && $sighting['org_id'] == $meOrgId) {
            ++$ownOrgSightingsCount;
        }
    }
}

echo sprintf(
    '%s (%s) %s %s',
    sprintf(
        '<span id="eventSightingCount" class="bold sightingsCounter">%s</span>',
        count($event['Sighting'])
    ),
    sprintf(
        '<span id="eventOwnSightingCount" class="green bold sightingsCounter">%s</span>',
        $ownOrgSightingsCount
    ),
    (Configure::read('Plugin.Sightings_policy')) ? '' : __('- restricted to own organisation only.'),
    sprintf(
        '<span class="fas fa-wrench useCursorPointer sightings_advanced_add" title="%s" role="button" tabindex="0" aria-label="%s" data-object-id="%s" data-object-context="event">&nbsp;</span>',
        __('Advanced Sightings'),
        __('Advanced Sightings'),
        h($event['Event']['id'])
    )
);
