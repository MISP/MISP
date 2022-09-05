<?php
$userOrgName = $this->get('me')['Organisation']['name'];

$totalCount = 0;
$ownCount = 0;
foreach ($sightingsData as $data) {
    $totalCount += $data['count'];
    $ownCount += isset($data['orgs'][$userOrgName]['count']) ? $data['orgs'][$userOrgName]['count'] : 0;
}

echo sprintf(
    '%s (%s) %s %s',
    sprintf(
        '<span id="eventSightingCount" class="bold sightingsCounter">%s</span>',
        $totalCount
    ),
    sprintf(
        '<span id="eventOwnSightingCount" class="green bold sightingsCounter">%s</span>',
        $ownCount
    ),
    (Configure::read('Plugin.Sightings_policy')) ? '' : __('- restricted to own organisation only.'),
    sprintf(
        '<span class="fas fa-wrench useCursorPointer sightings_advanced_add" title="%s" role="button" tabindex="0" aria-label="%s" data-object-id="%s" data-object-context="event">&nbsp;</span>',
        __('Advanced Sightings'),
        __('Advanced Sightings'),
        h($event['Event']['id'])
    )
);
