<?php
    echo sprintf(
        '%s (%s) %s %s',
        sprintf(
            '<span id="eventSightingCount" class="bold sightingsCounter" data-toggle="popover" data-trigger="hover" data-content="%s">%s</span>',
            $sightingPopover,
            count($event['Sighting'])
        ),
        sprintf(
            '<span id="eventOwnSightingCount" class="green bold sightingsCounter" data-toggle="popover" data-trigger="hover" data-content="%s">%s</span>',
            $sightingPopover,
            isset($ownSightings) ? count($ownSightings) : 0
        ),
        (Configure::read('Plugin.Sightings_policy')) ? '' : __('- restricted to own organisation only.'),
        sprintf(
            '<span class="icon-wrench useCursorPointer sightings_advanced_add" title="%s" role="button" tabindex="0" aria-label="%s" data-object-id="%s" data-object-context="event">&nbsp;</span>',
             __('Advanced Sightings'),
            __('Advanced Sightings'),
            h($event['Event']['id'])
        )
    );
