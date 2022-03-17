<?php
$distribution = Hash::extract($data, $field['path'])[0];
$event_id_path = Hash::extract($data, $field['event_id_path'])[0];
if ($distribution == 4) {
    try{
        $sg = Hash::extract($data, $field['sg_path']);
    } catch (Exception $e) {
        $sg = null;
    }
    if (empty($sg)) {
        $sgHtml = sprintf(
            '<span class="red bold" title="%s">%s</span>',
            __('your organisation is the local owner of this event, however it is not explicitly listed in the sharing group.'),
            __('Undisclosed sharing group')
        );
    } else {
        $sgHtml = sprintf(
            '<a href="%s%s">%s</a>',
            $baseurl . '/sharing_groups/view/',
            h($sg['id']),
            h($sg['name'])
        );
    }
}

$eventDistributionGraph = '';
if (!($distribution == 4 && empty($sg))) {
    $eventDistributionGraph = sprintf(
        '%s %s %s',
        sprintf(
            '<span id="distribution_graph_bar" style="margin-left: 5px;" data-object-id="%s" data-object-context="event"></span>',
            h($event_id_path)
        ),
        sprintf(
            '<it class="%s" data-object-id="%s" data-object-context="event" data-shown="false"></it><div style="display: none">%s</div>',
            'useCursorPointer fa fa-info-circle distribution_graph',
            h($event_id_path),
            $this->element('view_event_distribution_graph')
        ),
        sprintf(
            '<it type="button" id="showAdvancedSharingButton" title="%s" class="%s" aria-hidden="true" style="margin-left: 5px;"></it>',
            __('Toggle advanced sharing network viewer'),
            'fa fa-share-alt useCursorPointer'
        )
    );
}

echo sprintf(
    '%s %s',
    isset($sgHtml) ? $sgHtml : $distributionLevels[$distribution],
    $eventDistributionGraph
);
