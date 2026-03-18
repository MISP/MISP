<?php
    echo $this->element('genericElements/assetLoader', [
        'css' => ['attack_matrix', 'analyst-data'],
        'js' => [
            'doT', 'd3', 'd3.custom',
            'network-distribution-graph',
        ],
    ]);
    $eventId = $event['Event']['id'];
    $pageTitle = h($event['Event']['info']);
    $mayModify = (
        $this->Acl->canAccess('events', 'edit') &&
        (
            $isSiteAdmin ||
            $event['Event']['orgc_id'] == $me['org_id']
        )
    );

    echo $this->element(
        'genericElements/SingleViews/single_view',
        [
            'title' => $pageTitle,
            'data' => $event,
            'fields' => [
                [
                    'key' => __('Event ID'),
                    'path' => 'Event.id',
                ],
                [
                    'key' => 'UUID',
                    'path' => 'Event.uuid',
                    'type' => 'uuid',
                    'object_type' => 'Event',
                    'notes_path' => 'Note',
                    'opinions_path' => 'Opinion',
                    'relationship_path' => 'Relationship',
                    'action_buttons' => [
                        [
                            'url' => $baseurl
                                . '/events/add/extends:'
                                . h($event['Event']['uuid']),
                            'icon' => 'plus-square',
                            'style' => 'color:black;'
                                . ' font-size:15px;'
                                . 'padding-left:2px',
                            'title' => __(
                                'Extend this event'
                            ),
                            'requirement' =>
                                $this->Acl->canAccess(
                                    'events', 'add'
                                ),
                        ],
                    ],
                ],
                [
                    'key' => __('Creator org'),
                    'type' => 'org',
                    'path' => 'Orgc',
                    'element' => 'org',
                ],
                [
                    'key' => __('Owner org'),
                    'type' => 'org',
                    'path' => 'Org',
                    'element' => 'org',
                    'requirement' => $isSiteAdmin,
                ],
                [
                    'key' => __('Tags'),
                    'type' => 'custom',
                    'function' => function (array $event)
                        use ($mayModify)
                    {
                        return sprintf(
                            '<span class='
                            . '"eventTagContainer">'
                            . '%s</span>',
                            $this->element(
                                'ajaxTags',
                                [
                                    'event' => $event,
                                    'tags' =>
                                        $event['EventTag'],
                                    'tagAccess' =>
                                        $this->Acl
                                            ->canAccess(
                                                'events',
                                                'edit'
                                            )
                                        && $mayModify,
                                    'localTagAccess' =>
                                        $this->Acl
                                            ->canModifyTag(
                                                $event,
                                                true
                                            ),
                                ]
                            )
                        );
                    },
                ],
                [
                    'key' => __('Date'),
                    'path' => 'Event.date',
                ],
                [
                    'key' => __('Threat Level'),
                    'path' => 'ThreatLevel.name',
                    'key_title' =>
                        $eventDescriptions[
                            'threat_level_id'
                        ]['desc'],
                    'class' => 'threat-level-'
                        . h(strtolower(
                            $event['ThreatLevel']['name']
                        )),
                ],
                [
                    'key' => __('Analysis'),
                    'key_title' =>
                        $eventDescriptions[
                            'analysis'
                        ]['desc'],
                    'path' => 'Event.analysis',
                    'type' => 'mapping',
                    'mapping' => $analysisLevels,
                ],
                [
                    'key' => __('Distribution'),
                    'path' => 'Event.distribution',
                    'sg_path' => 'SharingGroup',
                    'event_id_path' => 'Event.id',
                    'type' => 'distribution',
                ],
                [
                    'key' => __('Published'),
                    'path' => 'Event.published',
                    'key_class' =>
                        $event['Event']['published']
                            ? '' : 'not-published',
                    'class' =>
                        $event['Event']['published']
                            ? 'published'
                            : 'not-published',
                    'type' => 'custom',
                    'function' => function (
                        array $event
                    ) {
                        if (
                            !$event['Event']['published']
                        ) {
                            return sprintf(
                                '<span class="label'
                                . ' label-important'
                                . ' label-padding">'
                                . '%s</span>',
                                __('No')
                            );
                        }
                        return sprintf(
                            '<span class="label'
                            . ' label-success'
                            . ' label-padding">'
                            . '%s</span>',
                            __('Yes')
                        );
                    },
                ],
                [
                    'key' => __('Last change'),
                    'raw' => $this->Time->time(
                        $event['Event']['timestamp']
                    ),
                ],
                [
                    'key' => __('Extends'),
                    'type' => 'custom',
                    'requirement' => !empty(
                        $event['Event']['Extends']
                    ),
                    'function' => function (
                        array $event
                    ) use ($baseurl) {
                        $ext =
                            $event['Event']['Extends'];
                        if (is_string($ext)) {
                            return h($ext);
                        }
                        return sprintf(
                            '%s (<a href="%s">%s</a>)'
                            . ': %s',
                            __('Event'),
                            $baseurl . '/events/view/'
                                . h($ext['id']),
                            h($ext['id']),
                            h($ext['info'])
                        );
                    },
                ],
                [
                    'key' => __('Extended by'),
                    'type' => 'custom',
                    'requirement' => !empty(
                        $event['Event']['ExtendedBy']
                    ),
                    'function' => function (
                        array $event
                    ) use ($baseurl) {
                        $lines = [];
                        foreach (
                            $event['Event']['ExtendedBy']
                            as $ext
                        ) {
                            $lines[] = sprintf(
                                '<div style='
                                . '"padding-left:1em">'
                                . '<span class='
                                . '"apply_css_arrow">'
                                . '%s (<a href="%s">'
                                . '%s</a>): %s'
                                . '</span></div>',
                                __('Event'),
                                $baseurl
                                    . '/events/view/'
                                    . h($ext['id']),
                                h($ext['id']),
                                h($ext['info'])
                            );
                        }
                        return implode('', $lines);
                    },
                ],
                [
                    'key' => __('Correlation'),
                    'class' =>
                        $event['Event'][
                            'disable_correlation'
                        ]
                        ? 'background-red bold' : '',
                    'type' => 'custom',
                    'function' => function (
                        $event
                    ) {
                        return $event['Event'][
                            'disable_correlation'
                        ]
                        ? __('Disabled')
                        : __('Enabled');
                    },
                    'requirement' => (
                        !Configure::read(
                            'MISP.completely_disable'
                            . '_correlation'
                        ) &&
                        Configure::read(
                            'MISP.allow_disabling'
                            . '_correlation'
                        )
                    ),
                ],
            ],
            'side_panels' => [
                [
                    'type' => 'html',
                    'html' => '<div id="side-related-events">'
                        . '<div class="loading-placeholder">'
                        . '<i class="fas fa-spinner fa-spin"></i> '
                        . __('Loading related events...')
                        . '</div></div>',
                ],
                [
                    'type' => 'html',
                    'html' => '<div id="side-warninglist-hits">'
                        . '<div class="loading-placeholder">'
                        . '<i class="fas fa-spinner fa-spin"></i> '
                        . __('Loading warninglist hits...')
                        . '</div></div>',
                ],
            ],
            'children' => [
                [
                    'title' => __('Attributes'),
                    'url' => sprintf(
                        '/events/viewAttributes/%s',
                        h($eventId)
                    ),
                    'elementId' =>
                        'attributes_panel',
                    'open' => true,
                ],
                [
                    'title' => __('Objects'),
                    'url' => sprintf(
                        '/events/viewObjects/%s',
                        h($eventId)
                    ),
                    'elementId' => 'objects_panel',
                ],
            ],
            'append' => [],
        ]
    );

    echo '<div id="event-galaxies-container" style="margin-bottom:15px;">';
    echo $this->element(
        '/Events/View/event_galaxies2',
        [
            'galaxies' => $event['Galaxy'] ?? [],
            'event' => $event,
            'eventId' => $eventId,
        ]
    );
    echo '</div>';
?>
<script>
// Move galaxies above the first accordion child
$(function() {
    var $galaxies = $('#event-galaxies-container');
    var $firstAccordion = $('#attributes_panel');
    if ($galaxies.length && $firstAccordion.length) {
        $galaxies.insertBefore($firstAccordion);
    }
});
$(function() {
    // Load related events into side panel
    $.ajax({
        type: 'get',
        url: baseurl
            + '/events/viewRelatedEvents/'
            + '<?= h($eventId) ?>',
        success: function(data) {
            $('#side-related-events').html(data);
        },
        error: function() {
            $('#side-related-events').html(
                '<em><?= __('Could not load related events.') ?></em>'
            );
        }
    });

    // Load warninglist hits into side panel
    $.ajax({
        type: 'get',
        url: baseurl
            + '/events/viewWarninglistHits/'
            + '<?= h($eventId) ?>',
        success: function(data) {
            $('#side-warninglist-hits').html(data);
        },
        error: function() {
            $('#side-warninglist-hits').html(
                '<em><?= __('Could not load warninglist hits.') ?></em>'
            );
        }
    });
});
</script>
