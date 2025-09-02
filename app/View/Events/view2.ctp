<?php
    echo $this->element('genericElements/assetLoader', [
        'css' => ['query-builder.default', 'attack_matrix', 'analyst-data'],
        'js' => ['doT', 'extendext', 'moment.min', 'query-builder', 'network-distribution-graph', 'd3', 'd3.custom', 'jquery-ui.min'],
    ]);
    $pageTitle = $event['Event']['info'];
    if ($extended) {
        $pageTitle = '[' . __('Extended view') . '] ' . $pageTitle;
    } else if ($extending) {
        $pageTitle = '[' . __('Extending view') . '] ' . $pageTitle;
    }
    echo $this->element(
        'genericElements/SingleViews/single_view',
        [
            'title' => $pageTitle,
            'data' => $event,
            'fields' => [
                [
                    'key' => __('Event ID'),
                    'path' => 'Event.id'
                ],
                [
                    'key' => 'UUID',
                    'path' => 'Event.uuid',
                    'class' => '',
                    'type' => 'uuid',
                    'object_type' => 'Event',
                    'notes_path' => 'Note',
                    'opinions_path' => 'Opinion',
                    'relationship_path' => 'Relationship',
                    'action_buttons' => [
                        [
                            'url' => $baseurl . '/events/add/extends:' . h($event['Event']['uuid']),
                            'icon' => 'plus-square',
                            'style' => 'color:black; font-size:15px;padding-left:2px',
                            'title' => __('Extend this event'),
                            'requirement' => $this->Acl->canAccess('events', 'add'),
                        ],
                        [
                            'url' => $baseurl . '/servers/idTranslator/' . h($event['Event']['id']),
                            'icon' => 'server',
                            'style' => 'color:black; font-size:15px;padding-left:2px',
                            'title' => __('Check this event on different servers'),
                            'requirement' => $this->Acl->canAccess('servers', 'idTranslator'),
                        ]
                    ]
                ],
                [
                    'key' => __('Source Organisation'),
                    'type' => 'org',
                    'path' => 'Orgc',
                    'element' => 'org',
                    'requirement' => !empty(Configure::read('MISP.showorgalternate'))
                ],
                [
                    'key' => __('Member Organisation'),
                    'type' => 'org',
                    'path' => 'Org',
                    'element' => 'org',
                    'requirement' => !empty(Configure::read('MISP.showorgalternate'))
                ],
                [
                    'key' => __('Creator org'),
                    'type' => 'org',
                    'path' => 'Orgc',
                    'element' => 'org',
                    'requirement' => empty(Configure::read('MISP.showorgalternate'))
                ],
                [
                    'key' => __('Owner org'),
                    'type' => 'org',
                    'path' => 'Org',
                    'element' => 'org',
                    'requirement' => $isSiteAdmin && empty(Configure::read('MISP.showorgalternate'))
                ],
                [
                    'key' => __('Contributors'),
                    'type' => 'custom',
                    'function' => function (array $event) use ($contributors, $baseurl) {
                        $contributorsContent = [];
                        foreach ($contributors as $organisationId => $name) {
                            $org = ['Organisation' => ['id' => $organisationId, 'name' => $name]];
                            if (Configure::read('MISP.log_new_audit')) {
                                $link = $baseurl . "/audit_logs/eventIndex/" . h($event['Event']['id']) . '/' . h($organisationId);
                            } else {
                                $link = $baseurl . "/logs/event_index/" . h($event['Event']['id']) . '/' . h($name);
                            }
                            $contributorsContent[] = $this->OrgImg->getNameWithImg($org, $link);
                        }
                        return implode('<br>', $contributorsContent);
                    },
                    'requirement' => !empty($contributors)
                ],
                [
                    'key' => __('Creator user'),
                    'path' => 'User.email',
                    'requirement' => isset($event['User']['email'])
                ],
                [
                    'key' => __('Protected Event (experimental)'),
                    'key_info' => __(
                        "Protected events carry a list of cryptographic keys used to sign and validate the information in transit.\n\nWhat this means in practice, a protected event shared with another instance will only be able to receive updates via the synchronisation mechanism from instances that are able to provide a valid signature from the event's list of signatures.\n\nFor highly critical events in broader MISP networks, this can provide an additional layer of tamper proofing to ensure that the original source of the information maintains control over modifications. Whilst this feature has its uses, it is not required in most scenarios."
                    ),
                    'path' => 'CryptographicKey',
                    'event_path' => 'Event',
                    'owner' => (
                        (int)$me['org_id'] === (int)$event['Event']['orgc_id'] &&
                        $hostOrgUser &&
                        !$event['Event']['locked']
                    ),
                    'instanceFingerprint' => $instanceFingerprint,
                    'type' => 'protectedEvent'
                ],
                [
                    'key' => __('Tags'),
                    'type' => 'custom',
                    'function' => function(array $event) use($isSiteAdmin, $mayModify, $me, $context) {
                        return sprintf(
                            '<span class="eventTagContainer">%s</span>',
                            $this->element(
                                'ajaxTags',
                                [
                                    'event' => $event,
                                    'tags' => $event['Event']['EventTag'],
                                    'tagAccess' => $isSiteAdmin || $mayModify,
                                    'localTagAccess' => $this->Acl->canModifyTag($event, true),
                                    'missingTaxonomies' => $context['missingTaxonomies'],
                                    'tagConflicts' => []
                                ]
                            )
                        );
                    }
                ],
                [
                    'key' => __('Date'),
                    'path' => 'Event.date'
                ],
                [
                    'key' => __('Threat Level'),
                    'path' => 'ThreatLevel.name',
                    'key_title' => $context['eventDescriptions']['threat_level_id']['desc'],
                    'class' => 'threat-level-' . h(strtolower($event['Event']['ThreatLevel']['name']))
                ],
                [
                    'key' => __('Analysis'),
                    'key_title' => $context['eventDescriptions']['analysis']['desc'],
                    'path' => 'Event.analysis',
                    'type' => 'mapping',
                    'mapping' => $context['analysisLevels']
                ],
                [
                    'key' => __('Distribution'),
                    'path' => 'Event.distribution',
                    'sg_path' => 'SharingGroup',
                    'event_id_path' => 'Event.id',
                    'type' => 'distribution'
                ],
                [
                    'key' => __('Published'),
                    'path' => 'Event.published',
                    'key_class' => ($event['Event']['published'] == 0) ? 'not-published' : 'published',
                    'class' => ($event['Event']['published'] == 0) ? 'not-published' : 'published',
                    'type' => 'custom',
                    'function' => function() use($event) {
                        if (!$event['Event']['published']) {
                            $string = '<span class="label label-important label-padding">' . __('No') . '</span>';
                            if (!empty($event['Event']['publish_timestamp'])) {
                                $string .= __(' (last published at %s)', $this->Time->time($event['Event']['publish_timestamp']));
                            }
                            return $string;
                        } else {
                            return sprintf(
                                '<span class="label label-success label-padding">%s</span> %s',
                                __('Yes'),
                                empty($event['Event']['publish_timestamp']) ? __('N/A') : $this->Time->time($event['Event']['publish_timestamp'])
                            );
                        }
                    }
                ],
                [
                    'key' => __('Extends'),
                    'type' => 'extends',
                    'path' => 'Event.extends_uuid',
                    'extending' => $extending,
                    'extendedEvent' => isset($extendedEvent) ? $extendedEvent : null,
                    'class' => 'break-word',
                    'requirement' => !empty($extendedEvent)
                ],
                [
                    'key' => __('Extended by'),
                    'type' => 'extendedBy',
                    'path' => 'Event.id',
                    'extended_by' => isset($extensions) ? $extensions : null,
                    'extended' => $extended,
                    'class' => 'break-word',
                    'requirement' => !empty($extensions)
                ],
                [
                    'key' => __('Sightings'),
                    'type' => 'element',
                    'element' => '/Events/View/eventSightingValue',
                    'element_params' => array(
                        'event' => $event,
                        'sightingsData' => isset($sightingsData['data']['all']) ? $sightingsData['data']['all'] : [],
                    )
                ],
                [
                    'key' => __('Correlation'),
                    'class' => $event['Event']['disable_correlation'] ? 'background-red bold' : '',
                    'type' => 'custom',
                    'function' => function($event) use($mayModify, $isSiteAdmin) {
                        return sprintf(
                            '%s%s',
                            $event['Event']['disable_correlation'] ? __('Disabled') : __('Enabled'),
                            (!$mayModify && !$isSiteAdmin) ? '' :
                                sprintf(
                                    ' (<a onclick="getPopup(%s);" style="%scursor:pointer">%s</a>)',
                                    sprintf(
                                        "'%s', 'events', 'toggleCorrelation', '', '#confirmation_box'",
                                        h($event['Event']['id'])
                                    ),
                                    $event['Event']['disable_correlation'] ? 'color:white;' : '',
                                    $event['Event']['disable_correlation'] ? __('enable') : __('disable')
                                )
                        );
                    },
                    'requirement' => (!Configure::read('MISP.completely_disable_correlation') && Configure::read('MISP.allow_disabling_correlation'))
                ],
            ],
            'side_panels' => [
                [
                    'type' => 'tagConflicts',
                    'requirement' => !empty($warningTagConflicts)
                ],
                [
                    'type' => 'relatedEvents',
                    'requirement' => !empty($event['RelatedEvent'])
                ],
                [
                    'type' => 'relatedFeeds',
                    'requirement' => !empty($event['Feed']) || !empty($event['Event']['FeedCount'])
                ],
                [
                    'type' => 'relatedServers',
                    'requirement' => !empty($event['Server']) || !empty($event['Event']['ServerCount'])
                ],
                [
                    'type' => 'eventWarnings',
                    'requirement' => !empty($event['warnings'])
                ]
            ],
            'children' => [
                [
                    'url' => '/attributes/index/eventid:{{0}}/',
                    'url_params' => ['Event.id'],
                    'title' => __('Attributes'),
                    'elementId' => 'attributes_container',
                ],
                [
                    'url' => '/objects/index/{{0}}/',
                    'url_params' => ['Event.id'],
                    'title' => __('Objects'),
                    'elementId' => 'objects_container'
                ],
            ],
            'append' => [
                [
                    'element' => '/Events/View/event_contents',
                    'element_params' => [
                        'mayModify' => $mayModify
                    ]
                ]
            ]
        ]
    );
