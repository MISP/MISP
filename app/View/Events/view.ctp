<?php
    $mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
    $mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
    $menuData = array_merge($menuData, ['mayPublish' => $mayPublish, 'mayModify' => $mayModify]);
    $scripts = ['doT', 'extendext', 'moment.min', 'query-builder', 'network-distribution-graph'];
    echo $this->element('genericElements/assetLoader', array(
        'css' => ['query-builder.default', 'attack_matrix'],
        'js' => ['doT', 'extendext', 'moment.min', 'query-builder', 'network-distribution-graph']
    ));
    echo $this->element(
        'genericElements/SingleViews/single_view',
        [
            'title' => ($extended ? '[' . __('Extended view') . '] ' : '') . h(nl2br($event['Event']['info'])),
            'data' => $event,
            'fields' => [
                [
                    'key' => __('Event ID'),
                    'path' => 'Event.id'
                ],
                [
                    'key' => 'UUID',
                    'path' => 'Event.uuid',
                    'class' => 'quickSelect',
                    'type' => 'uuid',
                    'action_buttons' => [
                        [
                            'url' => $baseurl . '/events/add/extends:' . h($event['Event']['uuid']),
                            'icon' => 'plus-square',
                            'style' => 'color:black; font-size:15px;padding-left:2px',
                            'title' => __('Extend this event'),
                            'requirement' => $isAclAdd
                        ],
                        [
                            'url' => $baseurl . '/servers/idTranslator/' . h($event['Event']['id']),
                            'icon' => 'server',
                            'style' => 'color:black; font-size:15px;padding-left:2px',
                            'title' => __('Check this event on different servers'),
                            'requirement' => $isSiteAdmin || $hostOrgUser
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
                    'function' => function ($data) use ($contributors, $baseurl, $event) {
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
                        (int)$me['org_id'] === (int)Configure::read('MISP.host_org_id') &&
                        !$event['Event']['locked']
                    ),
                    'instanceFingerprint' => $instanceFingerprint,
                    'type' => 'protectedEvent'
                ],
                [
                    'key' => __('Tags'),
                    'type' => 'custom',
                    'function' => function($data) use($event, $isSiteAdmin, $mayModify, $me, $missingTaxonomies, $tagConflicts) {
                        return sprintf(
                            '<span class="eventTagContainer">%s</span>',
                            $this->element(
                                'ajaxTags',
                                [
                                    'event' => $event,
                                    'tags' => $event['EventTag'],
                                    'tagAccess' => ($isSiteAdmin || $mayModify),
                                    'localTagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id'] || (int)$me['org_id'] === Configure::read('MISP.host_org_id')),
                                    'missingTaxonomies' => $missingTaxonomies,
                                    'tagConflicts' => $tagConflicts
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
                    'key_title' => $eventDescriptions['threat_level_id']['desc'],
                    'class' => 'threat-level-' . h(strtolower($event['ThreatLevel']['name']))
                ],
                [
                    'key' => __('Analysis'),
                    'key_title' => h($eventDescriptions['analysis']['desc']),
                    'path' => 'Event.analysis',
                    'type' => 'mapping',
                    'mapping' => $analysisLevels
                ],
                [
                    'key' => __('Distribution'),
                    'path' => 'Event.distribution',
                    'sg_path' => 'SharingGroup',
                    'event_id_path' => 'Event.id',
                    'type' => 'distribution'
                ],
                [
                    'key' => __('Warnings'),
                    'key_class' => !empty($warnings) ? 'background-red bold' : '',
                    'class' => !empty($warnings) ? 'background-red bold' : '',
                     'green',
                    'type' => 'warnings',
                    'warnings' => $warnings,
                    'requirement' => !empty($warnings) && ($me['org_id'] === $event['Event']['orgc_id'] || !empty($me['Role']['perm_site_admin']))
                ],
                [
                    'key' => __('Info'),
                    'path' => 'Event.info'
                ],
                [
                    'key' => __('Published'),
                    'path' => 'Event.published',
                    'key_class' => ($event['Event']['published'] == 0) ? 'background-red bold not-published' : 'published',
                    'class' => ($event['Event']['published'] == 0) ? 'background-red bold not-published' : 'published',
                    'type' => 'custom',
                    'function' => function($data) use($event) {
                        if (!$event['Event']['published']) {
                            return __('No');
                        } else {
                            return sprintf(
                                '<span class="green bold">%s</span> (%s)',
                                __('Yes'),
                                empty($event['Event']['publish_timestamp']) ? __('N/A') : $this->Time->time($event['Event']['publish_timestamp'])
                            );
                        }
                    }
                ],
                [
                    'key' => __('#Attributes'),
                    'raw' => $attribute_count . __n(' (%s Object)', ' (%s Objects)', $object_count, h($object_count))
                ],
                [
                    'key' => __('First recorded change'),
                    'raw' => !$oldest_timestamp ? '' : $this->Time->time($oldest_timestamp)
                ],
                [
                    'key' => __('Last change'),
                    'raw' => $this->Time->time($event['Event']['timestamp'])
                ],
                [
                    'key' => __('Modification map'),
                    'type' => 'element',
                    'element' => 'sparkline',
                    'element_params' => [
                        'scope' => 'modification',
                        'id' => $event['Event']['id'],
                        'csv' => $modificationMapCSV
                    ]
                ],
                [
                    'key' => __('Extends'),
                    'type' => 'extends',
                    'path' => 'Event.extends_uuid',
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
                    'key' => __('Activity'),
                    'type' => 'element',
                    'element' => 'sparkline',
                    'element_params' => [
                        'scope' => 'event',
                        'id' => $event['Event']['id'],
                        'csv' => $sightingsData['csv']['all']
                    ],
                    'requirement' => isset($sightingsData['data']['all'])
                ],
                [
                    'key' => __('Delegation request'),
                    'class' => 'background-red bold',
                    'type' => 'delegationRequest',
                    'delegationRequest' => isset($delegationRequest) ? $delegationRequest : null,
                    'requirement' => !empty($delegationRequest)
                ],
                [
                    'key' => __('Correlation'),
                    'class' => $event['Event']['disable_correlation'] ? 'background-red bold' : '',
                    'type' => 'custom',
                    'function' => function($data) use($mayModify, $isSiteAdmin) {
                        return sprintf(
                            '%s%s',
                            $data['Event']['disable_correlation'] ? __('Disabled') : __('Enabled'),
                            (!$mayModify && !$isSiteAdmin) ? '' :
                                sprintf(
                                    ' (<a onClick="getPopup(%s);" style="%scursor:pointer;font-weight:normal;">%s</a>)',
                                    sprintf(
                                        "'%s', 'events', 'toggleCorrelation', '', '#confirmation_box'",
                                        h($data['Event']['id'])
                                    ),
                                    $data['Event']['disable_correlation'] ? 'color:white;' : '',
                                    $data['Event']['disable_correlation'] ? __('enable') : __('disable')
                                )
                        );
                    },
                    'requirement' => (!Configure::read('MISP.completely_disable_correlation') && Configure::read('MISP.allow_disabling_correlation'))
                ]
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
