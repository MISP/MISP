<?php

use Cake\Core\Configure;

$content = '';

$event = $entity;
$warningslist_hits = $warningslist_hits;
$contributors = [];
$instanceFingerprint = '???';
$hostOrgUser = true;
$extended = false;

$fields = [
    [
        'key' => __('Threat Level'),
        // 'path' => 'ThreatLevel.name',
        // 'key_title' => $eventDescriptions['threat_level_id']['desc'],
        // 'class' => 'threat-level-' . h(strtolower($event['ThreatLevel']['name']))
        'path' => 'Event.threat_level_id',
    ],
    [
        'key' => __('Analysis'),
        // 'key_title' => $eventDescriptions['analysis']['desc'],
        'path' => 'Event.analysis',
        // 'type' => 'mapping',
        // 'mapping' => $analysisLevels
    ],
    [
        'key' => __('Tags'),
        'type' => 'custom',
        'function' => function (array $event, $viewContext) {
            $html = '';
            foreach ($event['Event']['Tag'] as $tag) {
                if (str_starts_with($tag['name'], 'misp-galaxy:')) {
                    continue;
                }
                $html .= $viewContext->Bootstrap->badge([
                    'text' => $tag['name'],
                    'class' => ['rounded-1'],
                    'attrs' => [
                        'style' => [
                            "background-color: {$tag['colour']} !important;",
                            "color: white !important;",
                            "margin: 1px !important;"
                        ],
                    ],
                ]);
            }
            return $html;
        }
        // 'function' => function (array $event) use ($isSiteAdmin, $mayModify, $me, $missingTaxonomies, $tagConflicts) {
        //     return sprintf(
        //         '<span class="eventTagContainer">%s</span>',
        //         $this->element(
        //             'ajaxTags',
        //             [
        //                 'event' => $event,
        //                 'tags' => $event['EventTag'],
        //                 'tagAccess' => $isSiteAdmin || $mayModify,
        //                 'localTagAccess' => $this->Acl->canModifyTag($event, true),
        //                 'missingTaxonomies' => $missingTaxonomies,
        //                 'tagConflicts' => $tagConflicts
        //             ]
        //         )
        //     );
        // }
    ],
    [
        'key' => __('Galaxies'),
        'type' => 'custom',
        'function' => function (array $event, $viewContext) {
            $html = '';
            foreach ($event['Event']['Tag'] as $tag) {
                if (!str_starts_with($tag['name'], 'misp-galaxy:')) {
                    continue;
                }
                $html .= $viewContext->Bootstrap->badge([
                    'text' => $tag['name'],
                    'class' => ['rounded-1'],
                    'attrs' => [
                        'style' => [
                            "background-color: {$tag['colour']} !important;",
                            "color: white !important;",
                            "margin: 1px !important;"
                        ],
                    ],
                ]);
            }
            return $html;
        }
    ],
    [
        'key' => __('Extends'),
        // 'type' => 'extends',
        'path' => 'Event.extends_uuid',
        'extendedEvent' => isset($extendedEvent) ? $extendedEvent : null,
        'class' => 'break-word',
        'requirement' => !empty($extendedEvent)
    ],
    [
        'key' => __('Extended by'),
        // 'type' => 'extendedBy',
        'path' => 'Event.id',
        'extended_by' => isset($extensions) ? $extensions : null,
        'extended' => $extended,
        'class' => 'break-word',
        'requirement' => !empty($extensions)
    ],
    [
        'key' => __('Related Events'),
        'type' => 'custom',
        'function' => function ($event, $viewContext) {
            $text = __('{0} related hits', count($event['Event']['RelatedEvent'] ?? []));
            if (count($event['Event']['RelatedEvent'] ?? []) == 0) {
                return $this->Bootstrap->node('span', [
                    'class' => ['fs-7 text-muted'],
                ], $text);
            }
            $table = $this->Bootstrap->table(
                [
                    'hover' => false,
                    'striped' => false,
                    'class' => ['event-context-related', 'mb-0'],
                ],
                [
                    'items' => $event['Event']['RelatedEvent'],
                    'fields' => [
                        [
                            'path' => 'Event.info',
                            'label' =>  __('Name'),
                            'class' => ['fw-light']
                        ],
                        [
                            'path' => 'Event.date',
                            'label' =>  __('Date'),
                        ],
                        [
                            'path' => 'Event.Org.name',
                            'label' =>  __('Org'),
                        ],
                    ],
                ]
            );

            return $viewContext->Bootstrap->collapse([
                'button' => [
                    'text' => $text,
                    'variant' => 'link',
                    'size' => 'sm',
                    'class' => 'p-0'
                ],
            ], $table);
        }
    ],
    [
        'key' => __('Feed Hits'),
        'type' => 'custom',
        'function' => function ($event, $viewContext) {
            $text = __('{0} feed hits', count($event['Event']['Feed'] ?? []));
            if (count($event['Event']['Feed'] ?? []) == 0) {
                return $this->Bootstrap->node('span', [
                    'class' => ['fs-7 text-muted'],
                ], $text);
            }
            $table = $this->Bootstrap->table(
                [
                    'hover' => false,
                    'striped' => false,
                    'class' => ['event-context-feed', 'mb-0'],
                ],
                [
                    'items' => $event['Event']['Feed'],
                    'fields' => [
                        [
                            'path' => 'name',
                            'label' =>  __('Name'),
                            'class' => ['fw-light']
                        ],
                        [
                            'path' => 'provider',
                            'label' =>  __('Provider'),
                        ],
                    ],
                ]
            );

            return $viewContext->Bootstrap->collapse([
                'button' => [
                    'text' => $text,
                    'variant' => 'link',
                    'size' => 'sm',
                    'class' => 'p-0'
                ],
            ], $table);
        }
    ],
    [
        'key' => __('Server Hits'),
        'type' => 'custom',
        'function' => function ($event, $viewContext) {
            $text = __('{0} server hits', count($event['Event']['Server'] ?? []));
            if (count($event['Event']['Server'] ?? []) == 0) {
                return $this->Bootstrap->node('span', [
                    'class' => ['fs-7 text-muted'],
                ], $text);
            }
            $table = $this->Bootstrap->table(
                [
                    'hover' => false,
                    'striped' => false,
                    'class' => ['event-context-feed', 'mb-0'],
                ],
                [
                    'items' => $event['Event']['Server'] ?? [],
                    'fields' => [
                        [
                            'path' => 'name',
                            'label' =>  __('Name'),
                            'class' => ['fw-light']
                        ],
                        [
                            'path' => 'provider',
                            'label' =>  __('Provider'),
                        ],
                    ],
                ]
            );

            return $viewContext->Bootstrap->collapse([
                'button' => [
                    'text' => $text,
                    'variant' => 'link',
                    'size' => 'sm',
                    'class' => 'p-0'
                ],
            ], $table);
        }
    ],
    [
        'key' => __('Warninglist Hits'),
        'type' => 'custom',
        'rowVariant' => !empty($warningslist_hits) ? 'danger' : '',
        'function' => function ($event, $viewContext) use ($warningslist_hits) {
            $text = __('{0} warninglist hits', count($warningslist_hits ?? []));
            if (count($warningslist_hits ?? []) == 0) {
                return $this->Bootstrap->node('span', [
                    'class' => ['fs-7 text-muted'],
                ], $text);
            }
            $table = $this->Bootstrap->table(
                [
                    'hover' => false,
                    'striped' => false,
                    'class' => ['event-context-warninglist', 'mb-0'],
                ],
                [
                    'items' => $warningslist_hits,
                    'fields' => [
                        [
                            'path' => 'warninglist_name',
                            'label' =>  __('Name'),
                            'class' => ['fw-light']
                        ],
                        [
                            'path' => 'warninglist_category',
                            'label' =>  __('Category'),
                        ],
                    ],
                ]
            );

            return $viewContext->Bootstrap->collapse([
                'button' => [
                    'text' => __('{0} warninglist hits', count($warningslist_hits)),
                    'variant' => 'link',
                    'size' => 'sm',
                    'class' => 'p-0'
                ],
            ], $table);
        }
    ],
];

$tableRandomValue = Cake\Utility\Security::randomString(8);
$listTableOptions = [
    'id' => "single-view-table-{$tableRandomValue}",
    'hover' => false,
    'fuild' => true,
    'tableClass' => ['event-context', 'mb-0'],
    'elementsRootPath' => '/genericElements/SingleViews/Fields/'
];
$listTable = $this->Bootstrap->listTable($listTableOptions, [
    'item' => $entity,
    'fields' => $fields
]);

$content = $listTable;

echo $this->Bootstrap->card([
    'bodyHTML' => $content,
    'bodyClass' => 'p-0',
    'class' => ['shadow-md'],
]);
