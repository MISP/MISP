<?php

use App\Model\Entity\SharingGroup;
// debug($entity);

echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => __('Sharing Group {0}', $entity['name']),
        'data' => $entity,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'id'
            ],
            [
                'key' => __('UUID'),
                'path' => 'uuid'
            ],
            [
                'key' => __('Name'),
                'path' => 'name'
            ],
            [
                'key' => __('Releasability'),
                'path' => 'releasability'
            ],
            [
                'key' => __('Description'),
                'path' => 'description'
            ],
            [
                'key' => __('Selectable'),
                'path' => 'active',
                'type' => 'boolean'
            ],
            [
                'key' => __('Created by'),
                'type' => 'org',
                'path' => 'Organisation',
            ],
            [
                'key' => __('Created'),
                'sort' => 'created',
                'path' => 'created',
                'type' => 'datetime'
            ],
            [
                'key' => __('Modified'),
                'sort' => 'modified',
                'path' => 'modified',
                'type' => 'datetime'
            ],
            [
                'key' => __('Synced by'),
                'type' => 'org',
                'path' => 'sync_org.name',
                'data_path' => 'sync_org',
                'requirement' => isset($entity['sync_org'])
            ],
            [
                'key' => __('Events'),
                'raw' => __n('{0} event', '{0} events', $entity['event_count'], $entity['event_count']),
                'url' => sprintf('/events/index/searchsharinggroup:%s', h($entity['id']))
            ],
            [
                'key' => __('Organisations'),
                'type' => 'custom',
                'requirement' => isset($entity['SharingGroupOrg']),
                'function' => function (SharingGroup $sharingGroup) {
                    $table = $this->Bootstrap->table(
                       ['hover' => true, 'striped' => true, 'condensed' => true, 'variant' => 'secondary'],
                       [
                           'items' => array_map(fn ($entity) => $entity->toArray(), $sharingGroup->SharingGroupOrg),
                           'fields' => [
                                [ 'label' => __('Name'), 'path' => 'Organisation', 'element' => 'org'], // TODO: [3.x-MIGRATION] $this->OrgImg->getNameWithImg($sgo)
                                [ 'label' => __('Is local'), 'path' => 'Organisation.local', 'element' => 'boolean',],
                                [ 'label' => __('Can extend'), 'path' => 'extend', 'element' => 'boolean',],
                            ],
                       ]
                    );
                    echo $table;
                }
            ],
            [
                'key' => __('Instances'),
                'type' => 'custom',
                'requirement' => isset($entity->SharingGroupServer),
                'function' => function (SharingGroup $sharingGroup) {
                    if (empty($sharingGroup->roaming)) {
                        $cell = $this->Bootstrap->table(
                            ['hover' => true, 'striped' => true, 'condensed' => true, 'variant' => 'secondary'],
                            [
                                'items' => array_map(fn ($entity) => $entity->toArray(), $sharingGroup->SharingGroupServer),
                                'fields' => [
                                    ['label' => __('Name'), 'path' => 'Server.name',], // TODO: [3.x-MIGRATION] $this->OrgImg->getNameWithImg($sgo)
                                    ['label' => __('URL'), 'path' => 'Server.url',],
                                    ['label' => __('All orgs'), 'path' => 'all_orgs', 'element' => 'boolean',],
                                ],
                            ]
                        );
                    } else {
                        $cell = $this->Bootstrap->badge([
                            'text' => __('Roaming mode'),
                            'variant' => 'primary',
                            'size' => 'md',
                        ]);
                    }
                    echo $cell;
                }
            ]
        ]
    ]
);
