<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => __('Sharing Group %s', $entity['name']),
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
                'element' => 'org',
                'path' => 'Organisation.name',
                'data_path' => 'Organisation'
            ],
            [
                'key' => __('Synced by'),
                'element' => 'org',
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
                'function' => function (array $sharingGroup) {
                    echo sprintf(
                        '<div class="span6">
                         <table class="table table-striped table-hover table-condensed">
                            <tr>
                                <th>%s</th>
                                <th>%s</th>
                                <th>%s</th>
                            </tr>',
                        __('Name'),
                        __('Is local'),
                        __('Can extend')
                    );
                    foreach ($sharingGroup['SharingGroupOrg'] as $sgo) {
                        echo '<tr>';
                        // TODO: [3.x-MIGRATION]
                        // echo sprintf('<td>%s</td>', $this->OrgImg->getNameWithImg($sgo));
                        echo sprintf('<td><span class="%s"></span></td>', $sgo['Organisation']['local'] ? 'fas fa-check' : 'fas fa-times');
                        echo sprintf('<td><span class="%s"></span></td>', $sgo['extend'] ? 'fas fa-check' : 'fas fa-times');
                        echo '</tr>';
                    }
                    echo '</table>
                    </div>';
                }
            ],
            [
                'key' => __('Instances'),
                'type' => 'custom',
                'requirement' => isset($entity['SharingGroupServer']),
                'function' => function (array $sharingGroup) {
                    echo sprintf(
                        '<div class="span6">
                         <table class="table table-striped table-hover table-condensed">
                            <tr>
                                <th>%s</th>
                                <th>%s</th>
                                <th>%s</th>
                            </tr>',
                        __('Name'),
                        __('URL'),
                        __('All orgs')
                    );
                    foreach ($sharingGroup['SharingGroupServer'] as $entitys) {
                        echo '<tr>';
                        echo sprintf('<td>%s</td>', h($entitys['Server']['name']));
                        echo sprintf('<td>%s</td>', h($entitys['Server']['url']));
                        echo sprintf('<td><span class="%s"></span></td>', $entitys['all_orgs'] ? 'fas fa-check' : 'fas fa-times');
                        echo '</tr>';
                    }
                    echo '</table>
                    </div>';
                }
            ]
        ]
    ]
);
