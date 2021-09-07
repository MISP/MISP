<?php

echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => __('Sharing Group %s', $sg['SharingGroup']['name']),
        'data' => $sg,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'SharingGroup.id'
            ],
            [
                'key' => __('UUID'),
                'path' => 'SharingGroup.uuid'
            ],
            [
                'key' => __('Name'),
                'path' => 'SharingGroup.name'
            ],
            [
                'key' => __('Releasability'),
                'path' => 'SharingGroup.releasability'
            ],
            [
                'key' => __('Description'),
                'path' => 'SharingGroup.description'
            ],
            [
                'key' => __('Selectable'),
                'path' => 'SharingGroup.active',
                'type' => 'boolean'
            ],
            [
                'key' => __('Created by'),
                'path' => 'Organisation',
                'type' => 'org'
            ],
            [
                'key' => __('Synced by'),
                'path' => 'SharingGroup.sync_org',
                'type' => 'org',
                'requirement' => isset($sg['SharingGroup']['sync_org'])
            ],
            [
                'key' => __('Events'),
                'raw' => __n('%s event', '%s events', $sg['SharingGroup']['event_count'], $sg['SharingGroup']['event_count']),
                'url' => sprintf('/events/index/searchsharinggroup:%s', h($sg['SharingGroup']['id']))
            ],
            [
                'key' => __('Organisations'),
                'type' => 'custom',
                'function' => function ($sharingGroup) {
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
                        echo sprintf('<td>%s</td>', $this->OrgImg->getNameWithImg($sgo));
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
                'function' => function ($sharingGroup) {
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
                    foreach ($sharingGroup['SharingGroupServer'] as $sgs) {
                        echo '<tr>';
                        echo sprintf('<td>%s</td>', h($sgs['Server']['name']));
                        echo sprintf('<td>%s</td>', h($sgs['Server']['url']));
                        echo sprintf('<td><span class="%s"></span></td>', $sgs['all_orgs'] ? 'fas fa-check' : 'fas fa-times');
                        echo '</tr>';
                    }
                    echo '</table>
                    </div>';
                }
            ]
        ]
    ]
);
