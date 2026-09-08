<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('SharingGroups', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add SharingGroups'),
        'icon' => 'plus',
        'url' => $baseurl . '/SharingGroups/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'SharingGroup.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'SharingGroup.id',
        'data_path' => 'SharingGroup.id',
        'element' => 'id',
        'url' => $baseurl . '/SharingGroups/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'sort' => 'SharingGroup.uuid',
        'data_path' => 'SharingGroup.uuid',
        'element' => 'uuid',
        'url' => $baseurl . '/SharingGroups/view/%id%',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'SharingGroup.name',
        'data_path' => 'SharingGroup.name, SharingGroup.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Releasable to'),
        'element' => 'custom',
        'function' => function (array $sharingGroup) use ($baseurl) {
            $combined = __("Organisations:");
            if (empty($sharingGroup['SharingGroupOrg'])) {
                $combined .= "<br>N/A";
            } else {
                foreach ($sharingGroup['SharingGroupOrg'] as $sge) {
                    if (!empty($sge['Organisation'])) {
                        $combined .= "<br><a href='" . $baseurl . "/organisation/view/" . h($sge['Organisation']['id']) . "'>" . h($sge['Organisation']['name']) . "</a>";
                        if ($sge['extend']) {
                            $combined .= ' (can extend)';
                        }
                    }
                }
            }
            $combined .= '<hr style="margin:5px 0;"><br>Instances:';
            if (empty($sharingGroup['SharingGroupServer'])) {
                $combined .= "<br>N/A";
            } else {
                foreach ($sharingGroup['SharingGroupServer'] as $sgs) {
                    if ($sgs['server_id'] != 0) {
                        $combined .= "<br><a href='" . $baseurl . "/server/view/" . h($sgs['Server']['id']) . "'>" . h($sgs['Server']['name']) . "</a>";
                    } else {
                        $combined .= "<br>This instance";
                    }
                    if ($sgs['all_orgs']) {
                        $combined .= ' (all organisations)';
                    } else {
                        $combined .= ' (as defined above)';
                    }
                }
            } ?>
            <span data-toggle="popover" data-trigger="hover" title="<?= __('Distribution List') ?>" data-content="<?= h($combined) ?>">
                <?= empty($sharingGroup['SharingGroup']['releasability']) ?
                    '<span style="color: gray">' . __('Not defined') . '</span>' :
                    h($sharingGroup['SharingGroup']['releasability'])
                ?>
            </span>
            <?php
        },
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Creator'),
        'sort' => 'Organisation.name',
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Selectable'),
        'sort' => 'SharingGroup.active',
        'data_path' => 'SharingGroup.active',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Org Count'),
        'sort' => 'SharingGroup.org_count',
        'data_path' => 'SharingGroup.org_count',
        'element' => 'count',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'SharingGroup.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/SharingGroups/view/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/SharingGroups/edit/%id%',
                'requirement' => $me['Role']['perm_sharing_group']
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/SharingGroups/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $me['Role']['perm_sharing_group']
            ]
        ]
    ]

];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $sharingGroups,
            'cards_per_row' => ['' => 1, 'lg' => 2, 'xxxxl' => 3],
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search by SharingGroup name',
                        'name'        => 'value',
                        'mode'        => 'legacy',
                    ],
                ],
                'delete' => '/deleteSelection',
            ],
            'fields' => $fields,
            'primary_id_path' => 'SharingGroup.id',
            'row_dblclick_url' => $baseurl . '/SharingGroups/view/%id%',
        ]
    ],
    'item_url' => '/SharingGroups'
]);