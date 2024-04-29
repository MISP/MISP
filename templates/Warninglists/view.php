<?php

echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => __('Warninglist View'),
        'data' => $entity,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'id'
            ],
            [
                'key' => __('Name'),
                'path' => 'name'
            ],
            [
                'key' => __('Description'),
                'path' => 'description'
            ],
            [
                'key' => __('Version'),
                'path' => 'version'
            ],
            [
                'key' => __('Category'),
                'path' => 'category',
                'function' => function (array|\App\Model\Entity\Warninglist $row) use ($possibleCategories) {
                    return $possibleCategories[$row['category']];
                }
            ],
            [
                'key' => __('Type'),
                'path' => 'type'
            ],
            [
                'key' => __('Accepted attribute types'),
                'path' => 'type' // FIXME
            ]
        ],
        'children' => [
            [
                'url' => '/warninglists/preview_entries/{{0}}',
                'url_params' => ['id'],
                'title' => __('Values'),
                'elementId' => 'preview_entries_container'
            ]
        ]
    ]
);


// $types = implode(', ', array_column($warninglist['WarninglistType'], 'type'));
// $table_data = [
//     ['key' => __('ID'), 'value' => $entity['id']],
//     ['key' => __('Name'), 'value' => $entity['name']],
//     ['key' => __('Description'), 'value' => $entity['description']],
//     ['key' => __('Version'), 'value' => $entity['version']],
//     ['key' => __('Category'), 'value' => $possibleCategories[$entity['category']]],
//     ['key' => __('Type'), 'value' => $entity['type']],
//     ['key' => __('Accepted attribute types'), 'value' => $types],
//     [
//         'key' => __('Enabled'),
//         'boolean' => $entity['enabled'],
//         'html' => $me['Role']['perm_warninglist'] ? sprintf(
//             ' <a href="%s/warninglists/enableWarninglist/%s%s" title="%s">%s</a>',
//             $baseurl,
//             h($warninglist['Warninglist']['id']),
//             $entity['enabled'] ? '' : '/1',
//             $entity['enabled'] ? __('Disable') : __('Enable'),
//             $entity['enabled'] ? __('Disable') : __('Enable')
//         ) : '',
//     ],
// ];

// $values = [];
// foreach ($warninglist['WarninglistEntry'] as $entry) {
//     $value = '<span class="warninglist-value">' . h($entry['value']) . '</span>';
//     if ($entry['comment']) {
//         $value .= ' <span class="warninglist-comment"># ' . h($entry['comment']) . '</span>';
//     }
//     $values[] = $value;
// }

// echo '<div class="warninglist view">';
// echo sprintf(
//     '<div class="row-fluid"><div class="span8" style="margin:0;">%s</div></div><h4>%s</h4>',
//     sprintf(
//         '<h2>%s</h2>%s',
//         h($warninglist['Warninglist']['name']),
//         $this->element('genericElements/viewMetaTable', ['table_data' => $table_data])
//     ),
//     __('Values')
// );
// echo implode('<br>', $values);
// echo '</div>';
// echo $this->element(
//     '/genericElements/SideMenu/side_menu',
//     [
//         'menuList' => 'warninglist',
//         'menuItem' => 'view',
//         'id' => $entity['id'],
//         'isDefault' => $entity['default'] == 1,
//     ]
// );
