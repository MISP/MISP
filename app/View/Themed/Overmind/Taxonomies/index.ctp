<?php
$fields = [
    [
        'element' => 'selector',
        'data_path' => 'Taxonomy.id',
        'enable_path' => 'Taxonomy.enabled',
        'require_path' => 'Taxonomy.required',
        'highlight_path' => 'Taxonomy.highlighted',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/taxonomies/view/%id%'
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Disable'),
                'label_off' => __('Enable'),
                'icon_on' => 'stop text-danger',
                'icon_off' => 'play text-success',
                'url' => '/taxonomies/%action%/%id%',
                'enable_path' => 'Taxonomy.enabled',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Optional'),
                'label_off' => __('Require'),
                'icon_on' => 'question text-dark',
                'icon_off' => 'asterisk text-dark',
                'url' => '/taxonomies/%action%/%id%',
                'require_path' => 'Taxonomy.required',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Remove Highlight'),
                'label_off' => __('Highlight'),
                'icon_on' => 'down-long text-primary',
                'icon_off' => 'highlighter text-primary',
                'url' => '/taxonomies/%action%/%id%',
                'highlight_path' => 'Taxonomy.highlighted',
                'requirement' => $isSiteAdmin
            ]
        ]
    ],
    [
        'name' => __('ID'),
        'sort' => 'Taxonomy.id',
        'data_path' => 'Taxonomy.id',
        'element' => 'id',
        'url' => $baseurl . '/taxonomies/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Namespace'),
        'sort' => 'Taxonomy.namespace',
        'data_path' => 'Taxonomy.namespace, Taxonomy.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Version'),
        'data_path' => 'Taxonomy.version',
        'element' => 'version',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'Taxonomy.enabled',
        'data_path' => 'Taxonomy.enabled',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Required'),
        'sort' => 'Taxonomy.required',
        'data_path' => 'Taxonomy.required',
        'element' => 'required',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Highlighted'),
        'sort' => 'Taxonomy.highlighted',
        'data_path' => 'Taxonomy.highlighted',
        'element' => 'highlighted',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Active Tags'),
        'element' => 'custom',
        'class' => 'shortish',
        'function' => function (array $item) use ($isSiteAdmin) {
            $content = '<strong>' . h($item['current_count']) . '</strong> / ' . h($item['total_count']);
            if ($item['current_count'] != $item['total_count'] && $isSiteAdmin && $item['Taxonomy']['enabled']) {
                $content .= ' (' . $this->Form->postLink(__('enable all'), array('action' => 'addTag', h($item['Taxonomy']['id'])), array('title' => __('Enable all tags')), __('Are you sure you want to enable every tag associated to this taxonomy?')) . ')';
            }
            return $content;
        }
    ]
];

if ($this->Acl->canAccess('taxonomies', 'update')) {
    $this->set('headerActions', [
        [
            'type' => 'post',
            'label' => __('Update Taxonomies'),
            'icon' => 'sync',
            'url' => $baseurl . '/taxonomies/update'
        ]
    ]);
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search by taxonomies name',
                        'name'        => 'value',
                        'mode'        => 'legacy',
                    ],
                ],
                'delete' => '/deleteSelection',
                'enable' => 1,
                'require' => 1,
                'highlight' => 1,
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/taxonomies'
]);