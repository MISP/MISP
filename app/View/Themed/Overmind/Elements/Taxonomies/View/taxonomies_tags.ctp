<?php

if ($taxonomy['enabled']) {
    $fields = [
        [
        'element' => 'checkbox',
        'data_path' => 'existing_tag.id',
        'card_section' => 'selector',
        ],
        [
            'name' => __('Tag'),
            //'sort' => 'existing_tag.Tag',
            'data_path' => 'existing_tag.Tag',
            'element' => 'tag_name',
            'card_section' => 'tag',
            'display_in' => ['table','card']
        ],
        [
            'name' => __('Informations'),
            //'sort' => 'expanded',
            'data_path' => 'expanded, description',
            'element' => 'name_description',
            'card_section' => 'title',
            'display_in' => ['table', 'card']
        ],
        [
            'name' => __('Enabled'),
            //'sort' => 'existing_tag.Tag.hide_tag',
            'data_path' => 'existing_tag.Tag.hide_tag',
            'element' => 'enabled',
            'boolean_reverse' => true,
            'card_section' => 'top',
            'display_in' => ['table', 'card']
        ],
        [
            'name' => __('Relations'),
            'data_path' => 'events, attributes, existing_tag.Tag.id',
            'element' => 'tag_relations',
            'card_section' => 'meta',
            'display_in' => ['table','card']
        ],
        [
            'name' => __('Actions'),
            'element' => 'row_actions',
            'data_path' => 'existing_tag.id',
            'card_section' => 'extra',
            'display_in' => ['table','card'],
            'actions' => [
                [
                    'type' => 'modal',
                    'label' => __('Create Tag'),
                    'icon' => 'plus',
                    'url' => $baseurl . '/taxonomies/addTag/taxonomy_id:' . $taxonomy['id'] . '/name:%tag%',
                    'url_params_data_paths' => ['tag' => 'tag'],
                    'requirement' => function ($row) use ($isAclTagger, $taxonomy) {
                        return $isAclTagger && $taxonomy['enabled'] && empty($row['existing_tag']);
                    }
                ],
                [
                    'type' => 'navigate',
                    'label' => __('View graph'),
                    'icon' => 'eye',
                    'url' => $baseurl . '/tags/viewGraph/%id%',
                    'requirement' => function ($row) use ($isAclTagger, $taxonomy) {
                        return $isAclTagger && $taxonomy['enabled'] && !empty($row['existing_tag']);
                    }
                ],
                [
                    'type' => 'modal',
                    'label' => __('Update'),
                    'icon' => 'sync',
                    'url' => $baseurl . '/taxonomies/addTag/taxonomy_id:' . $taxonomy['id'] . '/update:1/name:%tag%',
                    'url_params_data_paths' => ['tag' => 'tag'],
                    'requirement' => function ($row) use ($isAclTagger, $taxonomy) {
                        return $isAclTagger && $taxonomy['enabled'] && !empty($row['existing_tag']) && empty($row['existing_tag']['Tag']['hide_tag']);
                    }
                ],
                [
                    'type' => 'modal',
                    'label' => __('Enable'),
                    'icon' => 'play',
                    'url' => $baseurl . '/taxonomies/addTag/taxonomy_id:' .  $taxonomy['id'] . '/enable:1/name:%tag%',
                    'url_params_data_paths' => ['tag' => 'tag'],
                    'requirement' => function ($row) use ($isAclTagger, $taxonomy) {
                        return $isAclTagger && $taxonomy['enabled'] && !empty($row['existing_tag']) && !empty($row['existing_tag']['Tag']['hide_tag']);
                    }
                ],
                [
                    'type' => 'modal',
                    'label' => __('Disable'),
                    'icon' => 'stop',
                    'url' => $baseurl . '/taxonomies/disableTag/taxonomy_id:' .  $taxonomy['id'] . '/name:%tag%',
                    'url_params_data_paths' => ['tag' => 'tag'],
                    'requirement' => function ($row) use ($isAclTagger, $taxonomy) {
                        return $isAclTagger && $taxonomy['enabled'] && !empty($row['existing_tag']) && empty($row['existing_tag']['Tag']['hide_tag']);
                    }
                ]
            ]
        ],
    ];
} else {
    $fields = [
        [
            'name' => __('Tag'),
            //'sort' => 'existing_tag.Tag',
            'data_path' => 'existing_tag.Tag',
            'element' => 'tag_name',
            'card_section' => 'tag',
            'display_in' => ['table','card']
        ],
        [
            'name' => __('Informations'),
            //'sort' => 'expanded',
            'data_path' => 'expanded, description',
            'element' => 'name_description',
            'card_section' => 'title',
            'display_in' => ['table', 'card']
        ]
    ];
    }


/**
 * Scaffold
 */
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $entries,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search by tag name'),
                        'name'          => 'filter',
                        'mode'      => 'legacy',
                    ],
                ],
                //'enable' => 1,
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/taxonomies/view/' . $id
]);

?>