<?php
    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $taxonomy,
        'tabs' => [
            [
                'id' => 'general',
                'title' => __('General'),
                'icon' => 'fas fa-info-circle',

                // Content
                'left' => [
                    'Taxonomies/View/taxonomies_general',
                ],
                'right' => [
                    'Taxonomies/View/taxonomies_actions',
                ]
            ],
            [
                'id' => 'tags',
                'title' => __('Tags'),
                'icon' => 'fas fa-tag',
                'count' => $tag_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/taxonomies/taxonomy_tags/%s', h($taxonomy['id']))
                    ]
                ],
            ]
        ]
    ]);
?>

