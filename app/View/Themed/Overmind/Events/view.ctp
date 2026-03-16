<?php
echo $this->element('genericElementsBS5/layout/object_view_layout',
[
    'title' => $event['Event']['info'],
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'info-circle',
            'cards' => [
                'Events/general',
                'Events/general_statistics'
            ]
        ],
        [
            'id' => 'objects',
            'title' => __('Objects'),
            'icon' => 'cube',
            'count' => $object_count,
            'cards' => [
                'Events/objects'
            ]
        ],
        [
            'id' => 'attributes',
            'title' => __('Attributes'),
            'icon' => 'inbox',
            'count' => $attribute_count,
            'cards' => [
                'Events/attributes'
            ]
        ],
        [
            'id' => 'reports',
            'title' => __('Reports'),
            'icon' => 'file-alt',
            'count' => $report_count ?? 0,
            'cards' => [
                'Events/reports'
            ]
        ],
        [
            'id' => 'graph',
            'title' => __('Graph'),
            'icon' => 'project-diagram',
            'cards' => [
                'Events/graph'
            ]
        ],
        [
            'id' => 'timeline',
            'title' => __('Timeline'),
            'icon' => 'clock',
            'cards' => [
                'Events/timeline'
            ]
        ]
    ],
    'right_part' => [
        'Events/actions'
    ],
    'data' => $event
]);