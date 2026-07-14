<?php
// Overmind BS5 single-view for a Feed. The interactive feed-overlap/compare tool
// from the legacy view is OUT of scope for the CRUD port (coverage/compare is
// tracked in the parent plan); the read-only coverage percentage is kept.
$this->set('headerTitle', __('Feed: %s', $data['Feed']['name'] ?? ''));

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-rss',
            'left' => [
                'Feeds/View/feeds_general',
            ],
        ],
    ],
]);
