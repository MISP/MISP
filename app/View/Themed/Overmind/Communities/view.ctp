<?php
$this->set('headerIdentity', $community);
$this->set('headerTitle', $community['name'] ?? '');

$this->set('headerDescription', '');

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $community,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Communities/View/communities_general',
            ],
            'right' => [
                'Communities/View/communities_actions',
            ],
        ],
    ],
]);
