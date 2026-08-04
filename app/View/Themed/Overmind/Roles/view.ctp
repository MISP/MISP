<?php
$this->set('headerTitle', __('Role: %s', $data['Role']['name'] ?? ''));

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Roles/View/roles_general',
            ],
        ],
    ]
]);
?>
