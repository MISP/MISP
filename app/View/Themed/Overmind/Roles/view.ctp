<?php
$roleChip = $this->element('genericElementsBS5/IndexTable/Fields/role', [
    'row' => $data,
    'field' => ['data_path' => 'Role', 'no_link' => true, 'size' => 'lg'],
]);
$this->set('headerTitleHtml', $roleChip);

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
            'right' => [
                'Roles/View/roles_actions',
            ],
        ],
    ]
]);
