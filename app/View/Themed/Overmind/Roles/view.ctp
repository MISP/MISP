<?php
$roleChip = $this->element('genericElementsBS5/IndexTable/Fields/role', [
    'row' => $data,
    'field' => ['data_path' => 'Role', 'no_link' => true, 'size' => 'lg'],
]);
$this->set('headerTitleHtml', $roleChip);
$this->set('headerTitle', $data['Role']['name'] ?? '');
$this->set('headerIdentity', $data['Role'] ?? []);

$dates = [];
if (!empty($data['Role']['created'])) {
    $dates[] = '<span title="' . h(__('Created')) . '"><i class="fas fa-calendar-day me-1 opacity-50"></i>'
        . $this->Time->time($data['Role']['created']) . '</span>';
}
if (!empty($data['Role']['modified'])) {
    $dates[] = '<span title="' . h(__('Last modified')) . '"><i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($data['Role']['modified']) . '</span>';
}
$this->set('headerDescription', '<span class="d-inline-flex align-items-center gap-3 flex-wrap">' . implode('', $dates) . '</span>');

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
