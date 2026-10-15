<?php
$group = $sg['SharingGroup'] ?? [];
$railCards = $railCards ?? [];

$this->set('headerIdentity', $group);
$this->set('headerTitle', $group['name'] ?? '');

$dates = [];
if (!empty($group['created'])) {
    $dates[] = '<span title="' . h(__('Created')) . '"><i class="fas fa-calendar-day me-1 opacity-50"></i>'
        . $this->Time->time($group['created']) . '</span>';
}
if (!empty($group['modified'])) {
    $dates[] = '<span title="' . h(__('Last modified')) . '"><i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($group['modified']) . '</span>';
}
$this->set('headerDescription', '<span class="d-inline-flex align-items-center gap-3 flex-wrap">' . implode('', $dates) . '</span>');

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $sg,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'SharingGroups/View/sharingGroups_general',
                'SharingGroups/View/sharingGroups_members',
            ],
            'right' => array_merge([
                'SharingGroups/View/sharingGroups_actions',
                'SharingGroups/View/sharingGroups_analyst_data',
            ], $this->RailCard->rail($railCards, [
                'sg-inventory', 'sg-reach', 'sg-blueprint',
            ], 'general')),
        ],
    ],
]);
