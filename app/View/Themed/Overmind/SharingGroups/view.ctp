<?php
$group = $sg['SharingGroup'] ?? [];
$railCards = $railCards ?? [];

$this->set('headerIdentity', $group);
$this->set('headerTitle', $group['name'] ?? '');
$this->set('headerTimestamps', $group);

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
