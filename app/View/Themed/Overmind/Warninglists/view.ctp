<?php
$list = $warninglist['Warninglist'] ?? [];

$this->set('headerIdentity', $list);
$this->set('headerTitle', $list['name'] ?? '');
$this->set('headerDescription', '');

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $warninglist,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Warninglists/View/warninglists_general',
                'Warninglists/View/warninglists_values',
            ],
            'right' => [
                'Warninglists/View/warninglists_actions',
            ],
        ],
    ],
]);
