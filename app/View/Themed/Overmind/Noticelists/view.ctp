<?php
$noticelist = $data['Noticelist'] ?? [];

$this->set('headerIdentity', $noticelist);
$this->set('headerTitle', $noticelist['name'] ?? '');
$this->set('headerDescription', '');

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Noticelists/View/noticelists_general',
                'Noticelists/View/noticelists_values',
            ],
            'right' => [
                'Noticelists/View/noticelists_actions',
            ],
        ],
    ],
]);
