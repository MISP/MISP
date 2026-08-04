<?php
$this->set('headerTitle', __('Organisation: %s', $org['Organisation']['name'] ?? ''));

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $org,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Organisations/View/organisations_general',
            ],
        ],
    ]
]);
