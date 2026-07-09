<?php
$this->set('headerTitle', __('Auth key #%s', h($data['AuthKey']['id'])));

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-key',
            'left' => [
                'AuthKeys/View/authkeys_general',
            ],
            'right' => [
                'AuthKeys/View/authkeys_actions',
            ],
        ],
    ],
]);
