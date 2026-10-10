<?php
$this->set('headerTitle', __('Value'));
$this->set('headerDescription', __('The attributes holding this value that you can see.'));

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => ['Value' => $value, 'Attribute' => $attributes],
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Values/View/value_general',
                'Values/View/value_attributes',
            ],
        ],
    ],
]);
