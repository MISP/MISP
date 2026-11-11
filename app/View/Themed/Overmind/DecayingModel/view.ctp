<?php
$dm = $decaying_model['DecayingModel'];

$this->set('headerTitle', $dm['name']);
$this->set('headerDescription', !empty($dm['description']) ? $dm['description'] : __('Decaying model configuration and scoring curve.'));

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $decaying_model,
    'tabs' => [
        [
            'id' => 'overview',
            'title' => __('Overview'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'DecayingModel/View/decaying_model_general',
                'DecayingModel/View/decaying_model_curve',
            ],
            'right' => [
                'DecayingModel/View/decaying_model_actions',
                'DecayingModel/View/decaying_model_types',
            ],
        ],
    ],
]);
