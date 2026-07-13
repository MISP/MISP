<?php
echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'WorkflowBlueprints/View/workflowBlueprints_general',
            ],
        ],
    ]
]);
?>
