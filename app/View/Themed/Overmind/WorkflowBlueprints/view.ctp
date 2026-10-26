<?php
$blueprint = $data['WorkflowBlueprint'] ?? [];

$this->set('headerIdentity', $blueprint);
$this->set('headerTitle', $blueprint['name'] ?? '');
$this->set('headerTimestamps', $blueprint);

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'WorkflowBlueprints/View/workflowBlueprints_general',
                'WorkflowBlueprints/View/workflowBlueprints_steps',
            ],
            'right' => [
                'WorkflowBlueprints/View/workflowBlueprints_actions',
            ],
        ],
    ],
]);
