<?php
$blueprint = $data['WorkflowBlueprint'] ?? [];

$this->set('headerIdentity', $blueprint);
$this->set('headerTitle', $blueprint['name'] ?? '');
$this->set('headerDescription', empty($blueprint['timestamp'])
    ? ''
    : '<span title="' . h(__('Last modified')) . '"><i class="fas fa-edit me-1 opacity-50"></i>' . $this->Time->time($blueprint['timestamp']) . '</span>');

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
