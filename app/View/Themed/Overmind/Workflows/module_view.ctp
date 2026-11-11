<?php
/*
 * One page for the three kinds of module the workflow section lists: a core
 * trigger, an ad-hoc trigger (whose identity is the workflow it starts) and an
 * action/logic module.
 */
$isTrigger = $data['module_type'] === 'trigger';
$isAdhoc = !empty($data['is_adhoc']);
$hasWorkflow = !empty($data['Workflow']['id']);

if ($isAdhoc && $hasWorkflow) {
    $this->set('headerTitle', $data['Workflow']['name']);
    $this->set('headerDescription', !empty($data['Workflow']['description'])
        ? $data['Workflow']['description']
        : $data['description']);
} else {
    $this->set('headerTitle', $data['name']);
    $this->set('headerDescription', $data['description'] ?? '');
}
$this->set('headerActions', []);

$generalLeft = ['Workflows/View/module_general'];
if (!empty($data['params'])) {
    $generalLeft[] = 'Workflows/View/module_params';
}
$generalRight = ['Workflows/View/module_actions'];
if ($isTrigger) {
    $generalRight[] = 'Workflows/View/module_workflow';
}

$tabs = [
    [
        'id' => 'general',
        'title' => __('General'),
        'icon' => 'fas fa-info-circle',
        'left' => $generalLeft,
        'right' => $generalRight,
    ],
];
if ($isTrigger && $hasWorkflow) {
    $tabs[] = [
        'id' => 'execution-path',
        'title' => __('Execution path'),
        'icon' => 'fas fa-diagram-project',
        'count' => count(array_diff_key($data['Workflow']['data'] ?? [], ['_frames' => true])),
        'description' => __('The graph run when this trigger fires. Read-only: open the editor to change it.'),
        'left' => ['Workflows/View/module_execution_path'],
    ];
}
if (!$isTrigger) {
    $tabs[] = [
        'id' => 'test',
        'title' => __('Test module'),
        'icon' => 'fas fa-flask',
        'description' => __('Run this module once against data you supply, outside of any workflow.'),
        'left' => ['Workflows/View/module_test'],
    ];
}

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => $tabs,
]);
