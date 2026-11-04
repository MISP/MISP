<?php
$isTrigger = $data['module_type'] === 'trigger';
$isAdhoc = !empty($data['is_adhoc']);
$workflowId = !empty($data['Workflow']['id']) ? (int)$data['Workflow']['id'] : null;
$moduleId = h($data['id']);
$canManage = !empty($isSiteAdmin);

$actions = [];

if ($canManage) {
    // toggleModule($module_id, $enabled, $is_trigger)
    $suffix = $isTrigger ? '/1' : '';
    if (empty($data['disabled'])) {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/workflows/toggleModule/$moduleId/0$suffix",
            'icon' => 'fas fa-stop',
            'label' => $isAdhoc ? __('Disable workflow') : ($isTrigger ? __('Disable trigger') : __('Disable module')),
            'warning' => true,
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/workflows/toggleModule/$moduleId/1$suffix",
            'icon' => 'fas fa-play',
            'label' => $isAdhoc ? __('Enable workflow') : ($isTrigger ? __('Enable trigger') : __('Enable module')),
            'success' => true,
        ];
    }
}

if ($isTrigger) {
    if ($workflowId) {
        $actions[] = [
            'url' => "$baseurl/workflows/editor/$workflowId",
            'icon' => 'fas fa-code',
            'label' => __('Open in editor'),
        ];
    } elseif (!$isAdhoc) {
        // The editor creates the workflow of a trigger that has none yet.
        $actions[] = [
            'url' => "$baseurl/workflows/editor/$moduleId",
            'icon' => 'fas fa-plus',
            'label' => __('Create its workflow'),
        ];
    }
}

if ($isAdhoc && $workflowId && $canManage) {
    if (($data['trigger_scope'] ?? null) === 'events') {
        $actions[] = [
            'url' => "$baseurl/workflows/executeWorkflow/$workflowId",
            'onclick' => "event.preventDefault(); openModal('$baseurl/workflows/executeWorkflow/$workflowId');",
            'icon' => 'fas fa-play-circle',
            'label' => __('Run workflow'),
        ];
    }
    $actions[] = [
        'url' => "$baseurl/workflows/edit/$workflowId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/workflows/edit/$workflowId');",
        'icon' => 'fas fa-pen-to-square',
        'label' => __('Edit'),
    ];
}

if ($workflowId) {
    $actions[] = [
        'url' => "$baseurl/admin/logs/index/model:Workflow/action:execute_workflow/model_id:$workflowId",
        'icon' => 'fas fa-rectangle-list',
        'label' => __('Execution logs'),
    ];
    if ($canManage) {
        $debugOn = !empty($data['Workflow']['debug_enabled']);
        $actions[] = [
            'url' => "$baseurl/workflows/toggleDebugMode/$workflowId/" . ($debugOn ? '0' : '1'),
            'onclick' => "event.preventDefault(); openModal('$baseurl/workflows/toggleDebugMode/$workflowId/" . ($debugOn ? '0' : '1') . "', 'md');",
            'icon' => $debugOn ? 'fas fa-bug-slash' : 'fas fa-bug',
            'label' => $debugOn ? __('Disable debug mode') : __('Enable debug mode'),
        ];
    }
}

if ($isAdhoc && $workflowId && $canManage) {
    $actions[] = ['divider' => true];
    $actions[] = [
        'url' => "$baseurl/workflows/deleteSelection/$workflowId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/workflows/deleteSelection/$workflowId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete workflow'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions,
]);
