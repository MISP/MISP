<?php
$blueprintId = (int)$data['WorkflowBlueprint']['id'];

$actions = [];
if ($this->Acl->canAccess('workflowBlueprints', 'edit')) {
    $actions[] = [
        'url' => "$baseurl/workflowBlueprints/edit/$blueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/workflowBlueprints/edit/$blueprintId');",
        'icon' => 'fas fa-pen-to-square',
        'label' => __('Edit'),
    ];
}
if ($this->Acl->canAccess('workflowBlueprints', 'export')) {
    // export answers with Content-Disposition: attachment, the page stays put.
    $actions[] = [
        'url' => "$baseurl/workflowBlueprints/export/$blueprintId",
        'icon' => 'fas fa-download',
        'label' => __('Export'),
    ];
}
if ($this->Acl->canAccess('workflowBlueprints', 'delete')) {
    $actions[] = [
        'url' => "$baseurl/workflowBlueprints/deleteSelection/$blueprintId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/workflowBlueprints/deleteSelection/$blueprintId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions,
]);
