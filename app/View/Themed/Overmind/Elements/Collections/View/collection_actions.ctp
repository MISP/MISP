<?php

$collectiontId = h($data['Collection']['id']);
$mayModify = $this->Acl->canModifyCollection($data);

$actions = [];

// The workspace follows the collection rule, not the page's
$canWorkspace = !empty($intelGraph) && $this->Acl->canAccess('collections', 'active')
    && ClassRegistry::init('Collection')->canModify($me, $data['Collection']);
if ($canWorkspace) {
    $actions[] = [
        'url' => '#',
        'icon' => 'misp-icon misp-icon-analyst-graph misp-simple',
        'label' => __('Make it my workspace'),
        'short' => __('Workspace'),
        'attributes' => ['data-intel-graph-workspace' => strtolower($data['Collection']['uuid'])],
    ];
}

if ($isSiteAdmin || $mayModify) {
    $actions[] = [
        'url' => "$baseurl/CollectionElements/add/$collectiontId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/CollectionElements/add/$collectiontId');",
        'icon' => 'fas fa-file',
        'add' => true,
        'label' => __('Add Element to Collection'),
        'short' => __('Add element')
    ];

    $actions[] = [
        'url' => "$baseurl/collections/edit/$collectiontId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/collections/edit/$collectiontId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Collection'),
        'short' => __('Edit')
    ];

    $actions[] = [
        'url' => "$baseurl/collections/delete/$collectiontId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/collections/deleteSelection/$collectiontId');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Collection'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
?>
