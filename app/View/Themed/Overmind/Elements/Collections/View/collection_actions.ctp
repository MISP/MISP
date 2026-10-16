<?php

$collectiontId = h($data['Collection']['id']);
$mayModify = $this->Acl->canModifyCollection($data);

$actions = [];

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
