<?php

$templateId = h($data['Template']['id']);

$actions = [];

if ($isSiteAdmin) {
    $actions[] = [
        'url' => "$baseurl/templateElements/addV2/$templateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/templateElements/addV2/$templateId');",
        'icon' => 'fas fa-file-code',
        'label' => __('Add Element to Template')
    ];

    $actions[] = [
        'url' => "$baseurl/templates/edit/$templateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/templates/edit/$templateId');",
        'icon' => 'fas fa-pen',
        'label' => __('Edit Template')
    ];

    $actions[] = [
        'url' => "$baseurl/templates/delete/$templateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/templates/deleteSelection/$templateId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Template'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>
