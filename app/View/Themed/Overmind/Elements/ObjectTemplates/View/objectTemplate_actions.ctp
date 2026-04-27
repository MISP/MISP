<?php

$objectTemplateId = h($data['ObjectTemplate']['id']);
$objectTemplateName = h($data['ObjectTemplate']['name']);
$activated = h($data['ObjectTemplate']['active']);

$actions = [];

if ($isSiteAdmin) {
    if (!$activated) {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/objectTemplates/toggleActive/$objectTemplateId",
            'id' => $objectTemplateId,
            'icon' => 'fas fa-play',
            'label' => __('Activate Object Template'),
            'class' => 'text-success'
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/objectTemplates/toggleActive/$objectTemplateId",
            'id' => $objectTemplateId,
            'icon' => 'fas fa-stop',
            'label' => __('Deactivate Object Template'),
            'class' => 'text-warning'
        ];
    }

    $actions[] = [
        'url' => "$baseurl/objectTemplates/update/$objectTemplateName/$objectTemplateId",
        'icon' => 'fas fa-sync',
        'label' => __('Update Object Template')
    ];

    $actions[] = [
        'url' => "$baseurl/objectTemplates/delete/$objectTemplateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/objectTemplates/deleteSelection/$objectTemplateId', 'sm');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Object Template'),
        'danger' => true
    ];
}


echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>
