<?php

$objectTemplateId = (int)$data['ObjectTemplate']['id'];
$objectTemplateName = (string)$data['ObjectTemplate']['name'];
$activated = !empty($data['ObjectTemplate']['active']);
$fromLibrary = !empty($data['ObjectTemplate']['fixed']);

$actions = [];

if ($isSiteAdmin) {
    if (!$activated) {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/objectTemplates/toggleActive/$objectTemplateId",
            'id' => $objectTemplateId,
            'icon' => 'fas fa-toggle-on',
            'entity' => 'object',
            'label' => __('Activate Object Template'),
            'short' => __('Activate'),
            'class' => 'text-success'
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/objectTemplates/toggleActive/$objectTemplateId",
            'id' => $objectTemplateId,
            'icon' => 'fas fa-toggle-off',
            'entity' => 'object',
            'label' => __('Deactivate Object Template'),
            'short' => __('Deactivate'),
            'class' => 'text-warning'
        ];
    }

    if ($fromLibrary) {
        $updateUrl = $baseurl . '/objectTemplates/update/' . rawurlencode($objectTemplateName);
        $actions[] = [
            'url' => $updateUrl,
            'onclick' => "event.preventDefault(); openModal('" . h($updateUrl) . "', 'md');",
            'icon' => 'fas fa-arrows-rotate',
            'entity' => 'object',
            'label' => __('Update Object Template'),
            'short' => __('Update')
        ];
    }

    $actions[] = [
        'url' => "$baseurl/objectTemplates/delete/$objectTemplateId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/objectTemplates/deleteSelection/$objectTemplateId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Object Template'),
        'danger' => true
    ];
}


echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
?>
