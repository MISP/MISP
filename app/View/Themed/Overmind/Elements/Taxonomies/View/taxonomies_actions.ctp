<?php
$taxonomyId = $data['id'];
$enabled = $data['enabled'];
$required = $data['required'];
$highlighted = $data['highlighted'];

$actions = [];


if ($isSiteAdmin) {
    if (!$enabled) {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/enable/$taxonomyId",
            'id' => $taxonomyId,
            'icon' => 'fas fa-play',
            'label' => __('Enable Taxonomy'),
            'class' => 'text-success'
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/disable/$taxonomyId",
            'id' => $taxonomyId,
            'icon' => 'fas fa-stop',
            'label' => __('Disable Taxonomy'),
            'class' => 'text-warning'
        ];
    }

    if (!$required) {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/toggleRequired/$taxonomyId",
            'id' => $taxonomyId,
            'required' => $required,
            'icon' => 'fas fa-asterisk',
            'label' => __('Make Taxonomy required'),
            'class' => 'text-success'
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/toggleRequired/$taxonomyId",
            'id' => $taxonomyId,
            'required' => $required,
            'icon' => 'fas fa-question',
            'label' => __('Make Taxonomy optional'),
            'class' => 'text-warning'
        ];
    }

    if (!$highlighted) {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/toggleHighlighted/$taxonomyId",
            'id' => $taxonomyId,
            'icon' => 'fas fa-highlighter',
            'label' => __('Highlight Taxonomy'),
            'class' => 'text-success'
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/toggleHighlighted/$taxonomyId",
            'id' => $taxonomyId,
            'icon' => 'fas fa-down-long',
            'label' => __('Remove Highlight from Taxonomy'),
            'class' => 'text-warning'
        ];
    }

    $actions[] = [
        'url' => "$baseurl/taxonomies/delete/$taxonomyId",
        'onclick' => "event.preventDefault(); openModal('$baseurl/taxonomies/deleteSelection/$taxonomyId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete Taxonomy'),
        'danger' => true
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions
]);
?>
