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
            'icon' => 'fas fa-toggle-on',
            'entity' => 'tag',
            'label' => __('Enable Taxonomy'),
            'short' => __('Enable'),
            'class' => 'text-success'
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/disable/$taxonomyId",
            'id' => $taxonomyId,
            'icon' => 'fas fa-toggle-off',
            'entity' => 'tag',
            'label' => __('Disable Taxonomy'),
            'short' => __('Disable'),
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
            'entity' => 'tag',
            'label' => __('Make Taxonomy required'),
            'short' => __('Required'),
            'class' => 'text-success'
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/toggleRequired/$taxonomyId",
            'id' => $taxonomyId,
            'required' => $required,
            'icon' => 'fas fa-question',
            'entity' => 'tag',
            'label' => __('Make Taxonomy optional'),
            'short' => __('Optional'),
            'class' => 'text-warning'
        ];
    }

    if (!$highlighted) {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/toggleHighlighted/$taxonomyId",
            'id' => $taxonomyId,
            'icon' => 'fas fa-highlighter',
            'entity' => 'tag',
            'label' => __('Highlight Taxonomy'),
            'short' => __('Highlight'),
            'class' => 'text-success'
        ];
    } else {
        $actions[] = [
            'type' => 'post',
            'url' => "$baseurl/taxonomies/toggleHighlighted/$taxonomyId",
            'id' => $taxonomyId,
            'icon' => 'fas fa-down-long',
            'entity' => 'tag',
            'label' => __('Remove Highlight from Taxonomy'),
            'short' => __('Unhighlight'),
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

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions
]);
?>
