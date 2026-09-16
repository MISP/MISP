<?php
$isEdit = $this->request->params['action'] === 'edit';
$entry = ($isEdit && !empty($blockEntry['GalaxyClusterBlocklist']))
    ? $blockEntry['GalaxyClusterBlocklist']
    : [];

echo $this->element('genericElementsBS5/Modals/blocklist_form', [
    'model' => 'GalaxyClusterBlocklist',
    'isEdit' => $isEdit,
    'eyebrow' => __('Galaxy Cluster Blocklist'),
    'title' => $isEdit ? __('Edit Blocked Cluster') : __('Block Galaxy Clusters'),
    'description' => __('A blocklisted cluster is never created on this instance, not even through synchronisation.'),
    'icon' => 'misp-icon misp-icon-galaxy misp-simple',
    'uuidLabel' => __('Cluster UUIDs'),
    'uuidValue' => $entry['cluster_uuid'] ?? '',
    'entryId' => $entry['id'] ?? null,
    'fields' => [
        [
            'field' => 'cluster_orgc',
            'label' => __('Creating organisation'),
            'placeholder' => __('The organisation this cluster belongs to'),
            'value' => $entry['cluster_orgc'] ?? '',
        ],
        [
            'field' => 'cluster_info',
            'label' => __('Cluster value'),
            'placeholder' => __('The value to block'),
            'value' => $entry['cluster_info'] ?? '',
            'hint' => __('Best left empty when adding a list of UUIDs — it describes one entry, not all of them.'),
        ],
        [
            'field' => 'comment',
            'label' => __('Comment'),
            'type' => 'textarea',
            'rows' => 2,
            'placeholder' => __('Why this cluster is blocked'),
            'value' => $entry['comment'] ?? '',
        ],
    ],
]);
