<?php
$isEdit = $this->request->params['action'] === 'edit';
$entry = ($isEdit && !empty($blockEntry['SightingBlocklist']))
    ? $blockEntry['SightingBlocklist']
    : [];

echo $this->element('genericElementsBS5/Forms/blocklist_form', [
    'model' => 'SightingBlocklist',
    'isEdit' => $isEdit,
    'eyebrow' => __('Sighting Blocklist'),
    'title' => $isEdit ? __('Edit Blocked Organisation') : __('Block Sightings'),
    'description' => __('Sightings from a blocklisted organisation are neither created nor synchronised here; its other data is untouched.'),
    'icon' => 'misp-icon misp-icon-sighting misp-simple',
    'uuidLabel' => __('Organisation UUIDs'),
    'uuidValue' => $entry['org_uuid'] ?? '',
    'entryId' => $entry['id'] ?? null,
    'fields' => [
        [
            'field' => 'org_name',
            'label' => __('Organisation name'),
            'placeholder' => __('The name this UUID belongs to'),
            'value' => $entry['org_name'] ?? '',
        ],
        [
            'field' => 'comment',
            'label' => __('Comment'),
            'type' => 'textarea',
            'rows' => 2,
            'placeholder' => __('Why this organisation\'s sightings are blocked'),
            'value' => $entry['comment'] ?? '',
        ],
    ],
]);
