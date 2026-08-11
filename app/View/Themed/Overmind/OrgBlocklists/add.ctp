<?php
$isEdit = $this->request->params['action'] === 'edit';
$entry = ($isEdit && !empty($blockEntry['OrgBlocklist']))
    ? $blockEntry['OrgBlocklist']
    : [];

echo $this->element('genericElementsBS5/Forms/blocklist_form', [
    'model' => 'OrgBlocklist',
    'isEdit' => $isEdit,
    'eyebrow' => __('Organisation Blocklist'),
    'title' => $isEdit ? __('Edit Blocked Organisation') : __('Block Organisations'),
    'description' => __('No event of a blocklisted organisation is created or synchronised here; its local users keep their access.'),
    'icon' => 'fas fa-building',
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
            'placeholder' => __('Why this organisation is blocked'),
            'value' => $entry['comment'] ?? '',
        ],
    ],
]);
