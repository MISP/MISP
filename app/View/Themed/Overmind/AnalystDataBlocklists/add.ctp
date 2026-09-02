<?php
$isEdit = $this->request->params['action'] === 'edit';
$entry = ($isEdit && !empty($blockEntry['AnalystDataBlocklist']))
    ? $blockEntry['AnalystDataBlocklist']
    : [];

echo $this->element('genericElementsBS5/Modals/blocklist_form', [
    'model' => 'AnalystDataBlocklist',
    'isEdit' => $isEdit,
    'eyebrow' => __('Analyst Data Blocklist'),
    'title' => $isEdit ? __('Edit Blocked Analyst Data') : __('Block Analyst Data'),
    'description' => __('Blocklisted analyst data is never created on this instance, not even through synchronisation.'),
    'icon' => 'fas fa-clipboard-list',
    'uuidLabel' => __('Analyst Data UUIDs'),
    'uuidValue' => $entry['analyst_data_uuid'] ?? '',
    'entryId' => $entry['id'] ?? null,
    'fields' => [
        [
            'field' => 'analyst_data_orgc',
            'label' => __('Creating organisation'),
            'placeholder' => __('The organisation this analyst data belongs to'),
            'value' => $entry['analyst_data_orgc'] ?? '',
        ],
        [
            'field' => 'analyst_data_info',
            'label' => __('Analyst data value'),
            'placeholder' => __('The value to block'),
            'value' => $entry['analyst_data_info'] ?? '',
            'hint' => __('Best left empty when adding a list of UUIDs — it describes one entry, not all of them.'),
        ],
        [
            'field' => 'comment',
            'label' => __('Comment'),
            'type' => 'textarea',
            'rows' => 2,
            'placeholder' => __('Why this analyst data is blocked'),
            'value' => $entry['comment'] ?? '',
        ],
    ],
]);
