<?php
$isEdit = $this->request->params['action'] === 'edit';
$entry = ($isEdit && !empty($blockEntry['EventBlocklist']))
    ? $blockEntry['EventBlocklist']
    : [];

echo $this->element('genericElementsBS5/Forms/blocklist_form', [
    'model' => 'EventBlocklist',
    'isEdit' => $isEdit,
    'eyebrow' => __('Event Blocklist'),
    'title' => $isEdit ? __('Edit Blocked Event') : __('Block Events'),
    'description' => __('An event with a blocklisted UUID is never created on this instance, synchronisation included.'),
    'icon' => 'misp-icon misp-icon-event misp-simple',
    'uuidLabel' => __('Event UUIDs'),
    'uuidValue' => $entry['event_uuid'] ?? '',
    'entryId' => $entry['id'] ?? null,
    'fields' => [
        [
            'field' => 'event_orgc',
            'label' => __('Creating organisation'),
            'placeholder' => __('The organisation the event comes from'),
            'value' => $entry['event_orgc'] ?? '',
        ],
        [
            'field' => 'event_info',
            'label' => __('Event info'),
            'type' => 'textarea',
            'rows' => 2,
            'placeholder' => __('What the blocked event was about'),
            'value' => $entry['event_info'] ?? '',
            'hint' => $isEdit
                ? ''
                : __('Best left empty when blocking a list of UUIDs — it is stored on every entry.'),
        ],
        [
            'field' => 'comment',
            'label' => __('Comment'),
            'type' => 'textarea',
            'rows' => 2,
            'placeholder' => __('Why these events are blocked'),
            'value' => $entry['comment'] ?? '',
        ],
    ],
]);
