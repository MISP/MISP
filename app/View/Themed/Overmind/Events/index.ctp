<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

$headerActions = [];
// "Add Event → From Template" entry point — Overmind toolbar parity
// with the default theme (PRD §5.2 F2.1). Renders the searchable
// picker modal once on the page and adds a header action that opens
// it via headerSection's link.onClick callbacSk.
$canPickTemplate = (
    $this->Acl->canAccess('eventTemplates', 'index')
    && $this->Acl->canAccess('eventTemplates', 'instantiate')
);

if ($this->Acl->canAccess('events', 'importEvent')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Import Event'),
        'icon' => 'file-import',
        'url' => $baseurl . '/events/importEvent',
    ];
}

if ($canPickTemplate) {
    $headerActions[] = [
        'type' => 'modal',
        'id' => 'event-template-picker-button',
        'label' => __('From template'),
        'icon' => 'wand-magic-sparkles',
        'url' => '#',
        'onClick' => 'openEventTemplatePicker'
    ];
    echo $this->element('eventTemplates/templatePickerModal');
}

if ($this->Acl->canAccess('events', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Event'),
        'icon' => 'plus',
        'url' => $baseurl . '/events/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


echo $this->element('Events/index', [
    'events' => $events,
    'show_user_button' => true,
    'show_org_button' => true,
]);