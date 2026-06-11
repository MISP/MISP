<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('Event Reports');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('event_reports', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Report'),
        'icon' => 'plus',
        'url' => $baseurl . '/event_reports/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


echo $this->element('EventReports/index', [
    'reports' => $reports,
]);