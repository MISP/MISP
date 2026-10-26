<?php
/*
 * Full-page view of a single Analyst Data record (Note / Opinion / Relationship).
 * General tab = the record's metadata card and the analyst-data thread attached
 * to it (child notes/opinions/relationships + inbound relationships).
 */
$m = $modelSelection ?? 'Note';
$record = $data[$m] ?? [];
$railCards = $railCards ?? [];
$this->set('headerIdentity', $record);
$this->set('headerTimestamps', $record);

$this->set('headerTitle', h($m) . ' #' . h($record['id'] ?? ''));

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'ownership' => [
        'orgc' => $record['Orgc'] ?? [],
        'org' => $record['Org'] ?? [],
        'distribution' => $record['distribution'] ?? null,
        'sharingGroup' => $record['SharingGroup'] ?? [],
    ],
    'tabs' => [
        [
            'id'    => 'general',
            'title' => __('General'),
            'icon'  => 'fas fa-info-circle',
            'left'  => [
                'AnalystData/View/analystData_general',
                'AnalystData/View/analystData_thread',
            ],
            'right' => array_merge([
                'AnalystData/View/analystData_actions',
            ], $this->RailCard->rail($railCards, ['analyst-target', 'analyst-thread'], 'general')),
        ],
    ],
]);
