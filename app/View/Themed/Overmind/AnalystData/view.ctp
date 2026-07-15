<?php
/*
 * Full-page view of a single Analyst Data record (Note / Opinion / Relationship).
 * General tab = the record's metadata card; below it, the attached analyst-data
 * thread (child notes/opinions/relationships + inbound relationships), reusing
 * the shared Elements/AnalystData/thread renderer (also used by the modal
 * fragment viewForObject) without its modal header.
 */
$m = $modelSelection ?? 'Note';
$record = $data[$m] ?? [];

$this->set('headerTitle', h($m) . ' #' . h($record['id'] ?? ''));

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id'    => 'general',
            'title' => __('General'),
            'icon'  => 'fas fa-info-circle',
            'left'  => [
                'AnalystData/View/analystData_general',
            ],
        ],
    ],
]);

// The child analyst data merged onto the record by the controller's afterFind.
$thread = [
    'Note'                => $record['Note'] ?? [],
    'Opinion'             => $record['Opinion'] ?? [],
    'Relationship'        => $record['Relationship'] ?? [],
    'RelationshipInbound' => $record['RelationshipInbound'] ?? [],
];
?>

<div class="container-fluid">
    <div class="card shadow-sm">
        <div class="card-header bg-light d-flex align-items-center gap-2 py-3">
            <i class="fas fa-clipboard-list text-secondary"></i>
            <span class="fw-bold"><?= __('Attached analyst data') ?></span>
        </div>
        <div class="card-body p-0">
            <?= $this->element('AnalystData/thread', [
                'analystData'     => $thread,
                'objectType'      => $m,
                'objectUuid'      => $record['uuid'] ?? '',
                'showModalHeader' => false,
            ]) ?>
        </div>
    </div>
</div>
