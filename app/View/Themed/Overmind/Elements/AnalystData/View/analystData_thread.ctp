<?php
/*
 * The analyst data attached to the record: child notes, opinions and
 * relationships, and inbound relationships, as merged by the controller.
 */
$m = $modelSelection ?? 'Note';
$record = $data[$m] ?? [];
$thread = [
    'Note' => $record['Note'] ?? [],
    'Opinion' => $record['Opinion'] ?? [],
    'Relationship' => $record['Relationship'] ?? [],
    'RelationshipInbound' => $record['RelationshipInbound'] ?? [],
];
?>
<div class="card shadow-sm mb-3" id="analyst-thread">
    <div class="card-header bg-light d-flex align-items-center gap-2 py-3">
        <i class="fas fa-clipboard-list text-secondary"></i>
        <span class="fw-bold"><?= __('Attached analyst data') ?></span>
    </div>
    <div class="card-body p-0">
        <?= $this->element('AnalystData/thread', [
            'analystData' => $thread,
            'objectType' => $m,
            'objectUuid' => $record['uuid'] ?? '',
            'showModalHeader' => false,
        ]) ?>
    </div>
</div>
