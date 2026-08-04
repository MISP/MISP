<?php

$report = $data['EventReport'] ?? [];
$event = $data['Event'] ?? [];
$sharingGroup = $data['SharingGroup'] ?? [];


$descParts = [];
if (!empty($report['date'])) {
    $descParts[] = '<span>'
        . '<i class="fas fa-calendar-day me-1 opacity-50"></i>'
        . h($report['date'])
        . '</span>';
}
if (!empty($report['timestamp'])) {
    $descParts[] = '<span>'
        . '<i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($report['timestamp'])
        . '</span>';
}
$headerDescription = '<span class="d-inline-flex gap-3 flex-wrap">'
    . implode('', $descParts)
    . '</span>';
$this->set('headerDescription', $headerDescription);

?>

<div class="card mb-3 shadow-sm">
    <div class="card-body">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>
            <div class="fw-semibold fs-5">
                <?= h($report['name'] ?? '') ?>
            </div>
        </div>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    ID
                </div>
                <div class="bg-light rounded px-2 py-1 d-inline-block">
                    <?= h($report['id'] ?? '') ?>
                </div>
            </div>

            <!-- UUID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    UUID
                </div>
                <div class="d-flex align-items-center gap-2">
                    <div class="bg-light rounded px-2 py-1 font-monospace small">
                        <?= h($report['uuid'] ?? '') ?>
                    </div>
                    <button
                        class="text-muted border-0 bg-white"
                        onclick="copyToClipboard(this, '<?= h($report['uuid'] ?? '') ?>')"
                        data-bs-toggle="tooltip"
                        title="<?= __('Copy UUID') ?>"
                        aria-label="<?= __('Copy UUID') ?>">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </div>

            <!-- DISTRIBUTION -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Distribution') ?>
                </div>
                <?= $this->element('genericElementsBS5/Badges/distribution', [
                    'distribution' => (int)($report['distribution'] ?? 0),
                    'full' => true
                ]); ?>
            </div>

            <!-- EVENT -->
            <div class="col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Event') ?>
                </div>
                <?= $this->element('genericElementsBS5/Badges/event', [
                    'id' => $report['event_id'] ?? null,
                    'name' => $event['info'] ?? null,
                    'url' => $baseurl . '/events/view2/' . ($report['event_id'] ?? ''),
                    'org' => $event['Org'] ?? []
                ]); ?>
            </div>

            <?php if (!empty($report['deleted'])): ?>
            <!-- DELETED -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Status') ?>
                </div>
                <span class="badge bg-danger">
                    <i class="fas fa-trash-alt me-1"></i>
                    <?= __('Deleted') ?>
                </span>
            </div>
            <?php endif; ?>

            <?php if ((int)($report['distribution'] ?? -1) === 4 && !empty($sharingGroup)): ?>
            <!-- SHARING GROUP -->
            <div class="col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Sharing Group') ?>
                </div>
                <a href="<?= h($baseurl . '/sharing_groups/view/' . ($sharingGroup['id'] ?? '')) ?>">
                    <span class="misp-icon misp-icon-sharing-group misp-simple me-1"></span>
                    <?= h($sharingGroup['name'] ?? '') ?>
                </a>
            </div>
            <?php endif; ?>

        </div>

    </div>
</div>
