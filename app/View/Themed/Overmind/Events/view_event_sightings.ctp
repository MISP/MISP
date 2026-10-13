<?php
$total = $positive + $negative + $expiration;
$restricted = !Configure::read('Plugin.Sightings_policy');
$tiles = [
    ['count' => $positive, 'label' => __('Sightings'), 'icon' => 'fas fa-thumbs-up', 'tone' => 'success'],
    ['count' => $negative, 'label' => __('False positives'), 'icon' => 'fas fa-thumbs-down', 'tone' => 'danger'],
    ['count' => $expiration, 'label' => __('Expirations'), 'icon' => 'fas fa-clock', 'tone' => 'warning'],
];
?>
<div data-sighting-total="<?= (int)$total ?>">

<?php if ($total === 0): ?>
    <div class="d-flex flex-column align-items-center justify-content-center text-muted py-4">
        <span class="misp-icon misp-icon-sighting misp-hexagone mb-2 opacity-50 fs-3"></span>
        <p class="mb-0 small fw-semibold"><?= __('No sightings recorded yet.') ?></p>
    </div>
<?php else: ?>
    <div class="d-flex gap-2 p-3">
        <?php foreach ($tiles as $tile): ?>
            <div class="flex-fill rounded-3 p-2 d-flex flex-column gap-1 border border-<?= $tile['tone'] ?>-subtle bg-<?= $tile['tone'] ?>-subtle">
                <div class="d-flex align-items-center gap-2 small text-<?= $tile['tone'] ?>-emphasis fw-semibold">
                    <i class="<?= $tile['icon'] ?>"></i>
                    <span class="text-truncate"><?= $tile['label'] ?></span>
                </div>
                <div class="fw-bold fs-4 lh-1 text-<?= $tile['tone'] ?>-emphasis"><?= (int)$tile['count'] ?></div>
            </div>
        <?php endforeach; ?>
    </div>
    <div class="px-3 pb-3 small text-muted">
        <span class="misp-icon misp-icon-organisation misp-simple me-1"></span>
        <?= __('%s from your organisation', '<strong class="text-body">' . (int)$own . '</strong>') ?>
    </div>
<?php endif; ?>

<?php if ($restricted): ?>
    <div class="px-3 pb-3 small text-muted">
        <i class="fas fa-circle-info me-1"></i><?= __('Restricted to your own organisation only.') ?>
    </div>
<?php endif; ?>

</div>
