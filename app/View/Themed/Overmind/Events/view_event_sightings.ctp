<?php
$total = $positive + $negative;
?>

<div data-sighting-total="<?= $total ?>">

<?php if ($total === 0): ?>

    <div class="d-flex flex-column align-items-center justify-content-center
                text-muted py-4">
        <span class="misp-icon misp-icon-sighting misp-hexagone mb-2 opacity-50" style="font-size:2em;"></span>
        <p class="mb-0 small fw-semibold">
            <?= __('No sightings recorded yet.') ?>
        </p>
    </div>

<?php else: ?>

    <div class="d-flex gap-3 p-3">

        <!-- Positive -->
        <div class="flex-fill rounded-3 p-3 d-flex flex-column gap-1"
             style="background:#f0fdf4;border:1px solid #bbf7d0;">
            <div class="d-flex align-items-center gap-2">
                <span class="rounded-circle d-flex align-items-center
                             justify-content-center"
                      style="width:32px;height:32px;
                             background:#16a34a;">
                    <i class="fas fa-thumbs-up text-white"
                       style="font-size:.8rem;"></i>
                </span>
                <span class="text-muted small fw-semibold">
                    <?= __('Positive') ?>
                </span>
            </div>
            <div class="fw-bold ms-1" style="font-size:1.6rem;
                        color:#15803d;line-height:1;">
                <?= (int)$positive ?>
            </div>
        </div>

        <!-- Negative / False-positive -->
        <div class="flex-fill rounded-3 p-3 d-flex flex-column gap-1"
             style="background:#fff1f2;border:1px solid #fecdd3;">
            <div class="d-flex align-items-center gap-2">
                <span class="rounded-circle d-flex align-items-center
                             justify-content-center"
                      style="width:32px;height:32px;
                             background:#dc2626;">
                    <i class="fas fa-thumbs-down text-white"
                       style="font-size:.8rem;"></i>
                </span>
                <span class="text-muted small fw-semibold">
                    <?= __('False positive') ?>
                </span>
            </div>
            <div class="fw-bold ms-1" style="font-size:1.6rem;
                        color:#b91c1c;line-height:1;">
                <?= (int)$negative ?>
            </div>
        </div>

    </div>

<?php endif; ?>

</div>
