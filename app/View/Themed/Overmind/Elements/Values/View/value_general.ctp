<?php
$value = $data['Value'];
?>

<div class="card mb-3 shadow-sm">
    <div class="card-body">

        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Value') ?>
            </div>
            <div class="fw-semibold fs-5 font-monospace text-break">
                <?= h($value['value']) ?>
            </div>
        </div>

        <div class="row g-3">
            <div class="col-md-2">
                <div class="text-muted small text-uppercase fw-bold mb-1">ID</div>
                <div class="d-flex align-items-center gap-2">
                    <div class="bg-light rounded px-2 py-1"><?= h($value['id']) ?></div>
                </div>
            </div>

            <div class="col-md-2">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Attributes') ?>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <div class="bg-light rounded px-2 py-1"><?= h($value['attribute_count']) ?></div>
                </div>
            </div>

            <div class="col-md-8">
                <div class="text-muted small text-uppercase fw-bold mb-1">SHA-256</div>
                <div class="d-flex align-items-center gap-2">
                    <div class="bg-light rounded px-2 py-1 font-monospace text-break small">
                        <?= h($value['sha256']) ?>
                    </div>
                </div>
            </div>
        </div>

    </div>
</div>
