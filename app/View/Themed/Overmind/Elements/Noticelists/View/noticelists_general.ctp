<?php

$noticelist = $data['Noticelist'] ?? $data;

?>

<div class="card mb-3 shadow-sm">

    <div class="card-body">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small bold text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>

            <div class="fw-semibold fs-5">
                <?= h($noticelist['name'] ?? '') ?>
            </div>
        </div>

        <!-- EXPANDED NAME -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Expanded Name') ?>
            </div>
            <div class="ps-3 border-start border-4 border-primary py-1 italic">
                <?= nl2br(h($noticelist['expanded_name'] ?? '')) ?>
            </div>
        </div>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    ID
                </div>

                <div class="d-flex align-items-center gap-2">
                    <div class="bg-light rounded px-2 py-1">
                        <?= h($noticelist['id'] ?? '') ?>
                    </div>
                </div>
            </div>

            <!-- GEO -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Geographical Area') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/country',
                    [
                    'country' => $noticelist['geographical_area'],
                    ]
                ); ?>
            </div>

            <!-- VERSION -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Version') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/version',
                    [
                        'version' => $noticelist['version'],
                    ]
                ); ?>
            </div>

            <!-- ENABLED -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Enabled') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/enabled',
                    [
                        'enabled' => $noticelist['enabled'],
                        'full' => false
                    ]
                ); ?>
            </div>
        </div>

        <!-- LINKS -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Links') ?>
            </div>
            <?= $this->element('genericElementsBS5/Badges/links',
                    [
                        'links' => $noticelist['ref'],
                        'object' => $noticelist
                    ]
                ); ?>
        </div>

    </div>

</div>
