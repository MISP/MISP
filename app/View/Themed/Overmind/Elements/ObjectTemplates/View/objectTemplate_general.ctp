<?php

$objectTemplate = $data['ObjectTemplate'] ?? $data;
$organisation = $data['Organisation'] ?? $data;
?>

<div class="card mb-3 shadow-sm">

    <div class="card-body">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small bold text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>

            <div class="fw-semibold fs-5">
                <?= h($objectTemplate['name'] ?? '') ?>
            </div>
        </div>

        <!-- DESCRIPTION -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Description') ?>
            </div>

            <div class="bg-light border rounded p-3">
                <?= nl2br(h($objectTemplate['description'] ?? '')) ?>
            </div>
        </div>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    ID
                </div>

                <div class="d-flex align-items-center gap-2">
                    <div class="bg-light rounded px-2 py-1">
                        <?= h($objectTemplate['id'] ?? '') ?>
                    </div>
                </div>
            </div>

            <!-- UUID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    UUID
                </div>

                <div class="d-flex align-items-center gap-2">

                    <div class="bg-light rounded px-2 py-1" id="uuid-value">
                        <?= h($objectTemplate['uuid'] ?? '') ?>
                    </div>

                    <!-- COPY BUTTON -->
                    <button
                        class="text-muted border-0 bg-white"
                        onclick="copyToClipboard(this, '<?= h($objectTemplate['uuid'] ?? '') ?>')"
                        data-bs-toggle="tooltip"
                        title="<?= __('Copy UUID') ?>"
                        aria-label="<?= __('Copy UUID') ?>">
                        <i class="fas fa-copy"></i>
                    </button>

                </div>
            </div>

            <!-- CATEGORY -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Meta-category') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/category',
                    [
                        'category' => $objectTemplate['meta-category'],
                        'full' => false
                    ]
                ); ?>
            </div>

            <!-- VERSION -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Version') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/version',
                    [
                        'version' => $objectTemplate['version'],
                    ]
                ); ?>
            </div>

            <!-- ACTIVATED -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Activated') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean',
                    [
                        'boolean' => $objectTemplate['active'],
                        'full' => false
                    ]
                ); ?>
            </div>

            <!-- OWNER ORG -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Owner Org') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= $this->OrgImg->getOrgLogoV2($organisation, 24, false); ?>
                    <?= h($organisation['name'] ?? '') ?>
                </div>
            </div>

        </div>

        <?php if (!empty($objectTemplate['requirements'])): ?>
            <hr class="my-4 opacity-25">
            <div class="mb-2">
                <div class="text-muted small text-uppercase fw-bold mb-3">
                    <?= __('Requirements') ?>
                </div>
                <div class="requirements-wrapper d-flex flex-wrap gap-5">
                    <?php foreach ($objectTemplate['requirements'] as $group => $requirements): ?>
                        <div class="requirement-group mb-3">
                            <div class="d-flex align-items-center mb-1">
                                <span class="badge bg-secondary-subtle text-primary border border-secondary-subtle fw-bold text-uppercase" style="font-size: 0.75rem;">
                                    <?= h($group) ?>
                                </span>
                            </div>

                            <div class="requirement-list ps-2 border-start border-2 border-light-subtle">
                                <?php foreach ($requirements as $requirement): ?>
                                    <div class="d-flex align-items-baseline gap-2 mb-1">
                                        <i class="fas fa-check-circle text-primary" style="font-size: 0.8rem;"></i>
                                        <span class="text-muted small">
                                            <?= h($requirement) ?>
                                        </span>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

    </div>

</div>