<?php
$dm = $data['DecayingModel'];
$org = $data['Organisation'] ?? ['id' => $dm['org_id'], 'name' => $dm['org_id']];
$formulaDesc = $available_formulas[$dm['formula']]['description'] ?? null;
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body">
        <!-- META GRID -->
        <div class="row g-3">
            <!-- ID + UUID -->
            <div class="col-md-6">
                <div class="rounded-3 border p-3 h-100">
                    <div class="text-muted small text-uppercase fw-bold mb-2">
                        <i class="fas fa-fingerprint me-1"></i>
                        <?= __('Identifiers') ?>
                    </div>
                    <div class="d-flex flex-wrap align-items-center justify-content-between gap-2">
                        <div class="d-flex align-items-center gap-2">
                            <span class="text-muted small fw-bold">ID</span>
                            <span class="bg-light border rounded px-2 py-1 fw-semibold small font-monospace">
                                #<?= h($dm['id'] ?? '') ?>
                            </span>
                        </div>
                        <?php if (!empty($dm['uuid'])): ?>
                            <div class="d-flex align-items-center gap-2">
                                <span class="text-muted small fw-bold flex-shrink-0">UUID</span>
                                <div class="d-inline-flex align-items-center gap-1 bg-light border rounded px-2 py-1">
                                    <span class="font-monospace small text-truncate"><?= h($dm['uuid'] ?? '') ?></span>
                                    <button
                                        class="text-muted border-0 bg-transparent p-0 ms-1 flex-shrink-0"
                                        onclick="copyToClipboard(this, '<?= h($dm['uuid'] ?? '') ?>')"
                                        data-bs-toggle="tooltip"
                                        title="<?= __('Copy UUID') ?>"
                                        aria-label="<?= __('Copy UUID') ?>">
                                        <i class="fas fa-copy" style="font-size:0.75rem;"></i>
                                    </button>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Created by -->
            <div class="col-md-6">
                <div class="rounded-3 border p-3 h-100">
                    <div class="text-muted small text-uppercase fw-bold mb-2">
                        <span class="misp-icon misp-icon-user1 misp-hexagone"></span>
                        <?= __('Created by') ?>
                    </div>
                    <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 py-1">
                        <div class="d-inline-flex align-items-center gap-2">
                            <?php $logo = $this->OrgImg->getOrgLogoV2($org, 24); ?>
                            <?= $logo !== '' ? $logo : '<i class="misp-icon misp-icon-organisation misp-simple text-muted"></i>' ?>
                            <a href="<?= h($baseurl . '/organisations/view/' . $org['id']) ?>" 
                               class="text-decoration-none fw-semibold text-primary"><?= h($org['name'] ?? '') ?>
                            </a>
                        </div>
                        <div class="d-flex align-items-center gap-2 text-muted small">
                            <?php $email = h($user['email'] ?? '') ?>
                            <?= $email !== '' ? '<span><i class="misp-icon misp-icon-user1 misp-simple"></i> $email </span>'  : '' ?>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Formula') ?></div>
                <span class="badge bg-info-subtle text-info-emphasis border border-info-subtle"><?= h($dm['formula']) ?></span>
                <?php if (!empty($formulaDesc)): ?>
                    <i class="fas fa-circle-question text-muted ms-1" title="<?= h($formulaDesc) ?>"></i>
                <?php endif; ?>
            </div>

            <!-- VERSION -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Version') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/version',
                    [
                        'version' => $dm['version'],
                    ]
                ); ?>
            </div>

            <!-- DEFAULT -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Default') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/default',
                    [
                        'default' => $dm['default'],
                        'full' => false
                    ]
                ); ?>
            </div>

            <!-- ENABLED -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Enabled') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean',
                    [
                        'boolean' => $dm['enabled'],
                        'full' => false
                    ]
                ); ?>
            </div>

            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Shared') ?></div>
                <span class="badge bg-primary-subtle text-primary-emphasis border border-primary-subtle"><i class="fas fa-share-nodes me-1"></i> <?= h(__('Shared')) ?> </span>
            </div>

            <?php if (!empty($dm['ref'])): ?>
                <div class="col-12">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('References') ?></div>
                    <ul class="mb-0 ps-3">
                        <?php foreach ((array)$dm['ref'] as $ref): ?>
                            <li><a href="<?= h($ref) ?>" target="_blank" rel="noopener"><?= h($ref) ?></a></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
        </div>

    </div>
</div>
