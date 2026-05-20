<?php
    $sharingGroup = $sg['SharingGroup'];
    $organisation = $sg['Organisation'];
?>


<div class="card mb-3 shadow-sm">

    <div class="card-body">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small bold text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>

            <div class="fw-semibold fs-5">
                <?= h($sharingGroup['name'] ?? '') ?>
            </div>
        </div>

        <!-- DESCRIPTION -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Description') ?>
            </div>

            <div class="bg-light border rounded p-3">
                <?= nl2br(h($sharingGroup['description'] ?? '')) ?>
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
                        <?= h($sharingGroup['id'] ?? '') ?>
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
                        <?= h($sharingGroup['uuid'] ?? '') ?>
                    </div>

                    <!-- COPY BUTTON -->
                    <button
                        class="text-muted border-0 bg-white"
                        onclick="copyToClipboard(this, '<?= h(h($sharingGroup['uuid'] ?? '')) ?>')"
                        data-bs-toggle="tooltip"
                        title="<?= __('Copy UUID') ?>"
                        aria-label="<?= __('Copy UUID') ?>">
                        <i class="fas fa-copy"></i>
                    </button>

                </div>
            </div>

            <!-- SELECTABLE -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Selectable') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean',
                    [
                        'boolean' => $sharingGroup['active'],
                        'full' => false
                    ]
                ); ?>
            </div>

            <!-- CREATOR ORG -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Creator Org') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= $this->OrgImg->getOrgLogoV2($organisation, 24, false); ?>
                    <?= h($organisation['name'] ?? '') ?>
                </div>
            </div>

            <!-- SYNC ORG -->
            <?php if (!empty($sharingGroup['sync_org'])): ?>
                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1">
                        <?= __('Synced by') ?>
                    </div>

                    <div class="d-flex align-items-center gap-2">
                        <?= $this->OrgImg->getOrgLogoV2($sharingGroup['sync_org'], 24, false); ?>
                        <?= h($sharingGroup['sync_org'] ?? '') ?>
                    </div>
                </div>
            <?php endif; ?>

            <!-- LINKED EVENTS -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Linked Events') ?>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <a href="<?= $baseurl ?>/events/index/searchsharinggroup:<?= h($sharingGroup['id']) ?>" class="btn btn-sm btn-outline-primary rounded-pill px-3 fw-bold">
                        <i class="fas fa-calendar-check me-1"></i>
                        <?= __n('%s event', '%s events', $sharingGroup['event_count'], $sharingGroup['event_count']) ?>
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>


<div class="row">
    <div class="col-lg-6 mb-4">
        <div class="card h-100 shadow-sm border-0 rounded-4">
            <div class="card-header bg-white py-3 border-bottom-0">
                <h6 class="fw-bold mb-0"><i class="fas fa-building me-2 text-primary"></i><?= __('Member Organisations') ?></h6>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead class="table-light">
                            <tr class="small text-uppercase text-muted">
                                <th class="ps-4"><?= __('Organisation') ?></th>
                                <th class="text-center"><?= __('Local') ?></th>
                                <th class="text-center pe-4"><?= __('Extend') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($sg['SharingGroupOrg'] as $sgo): ?>
                                <tr>
                                    <td class="ps-4 fw-medium">
                                        <?= $this->OrgImg->getNameWithImg($sgo) ?>
                                    </td>
                                    <td class="text-center">
                                        <i class="<?= $sgo['Organisation']['local'] ? 'fas fa-check-circle text-success' : 'fas fa-times-circle text-muted' ?>"></i>
                                    </td>
                                    <td class="text-center pe-4">
                                        <i class="<?= $sgo['extend'] ? 'fas fa-check-circle text-primary' : 'fas fa-times-circle text-muted' ?>"></i>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="col-lg-6 mb-4">
        <div class="card h-100 shadow-sm border-0 rounded-4">
            <div class="card-header bg-white py-3 border-bottom-0">
                <h6 class="fw-bold mb-0"><i class="fas fa-server me-2 text-primary"></i><?= __('Target Instances') ?></h6>
            </div>
            <div class="card-body p-0">
                <?php if (!empty($sg['SharingGroup']['roaming'])): ?>
                    <div class="p-4 text-center">
                        <div class="alert alert-info border-0 rounded-3 mb-0 py-3">
                            <i class="fas fa-street-view fa-2x mb-2 text-info"></i>
                            <p class="mb-0 fw-medium"><?= __('Roaming mode is enabled for this sharing group.') ?></p>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-hover align-middle mb-0">
                            <thead class="table-light">
                                <tr class="small text-uppercase text-muted">
                                    <th class="ps-4"><?= __('Server') ?></th>
                                    <th><?= __('URL') ?></th>
                                    <th class="text-center pe-4"><?= __('All Orgs') ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($sg['SharingGroupServer'] as $sgs): ?>
                                    <tr>
                                        <td class="ps-4 fw-medium"><?= h($sgs['Server']['name']) ?></td>
                                        <td class="small text-muted"><?= h($sgs['Server']['url']) ?></td>
                                        <td class="text-center pe-4">
                                            <i class="<?= $sgs['all_orgs'] ? 'fas fa-check-circle text-success' : 'fas fa-times-circle text-muted' ?>"></i>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>