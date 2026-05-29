<div class="card mb-3 shadow-sm">

    <div class="card-body">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small bold text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>

            <div class="fw-semibold fs-5">
                <?= h($data['name'] ?? '') ?>
            </div>
        </div>

        <!-- DESCRIPTION -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Description') ?>
            </div>

            <div class="bg-light border rounded p-3">
                <?= nl2br(h($data['description'] ?? '')) ?>
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
                        <?= h($data['id'] ?? '') ?>
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
                        <?= h($data['uuid'] ?? '') ?>
                    </div>

                    <!-- COPY BUTTON -->
                    <button
                        class="text-muted border-0 bg-white"
                        onclick="copyToClipboard(this, '<?= h(h($data['uuid'] ?? '')) ?>')"
                        data-bs-toggle="tooltip"
                        title="<?= __('Copy UUID') ?>"
                        aria-label="<?= __('Copy UUID') ?>">
                        <i class="fas fa-copy"></i>
                    </button>

                </div>
            </div>

            <!-- VETTED -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Vetted by MISP-project') ?>
                </div>

                <div class="d-flex align-items-center py-2"">
                    <?= $this->element('genericElementsBS5/Badges/boolean', [
                        'boolean' => $data['misp_project_vetted'],
                        'full' => false
                    ]); ?>
                </div>
            </div>

            <!-- TYPE -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Type') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/type',
                    [
                        'type' => $data['type'],
                    ]
                ); ?>
            </div>


            <!-- OWNER ORG -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Owner Org') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= $this->OrgImg->getOrgLogoV2($data['Org'], 24, false); ?>
                    <?= h($data['Org']['name'] ?? '') ?>
                </div>
            </div>

            <!-- MAIL -->
            <div class="col-md-2">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Email') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <i class="fas fa-envelope text-primary"></i>
                    <?= h($data['email'] ?? '') ?>
                </div>
            </div>

            <!-- SECTOR -->
            <div class="col-md-2">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Sector') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <i class="fas fa-industry text-success"></i>
                    <?= h($data['sector'] ?? '') ?>
                </div>
            </div>


            <!-- NATIONALITY -->
            <div class="col-md-2">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Nationality') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <i class="fas fa-flag text-danger"></i>
                    <?= h($data['nationality'] ?? '') ?>
                </div>
            </div>

        </div>


        <!-- PGP KEY -->
        <?php if (!empty($data['pgp_key'])) : ?>
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-2">
                <?= __('PGP Key') ?>
            </div>

            <div class="border rounded overflow-hidden">

                <!-- Header bar -->
                <div class="d-flex align-items-center justify-content-between px-3 py-2 bg-dark">
                    <div class="d-flex align-items-center gap-2 text-light">
                        <i class="fas fa-key text-warning"></i>
                        <span class="small fw-semibold"><?= __('Public PGP Key') ?></span>
                    </div>
                    <button
                        class="btn btn-sm btn-outline-light py-0 px-2 d-flex align-items-center gap-1"
                        onclick="copyToClipboard(this, this.dataset.pgpKey)"
                        data-pgp-key="<?= h($data['pgp_key']) ?>"
                        data-bs-toggle="tooltip"
                        title="<?= __('Copy PGP Key') ?>"
                        aria-label="<?= __('Copy PGP Key') ?>">
                        <i class="fas fa-copy small"></i>
                        <span class="small"><?= __('Copy') ?></span>
                    </button>
                </div>

                <!-- Key content -->
                <pre class="mb-0 p-3 bg-black text-primary small" style="max-height: 200px; overflow-y: auto; font-family: monospace; white-space: pre-wrap; word-break: break-all;"><?= h($data['pgp_key']) ?></pre>

            </div>
        </div>
        <?php endif; ?>

    </div>

</div>