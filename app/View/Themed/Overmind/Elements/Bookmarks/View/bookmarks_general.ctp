<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>
            <div class="fw-semibold fs-5">
                <?= h($data['Bookmark']['name'] ?? '') ?>
            </div>
        </div>

        <!-- URL -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('URL') ?>
            </div>
            <?= $this->element('genericElementsBS5/Badges/links', [
                'links' => [$data['Bookmark']['url'] ?? ''],
                'object' => $data['Bookmark']
            ]); ?>
        </div>

        <!-- COMMENT -->
        <?php if (!empty($data['Bookmark']['comment'])): ?>
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Comment') ?>
            </div>
            <div class="bg-light border rounded p-3">
                <?= nl2br(h($data['Bookmark']['comment'])) ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">ID</div>
                <div class="bg-light rounded px-2 py-1">
                    <?= h($data['Bookmark']['id'] ?? '') ?>
                </div>
            </div>

            <!-- EXPOSED TO ORG -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Exposed to Org') ?>
                </div>
                <div class="d-flex align-items-center py-2">
                    <?= $this->element('genericElementsBS5/Badges/boolean', [
                        'boolean' => !empty($data['Bookmark']['exposed_to_org']),
                        'full' => false,
                        'true' => __('Exposed'),
                        'false' => __('Private')
                    ]); ?>
                </div>
            </div>

            <!-- USER -->
            <?php if (!empty($data['User'])): ?>
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('User') ?></div>
                <div class="bg-light rounded px-2 py-1 border text-truncate">
                    <?= h($data['User']['email'] ?? '') ?>
                </div>
            </div>
            <?php endif; ?>

            <!-- ORGANISATION -->
            <?php if (!empty($data['Organisation'])): ?>
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Organisation') ?></div>
                <div class="d-flex align-items-center bg-light rounded px-2 py-1 border">
                    <?= $this->OrgImg->getOrgLogoV2($data['Organisation'], 24) ?>
                    <span class="fw-semibold text-dark ms-2 text-truncate"><?= h($data['Organisation']['name'] ?? '') ?></span>
                </div>
            </div>
            <?php endif; ?>

        </div>

    </div>
</div>
