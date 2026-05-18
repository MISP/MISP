<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small bold text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>

            <div class="fw-semibold fs-5">
                <?= h($data['SharingGroupBlueprint']['name'] ?? '') ?>
            </div>
        </div>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    ID
                </div>
                <div class="bg-light rounded px-2 py-1">
                    <?= h($data['SharingGroupBlueprint']['id'] ?? '') ?>
                </div>
            </div>

            <!-- UUID -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    UUID
                </div>

                <div class="d-flex align-items-center gap-2">

                    <div class="bg-light rounded px-2 py-1" id="uuid-value">
                        <?= h($data['SharingGroupBlueprint']['uuid'] ?? '') ?>
                    </div>

                    <!-- COPY BUTTON -->
                    <button
                        class="text-muted border-0 bg-white"
                        onclick="copyToClipboard(this, '<?= h(h($data['SharingGroupBlueprint']['uuid'] ?? '')) ?>')"
                        data-bs-toggle="tooltip"
                        title="<?= __('Copy UUID') ?>"
                        aria-label="<?= __('Copy UUID') ?>">
                        <i class="fas fa-copy"></i>
                    </button>

                </div>
            </div>

            <!-- OWNER ORG -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Owner Org') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= $this->OrgImg->getOrgLogoV2($data['Organisation'], 24, false); ?>
                    <?= h($data['Organisation']['name'] ?? '') ?>
                </div>
            </div>

            <!-- SHARING GROUP -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Sharing Group') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= $this->element('genericElementsBS5/Badges/blueprint_sharing_group', [
                        'sgData' => $data['SharingGroup'] ?? '[]',
                        'blueprintId' => $data['SharingGroupBlueprint']['id'] ?? '',
                        'full' => true
                    ]); ?>
                </div>
            </div>
        </div>

        <!-- FILTERS -->
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Rules') ?>
            </div>

            <?= $this->element('genericElementsBS5/Badges/json', [
                'json' => $data['SharingGroupBlueprint']['rules'] ?? '{}',
                'full' => true
            ]); ?>
        </div>

    </div>
</div>