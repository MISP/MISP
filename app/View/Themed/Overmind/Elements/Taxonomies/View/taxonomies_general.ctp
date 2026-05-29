<div class="card mb-3 shadow-sm">

    <div class="card-body">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small bold text-uppercase fw-bold mb-1">
                <?= __('Namespace') ?>
            </div>

            <div class="fw-semibold fs-5">
                <?= h($data['namespace'] ?? '') ?>
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

            <!-- VERSION -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Version') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/version',
                    [
                        'version' => $data['version'],
                    ]
                ); ?>
            </div>

            <!-- ENABLED -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Enabled') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean',
                    [
                        'boolean' => $data['enabled'],
                        'full' => false
                    ]
                ); ?>
            </div>

            <!-- REQUIRED -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Required') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean',
                    [
                        'boolean' => $data['required'],
                        'full' => false
                    ]
                ); ?>
            </div>

            <!-- HIGHLIGHTED -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Highlighted') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean',
                    [
                        'boolean' => $data['highlighted'],
                        'full' => false
                    ]
                ); ?>
            </div>


            <!-- ACCEPTED ATTRIBUTE TYPES -->
            <?php if (!empty($data['WarninglistType'])): ?>
                <div class="mt-4">
                    <div class="text-muted small text-uppercase fw-bold mb-2">
                        <?= __('Accepted attribute types') ?>
                    </div>

                    <div class="d-flex flex-wrap gap-2">
                        <?php foreach ($data['WarninglistType'] as $type): ?>
                            <span class="badge bg-dark">
                                <?= h($type['type']) ?>
                            </span>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>

        </div>

    </div>

</div>
