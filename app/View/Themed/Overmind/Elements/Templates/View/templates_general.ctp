<div class="card mb-3 shadow-sm">

    <div class="card-body">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small bold text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>

            <div class="fw-semibold fs-5">
                <?= h($data['Template']['name'] ?? '') ?>
            </div>
        </div>

        <!-- DESCRIPTION -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Description') ?>
            </div>

            <div class="bg-light border rounded p-3">
                <?= nl2br(h($data['Template']['description'] ?? '')) ?>
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
                        <?= h($data['Template']['id'] ?? '') ?>
                    </div>
                </div>
            </div>

            <!-- OWNER ORG -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Owner Org') ?>
                </div>

                <div class="d-flex align-items-center gap-2">
                    <?= h($data['Template']['org'] ?? '') ?>
                </div>
            </div>

            <!-- SHAREABLE -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Shareable') ?>
                </div>

                <?= $this->element('genericElementsBS5/Badges/boolean',
                    [
                        'boolean' => $data['Template']['share'],
                        'full' => false
                    ]
                ); ?>
            </div>

        </div>

        <!-- ACCEPTED ATTRIBUTE TYPES -->
        <?php if (!empty($data['TemplateTag'])): ?>
            <div class="mt-4">
                <div class="text-muted small text-uppercase fw-bold mb-2">
                    <?= __('Tags') ?>
                </div>

                <div class="d-flex flex-wrap gap-2">
                    <?php foreach ($data['TemplateTag'] as $tag): ?>
                       <?= $this->element('genericElementsBS5/Badges/tag',
                            [
                                'tag' => $tag['Tag'],
                                'local' => false,
                                'hiddenClass' => '',
                                'showFavourite' => false
                            ]
                        ); ?>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

    </div>

</div>
