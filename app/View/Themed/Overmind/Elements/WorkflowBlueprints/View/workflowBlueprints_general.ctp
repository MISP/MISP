<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>
            <div class="fw-semibold fs-5">
                <?= h($data['WorkflowBlueprint']['name'] ?? '') ?>
            </div>
        </div>

        <!-- DESCRIPTION -->
        <?php if (!empty($data['WorkflowBlueprint']['description'])): ?>
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Description') ?>
            </div>
            <div class="bg-light border rounded p-3">
                <?= nl2br(h($data['WorkflowBlueprint']['description'])) ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">ID</div>
                <div class="bg-light rounded px-2 py-1">
                    <?= h($data['WorkflowBlueprint']['id'] ?? '') ?>
                </div>
            </div>

            <!-- UUID -->
            <div class="col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('UUID') ?></div>
                <div class="bg-light rounded px-2 py-1 font-monospace text-truncate">
                    <?= h($data['WorkflowBlueprint']['uuid'] ?? '') ?>
                </div>
            </div>

            <!-- DEFAULT -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Default') ?></div>
                <div class="d-flex align-items-center py-2">
                    <?= $this->element('genericElementsBS5/Badges/boolean', [
                        'boolean' => !empty($data['WorkflowBlueprint']['default']),
                        'full' => false
                    ]); ?>
                </div>
            </div>

        </div>

        <!-- TIMESTAMP -->
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Timestamp') ?></div>
            <div class="bg-light rounded px-2 py-1 d-inline-block">
                <?php $ts = $data['WorkflowBlueprint']['timestamp'] ?? 0; ?>
                <?= $ts ? h(date('Y-m-d H:i:s', (int)$ts)) : '-' ?>
            </div>
        </div>

        <!-- DATA -->
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Data') ?></div>
            <?= $this->element('genericElementsBS5/Badges/json', [
                'json' => $data['WorkflowBlueprint']['data'] ?? '[]',
                'full' => true
            ]); ?>
        </div>

    </div>
</div>
