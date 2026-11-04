<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- DESCRIPTION -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Description') ?>
            </div>

            <div class="bg-light border rounded p-3">
                <?= nl2br(h($data['Cerebrate']['description'] ?? '')) ?>
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
                    <?= h($data['Cerebrate']['id'] ?? '') ?>
                </div>
            </div>

            <!-- OWNER -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Owner') ?></div>
                <div class="d-flex align-items-center bg-light rounded px-2 py-1 border">
                    <div class="bg-primary text-white rounded-circle d-flex align-items-center justify-content-center me-3 shadow-sm" style="width: 25px; height: 25px;">
                        <i class="fas fa-user-shield small"></i>
                    </div>
                    <span class="fw-semibold text-dark"><?= h($data['Organisation']['name'] ?? __('System')) ?></span>
                </div>
            </div>

            <!-- PROXY -->
            <div class="col-md-4">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Skip Proxy') ?>
                </div>

                <div class="d-flex align-items-center py-2">
                    <?= $this->element('genericElementsBS5/Badges/boolean', [
                        'boolean' => $data['Cerebrate']['skip_proxy'],
                        'full' => false
                    ]); ?>
                </div>
            </div>

        </div>


        <!-- CONNECTION -->
        <div class="mt-4">

            <div class="row g-3">

                <!-- BASE URL -->
                <div class="col-md-6">
                    <div class="text-muted small text-uppercase fw-bold mb-1">
                        <?= __('URL') ?>
                    </div>

                    <?= $this->element('genericElementsBS5/Badges/links', [
                        'links' => [$data['Cerebrate']['url'] ?? ''],
                        'object' => $data['Cerebrate']
                    ]); ?>
                </div>
            </div>
        </div>

        <!-- API KEY -->
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Auth Key') ?>
            </div>

            <?= $this->element('genericElementsBS5/Badges/boolean', [
                'boolean' => !empty($data['Cerebrate']['authkey']),
                'full' => true,
                'true' => __('Configured'),
                'false' => __('Not set'),
                'trueIcon' => 'fa-key',
                'falseIcon' => 'fa-times-circle',
                'trueColor' => 'success',
                'falseColor' => 'secondary',
            ]); ?>
        </div>
    </div>
</div>