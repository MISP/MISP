<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small bold text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>

            <div class="fw-semibold fs-5">
                <?= h($data['TaxiiServer']['name'] ?? '') ?>
            </div>
        </div>

        <!-- DESCRIPTION -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Description') ?>
            </div>

            <div class="bg-light border rounded p-3">
                <?= nl2br(h($data['TaxiiServer']['description'] ?? '')) ?>
            </div>
        </div>

        <!-- META GRID -->
        <div class="row g-3">

            <!-- ID -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    ID
                </div>
                <div class="bg-light rounded px-2 py-1">
                    <?= h($data['TaxiiServer']['id'] ?? '') ?>
                </div>
            </div>

            <!-- OWNER -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Owner') ?></div>
                <div class="d-flex align-items-center bg-light rounded px-2 py-1 border">
                    <div class="bg-primary text-white rounded-circle d-flex align-items-center justify-content-center me-3 shadow-sm" style="width: 25px; height: 25px;">
                        <i class="fas fa-user-shield small"></i>
                    </div>
                    <span class="fw-semibold text-dark"><?= h($data['TaxiiServer']['owner'] ?? __('System')) ?></span>
                </div>
            </div>

            <!-- PROXY -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Skip Proxy') ?>
                </div>

                <div class="d-flex align-items-center py-2">
                    <?= $this->element('genericElementsBS5/Badges/boolean', [
                        'boolean' => $data['TaxiiServer']['skip_proxy'],
                        'full' => false
                    ]); ?>
                </div>
            </div>

            <!-- ENABLED -->
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= __('Enabled') ?>
                </div>

                <div class="d-flex align-items-center py-2">
                    <?= $this->element('genericElementsBS5/Badges/boolean', [
                        'boolean' => $data['TaxiiServer']['enabled'],
                        'full' => false,
                        'true' => __('Enabled'),
                        'false' => __('Disabled')
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
                        <?= __('Base URL') ?>
                    </div>

                    <?= $this->element('genericElementsBS5/Badges/links', [
                        'links' => [$data['TaxiiServer']['baseurl'] ?? ''],
                        'object' => $data['TaxiiServer']
                    ]); ?>
                </div>

                <!-- API ROOT -->
                <div class="col-md-3">
                    <div class="text-muted small mb-1">
                        <?= __('API Root') ?>
                    </div>
                    <div class="bg-white border rounded-3 px-3 py-2 fw-medium text-truncate shadow-xs">
                        <?= h($data['TaxiiServer']['api_root'] ?? '-') ?>
                    </div>
                </div>

                <!-- COLLECTION -->
                <div class="col-md-3">
                    <div class="text-muted small mb-1">
                        <?= __('Collection') ?>
                    </div>
                    <div class="bg-white border rounded-3 px-3 py-2 fw-medium text-truncate shadow-xs">
                        <?= h($data['TaxiiServer']['collection'] ?? '-') ?>
                    </div>
                </div>

            </div>
        </div>

        <!-- API KEY -->
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('API Key') ?>
            </div>

            <div class="d-flex align-items-center">
                <div class="input-group shadow-sm">
                    <span class="input-group-text bg-white border-end-0 text-muted"><i class="fas fa-key"></i></span>
                    <input type="password" 
                           class="form-control bg-white border-start-0 border-end-0" 
                           id="apiKeyField" 
                           value="<?= h($data['TaxiiServer']['api_key'] ?? '') ?>" 
                           readonly>
                    <button class="btn btn-light border border-start-0" 
                            type="button" 
                            onclick="toggleSecret('apiKeyField', this)"
                            data-bs-toggle="tooltip" 
                            title="<?= __('Show/Hide') ?>">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
        </div>

        <!-- FILTERS -->
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Filter Rules') ?>
            </div>

            <?= $this->element('genericElementsBS5/Badges/json', [
                'json' => $data['TaxiiServer']['filters'] ?? '{}',
                'full' => true
            ]); ?>
        </div>

    </div>
</div>
