<?php
$edit = $this->request->params['action'] === 'edit';
$enabledOptions = ['class' => 'form-check-input'];
if (!$edit && !isset($this->request->data['TaxiiServer']['enabled'])) {
    $enabledOptions['checked'] = true;
}

echo $this->Form->create('TaxiiServer', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-3">
                    <?= $edit ? __('Edit TAXII Server') : __('Add TAXII Server') ?>
                </h3>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'required' => true
                    ]) ?>
                </div>


                <!-- DESCRIPTION -->
                <div class="mb-3">
                    <?= $this->Form->label('description', __('Description') . (' (Optional)'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light',
                        'rows' => 3
                    ]) ?>
                </div>

                <hr class="my-4">

                <!-- OWNER -->
                <div class="mb-3">
                    <?= $this->Form->label('owner', __('Owner'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('owner', [
                        'label' => false,
                        'class' => 'form-control bg-light'
                    ]) ?>
                </div>

                <!-- BASE URL -->
                <div class="mb-3">
                    <?= $this->Form->label('baseurl', __('Base URL'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('baseurl', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => 'https://example.com/taxii2/'
                    ]) ?>
                </div>

                <!-- API KEY -->
                <div class="mb-3">
                    <?= $this->Form->label('api_key', __('API Key'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('api_key', [
                        'label' => false,
                        'class' => 'form-control bg-light'
                    ]) ?>
                </div>

                <!-- API ROOT -->
                <div class="mb-3">
                    <?= $this->Form->label('api_root', __('API Root'), ['class' => 'form-label fw-semibold']) ?>
                    <select id="api-root"
                            name="data[TaxiiServer][api_root]"
                            class="form-select tom-select bg-light">
                    </select>
                </div>

                <!-- COLLECTION -->
                <div class="mb-3">
                    <?= $this->Form->label('collection', __('Collection'), ['class' => 'form-label fw-semibold']) ?>
                    <select id="collection"
                            name="data[TaxiiServer][collection]"
                            class="form-select tom-select bg-light">
                    </select>
                </div>

                <!-- FILTERS -->
                <div class="mb-4">
                    <?= $this->Form->label('filters', __('Filter Rules (JSON)'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('filters', [
                        'class' => 'form-control bg-light',
                        'rows' => 5,
                        'placeholder' => '{"type": "ip-src"}'
                    ]) ?>
                </div>

                <!-- OPTIONS -->
                <div class="form-check form-switch mb-4">
                    <?= $this->Form->checkbox('skip_proxy', [
                        'class' => 'form-check-input',
                    ]) ?>
                    <?= $this->Form->label('skip_proxy', __('Skip Proxy'), ['class' => 'form-check-label']) ?>
                </div>

                <div class="form-check form-switch mb-4">
                    <?= $this->Form->checkbox('enabled', $enabledOptions) ?>
                    <?= $this->Form->label('enabled', __('Enabled'), ['class' => 'form-check-label']) ?>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" onclick="history.back()">
                        <?= __('Cancel') ?>
                    </button>

                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add server')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false
                        ]
                    ) ?>
                </div>

            </div>
        </div>
    </div>
</div>

<?= $this->Form->end(); ?>





<script>
document.addEventListener('DOMContentLoaded', () => {

    const baseUrlInput = document.querySelector('[name="data[TaxiiServer][baseurl]"]');
    const apiKeyInput = document.querySelector('[name="data[TaxiiServer][api_key]"]');

    const apiRootSelect = new TomSelect("#api-root", {
        valueField: "value",
        labelField: "label",
        searchField: "label"
    });

    const collectionSelect = new TomSelect("#collection", {
        valueField: "value",
        labelField: "label",
        searchField: "label"
    });

    async function fetchApiRoots() {
        const res = await fetch('/taxii_servers/getRoot', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                baseurl: baseUrlInput.value,
                api_key: apiKeyInput.value
            })
        });

        const data = await res.json();

        apiRootSelect.clearOptions();
        data.forEach(item => {
            apiRootSelect.addOption({
                value: item,
                label: item
            });
        });
    }

    async function fetchCollections() {
        const res = await fetch('/taxii_servers/getCollections', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                baseurl: baseUrlInput.value,
                api_key: apiKeyInput.value,
                api_root: apiRootSelect.getValue()
            })
        });

        const data = await res.json();

        collectionSelect.clearOptions();
        data.forEach(item => {
            collectionSelect.addOption({
                value: item,
                label: item
            });
        });
    }

    baseUrlInput.addEventListener('change', fetchApiRoots);
    apiKeyInput.addEventListener('change', fetchApiRoots);
    apiRootSelect.on('change', fetchCollections);
});
</script>
