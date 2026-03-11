<!-- =======================================================
Still in work 
======================================================= -->

<?php
    echo $this->Form->create('Server', ['novalidate' => true]);
    $bookmark = [];
?>

<!-- TYPE + ENDPOINT -->

<div class="mb-4">

    <label class="form-label fw-bold">
        <?= __('Type & Endpoint') ?>
    </label>

    <div class="d-flex gap-2">

        <div class="w-auto cursor-pointer">
            <?php
                echo $this->Form->input('method', [
                    'label' => false,
                    'options' => [
                    'GET' => 'GET',
                    'POST' => 'POST',
                    'DELETE' => 'DELETE'
                    ],
                    'class' => 'form-select'
                ]);
            ?>
        </div>

        <div class="flex-grow-1">
            <?php
                echo $this->Form->input('url', [
                    'label' => false,
                    'class' => 'form-control',
                    'placeholder' => '/events/view/1'
                ]);
            ?>
        </div>

    </div>

</div>

<?php
    if (!empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
        echo $this->Form->input('use_full_path', array(
            'label' => __('Use full path - disclose my apikey'),
            'type' => 'checkbox'
        ));
    }
    echo $this->Form->input('bookmark', array(
        'label' => __('Bookmark query'),
        'type' => 'checkbox',
        'onChange' => 'toggleRestClientBookmark();'
    ));
?>

<div class="mb-4">
    <label class="form-label fw-bold">
        <?= __('Header') ?>
    </label>

    <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead class="table-light">
                <tr>
                    <th class="w-25">Key</th>
                    <th class="w-100">Value</th>
                    <th></th>
                </tr>
            </thead>

            <tbody id="headers-table">
                <tr>
                    <td><input type="text" class="form-control header-key" value="Authorization"></td>
                    <td><input type="text" class="form-control header-value" value="<?= h($me['authkey'] ?? '') ?>" placeholder = "YOUR_API_KEY"></td>
                    <td></td>
                </tr>
                <tr>
                    <td><input type="text" class="form-control header-key" value="Accept"></td>
                    <td><input type="text" class="form-control header-value" value="application/json"></td>
                    <td></td>
                </tr>

                <tr>
                    <td><input type="text" class="form-control header-key" value="Content-type"></td>
                    <td><input type="text" class="form-control header-value" value="application/json"></td>
                    <td></td>
                </tr>
            </tbody>
            <thead class="table-light">
                <tr>
                    <th><a class="small text-primary ms-1" style="cursor:pointer" onclick="addHeaderRow()"> + <?= __('Add Header') ?></a></th>
                    <th></th>
                    <th></th>
                </tr>
            </thead>
        </table>
    </div>
</div>

<div class="mb-4">
    <label class="form-label fw-bold">
        <?= __('Body') ?>
    </label>

    <?php
        echo $this->Form->input('body', [
            'type' => 'textarea',
            'label' => false,
            'class' => 'form-control',
            'rows' => 8
        ]);
    ?>
</div>


<div class="mb-4">
    <label class="form-label fw-bold">
        <?= __('Options') ?>
    </label>

    <div class="row g-3"> <div class="col-md-6">
            <div class="d-flex justify-content-between align-items-center bg-light rounded border p-2 px-3">
                <label class="form-check-label mb-0 cursor-pointer" for="show-result">
                    <i class="fas fa-eye me-2 text-success"></i>
                    <?= __('Show Result') ?>
                </label>
                <div class="form-check form-switch mb-0">
                    <?php
                        echo $this->Form->input('show_result', [
                            'type' => 'checkbox',
                            'label' => false,
                            'class' => 'form-check-input',
                            'id' => 'show-result', // ID pour l'accessibilité
                            'div' => false,
                            'role' => 'switch'
                        ]);
                    ?>
                </div>
            </div>
        </div>

        <div class="col-md-6">
            <div class="d-flex justify-content-between align-items-center bg-light rounded border p-2 px-3">
                <label class="form-check-label mb-0 cursor-pointer" for="skip-ssl">
                    <i class="fas fa-shield-alt me-2 text-warning"></i>
                    <?= __('Skip SSL validation') ?>
                </label>
                <div class="form-check form-switch mb-0">
                    <?php
                        echo $this->Form->input('skip_ssl_validation', [
                            'type' => 'checkbox',
                            'label' => false,
                            'class' => 'form-check-input',
                            'id' => 'skip-ssl',
                            'div' => false,
                            'role' => 'switch'
                        ]);
                    ?>
                </div>
            </div>
        </div>

    </div>
</div>


<div>
    <?php
        echo $this->Form->button(
            '<i class="fas fa-play me-2"></i>' . __('Execute'), [
                'class' => 'btn btn-primary',
                'escape' => false
        ]);
    ?>
</div>

<?php
    echo $this->Form->end();
?>



<script>
    function addHeaderRow() {
        const table = document.getElementById("headers-table");

        const row = document.createElement("tr");

        row.innerHTML = `
        <td><input type="text" class="form-control header-key"></td>

        <td><input type="text" class="form-control header-value"></td>

        <td>
            <button class="btn btn-sm btn-outline-danger" onclick="this.closest('tr').remove()">
                <i class="fas fa-times"></i>
            </button>
        </td>
        `;

        table.appendChild(row);

    }
</script>