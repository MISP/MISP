<?php
    echo $this->Form->create('Server', ['novalidate' => true, 'id' => 'restClientForm']);
    $bookmark = [];

    // Fetching headers from request data or default variable
    $headerPayload = !empty($this->request->data['Server']['header']) ? $this->request->data['Server']['header'] : ($header ?? '');

    // Parsing headers into an array of key-value pairs
    $parsedHeaders = [];
    $lines = array_filter(explode("\n", str_replace("\r", "", $headerPayload)));
    foreach ($lines as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) === 2) {
            $parsedHeaders[] = [
                'key' => trim($parts[0]),
                'value' => trim($parts[1])
            ];
        }
    }
?>

<div class="d-none">
    <?php
        echo $this->Form->input('header', [
            'type' => 'textarea',
            'id' => 'hidden-header-payload',
            'default' => !empty($this->request->data['Server']['header']) ? $this->request->data['Server']['header'] : ($header ?? '')
        ]);
        echo $this->Form->input('bookmark', [
            'type' => 'checkbox',
            'id' => 'hidden-bookmark-checkbox'
        ]);
        echo $this->Form->input('name', [
            'type' => 'text',
            'id' => 'hidden-bookmark-name'
        ]);
    ?>
</div>

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
                        'PUT' => 'PUT',
                        'DELETE' => 'DELETE'
                    ],
                    'class' => 'form-select',
                    'id' => 'server-method'
                ]);
            ?>
        </div>

        <div class="flex-grow-1">
            <?php
                echo $this->Form->input('url', [
                    'label' => false,
                    'class' => 'form-control',
                    'id' => 'server-url',
                    'placeholder' => '/events/view/1'
                ]);
            ?>
        </div>

        <div class="w-auto">
            <button type="button" class="btn btn-outline-warning shadow-none d-flex align-items-center gap-2 h-100" onclick="openBookmarkModal()">
                <i class="fas fa-star"></i> <?= __('Bookmark me') ?>
            </button>
        </div>
    </div>

    <div class="d-flex align-items-center checkbox-index m-2 gap-3">
        <?php
            if (!empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
                echo $this->Form->input('use_full_path', array(
                    'label' => array('class' => 'form-check-label mb-0 ms-1'),
                    'type' => 'checkbox',
                    'div' => false,
                    'before' => '<div class="form-check d-flex align-items-center">',
                    'after' => '</div>'
                ));
            }
        ?>
    </div>
</div>

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
                <?php foreach ($parsedHeaders as $h): ?>
                    <tr>
                        <td><input type="text" class="form-control header-key" value="<?= h($h['key']) ?>"></td>
                        <td><input type="text" class="form-control header-value" value="<?= h($h['value']) ?>"></td>
                        <td>
                            <button class="btn btn-sm btn-outline-danger shadow-none" type="button" onclick="this.closest('tr').remove()">
                                <i class="fas fa-times"></i>
                            </button>
                        </td>
                    </tr>
                <?php endforeach; ?>
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
            'rows' => 8,
            'id' => 'server-body'
        ]);
    ?>

    <div id="template_description" class="alert alert-danger mt-3" style="display:none;">
         <?= __('⚠️ Fill out the JSON template above, make sure to replace all placeholder values. Fields with the value "optional" can be removed.') ?>
    </div>
</div>

<div class="mb-4">
    <label class="form-label fw-bold">
        <?= __('Options') ?>
    </label>

    <div class="row g-3">
        <div class="col-md-6">
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
                            'id' => 'show-result',
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
                'escape' => false,
                'type' => 'submit'
        ]);
    ?>
</div>

<?php
    echo $this->Form->end();
?>

<?php // Bookmarks modal : may be factored using the generic modal from default.ctp ?>
<div class="modal fade" id="bookmarkModal" tabindex="-1" aria-labelledby="bookmarkModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="bookmarkModalLabel"><i class="fas fa-star text-warning me-2"></i><?= __('Add to Bookmarks') ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div class="mb-3">
                    <label for="bookmarkNameInput" class="form-label fw-bold"><?= __('Bookmark Name') ?> <span class="text-danger">*</span></label>
                    <input type="text" class="form-control" id="bookmarkNameInput" placeholder="<?= __('e.g. Get all events') ?>" required>
                </div>
                <div class="mb-3">
                    <label class="form-label text-muted small mb-1"><?= __('Query Preview') ?></label>
                    <div class="p-2 bg-light rounded border font-monospace small" id="modal-query-preview"></div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><?= __('Cancel') ?></button>
                <button type="button" class="btn btn-primary" onclick="saveBookmark()"><?= __('Save Bookmark') ?></button>
            </div>
        </div>
    </div>
</div>


<script>
// Sync headers from the dynamic table to the hidden CakePHP field before form submission
document.getElementById('restClientForm').addEventListener('submit', function() {
    let headerPayload = "";
    const rows = document.querySelectorAll('#headers-table tr');
    rows.forEach(function(row) {
        const keyInput = row.querySelector('.header-key');
        const valInput = row.querySelector('.header-value');
        if (keyInput && valInput && keyInput.value.trim() !== '') {
            headerPayload += keyInput.value.trim() + ': ' + valInput.value.trim() + '\n';
        }
    });

    document.getElementById('hidden-header-payload').value = headerPayload.trim();
});


const bodyTextarea = document.querySelector('textarea[name="data[Server][body]"]');
const descriptionBox = document.getElementById('template_description');
if (bodyTextarea && descriptionBox) {
    bodyTextarea.addEventListener('input', function () {
        const isEmpty = !bodyTextarea.value.trim();
        if (isEmpty) {
            descriptionBox.style.display = 'none';
        }
    });
}

document.getElementById('restClientForm').addEventListener('submit', function() {
    syncHeaders();
});
</script>