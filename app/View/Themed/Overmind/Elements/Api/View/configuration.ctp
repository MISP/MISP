<?php
$arbitraryUrls = !empty(Configure::read('Security.rest_client_enable_arbitrary_urls'));
$restBaseUrl = Configure::read('Security.rest_client_baseurl') ?: Configure::read('MISP.baseurl');
$headerPayload = !empty($this->request->data['Server']['header'])
    ? $this->request->data['Server']['header']
    : ($header ?? '');

echo $this->Form->create('Server', [
    'novalidate' => true,
    'id' => 'restClientForm',
    'class' => 'card shadow-sm',
    'data-required-guard' => '1',
]);
?>

<div class="d-none">
    <?php
        echo $this->Form->input('header', [
            'type' => 'textarea',
            'id' => 'hidden-header-payload',
            'default' => $headerPayload,
        ]);
        echo $this->Form->input('bookmark', [
            'type' => 'checkbox',
            'id' => 'hidden-bookmark-checkbox',
        ]);
        // The Server model validates its own name, which makes FormHelper mark
        // this hidden bookmark name required, and the required guard would
        // then refuse every send.
        echo $this->Form->input('name', [
            'type' => 'text',
            'id' => 'hidden-bookmark-name',
            'required' => false,
        ]);
    ?>
</div>

<div class="card-body d-flex flex-column gap-2 pb-2">
    <div class="d-flex flex-wrap align-items-start gap-2">
        <div class="flex-grow-1 rest-request-line">
            <div class="input-group">
                <?= $this->Form->select('method', ['GET' => 'GET', 'POST' => 'POST', 'PUT' => 'PUT', 'DELETE' => 'DELETE'], [
                    'empty' => false,
                    'class' => 'form-select flex-grow-0 w-auto fw-bold font-monospace',
                    'id' => 'server-method',
                    'aria-label' => __('HTTP method'),
                ]) ?>
                <span class="input-group-text font-monospace small text-body-tertiary d-none d-md-flex" id="rest-base-url"
                      title="<?= __('Requests are sent to this instance') ?>"><?= h(rtrim($restBaseUrl, '/')) ?></span>
                <?= $this->Form->text('url', [
                    'class' => 'form-control font-monospace',
                    'id' => 'server-url',
                    'placeholder' => '/events/view/1',
                    'autocomplete' => 'off',
                    'required' => true,
                    'data-required-msg' => __('Enter the endpoint to call.'),
                    'aria-label' => __('Endpoint'),
                ]) ?>
            </div>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary" id="rest-bookmark-open"
                    title="<?= __('Bookmark this request') ?>" aria-label="<?= __('Bookmark this request') ?>">
                <i class="far fa-star"></i>
            </button>
            <button type="submit" class="btn btn-primary d-flex align-items-center gap-2 text-nowrap">
                <i class="fas fa-paper-plane"></i><?= __('Send') ?>
                <kbd class="d-none d-md-inline small bg-transparent border border-light-subtle"><?= __('Ctrl') ?> ↵</kbd>
            </button>
        </div>
    </div>

    <div class="d-flex flex-wrap align-items-center column-gap-4 row-gap-1 small">
        <?php if ($arbitraryUrls): ?>
            <div class="form-check form-switch mb-0">
                <?= $this->Form->checkbox('use_full_path', ['class' => 'form-check-input', 'id' => 'use-full-path', 'role' => 'switch']) ?>
                <label class="form-check-label" for="use-full-path"><?= __('Use full path') ?></label>
            </div>
        <?php endif; ?>
        <div class="form-check form-switch mb-0 ms-auto">
            <?= $this->Form->checkbox('show_result', ['class' => 'form-check-input', 'id' => 'show-result', 'role' => 'switch']) ?>
            <label class="form-check-label" for="show-result"><?= __('Show result') ?></label>
        </div>
        <div class="form-check form-switch mb-0">
            <?= $this->Form->checkbox('skip_ssl_validation', ['class' => 'form-check-input', 'id' => 'skip-ssl', 'role' => 'switch']) ?>
            <label class="form-check-label" for="skip-ssl"><?= __('Skip SSL validation') ?></label>
        </div>
    </div>
</div>

<ul class="nav nav-tabs px-3" role="tablist">
    <li class="nav-item" role="presentation">
        <button type="button" role="tab" class="nav-link active d-flex align-items-center gap-2" id="rest-tab-body"
                data-bs-toggle="tab" data-bs-target="#rest-pane-body" aria-controls="rest-pane-body" aria-selected="true">
            <?= __('Body') ?>
            <span class="badge bg-body-secondary text-body-secondary" id="rest-body-badge"
                  data-l-empty="<?= __('No body') ?>" data-l-valid="<?= __('JSON') ?>" data-l-invalid="<?= __('Invalid') ?>"><?= __('No body') ?></span>
        </button>
    </li>
    <li class="nav-item" role="presentation">
        <button type="button" role="tab" class="nav-link d-flex align-items-center gap-2" id="rest-tab-headers"
                data-bs-toggle="tab" data-bs-target="#rest-pane-headers" aria-controls="rest-pane-headers" aria-selected="false">
            <?= __('Headers') ?>
            <span class="badge rounded-pill bg-body-secondary text-body-secondary" id="rest-header-count">0</span>
            <i class="fas fa-circle fa-2xs text-warning d-none" id="rest-header-warning-dot"
               title="<?= __('Authorization still holds the placeholder') ?>"></i>
        </button>
    </li>
</ul>

<div class="tab-content card-body">
    <div class="tab-pane show active" id="rest-pane-body" role="tabpanel" aria-labelledby="rest-tab-body">
        <div class="alert alert-primary d-none align-items-start gap-3 py-2 px-3 small" id="rest-template-callout" role="status">
            <i class="fas fa-wand-magic-sparkles mt-1"></i>
            <div class="flex-grow-1 d-flex flex-column gap-1">
                <div>
                    <strong class="font-monospace" id="rest-template-name"></strong>
                    <?= __('loaded. Replace the placeholder values; fields set to "optional" can be removed.') ?>
                </div>
                <div class="d-none flex-wrap align-items-center gap-1 text-body-secondary" id="rest-template-required">
                    <span><?= __('Required:') ?></span>
                </div>
            </div>
            <button type="button" class="btn-close btn-sm" id="rest-template-close" aria-label="<?= __('Dismiss') ?>"></button>
        </div>

        <?= $this->element('genericElementsBS5/Forms/json_field', [
            'field' => 'body',
            'label' => __('Body'),
            'id' => 'server-body',
            'rows' => 8,
            'minHeight' => '200px',
            'emptyLabel' => __('No body'),
            'hint' => __('The request body — a GET needs none.'),
        ]) ?>
    </div>

    <div class="tab-pane" id="rest-pane-headers" role="tabpanel" aria-labelledby="rest-tab-headers">
        <div class="row g-2 small fw-bold text-uppercase text-body-secondary mb-1">
            <div class="col-4"><?= __('Key') ?></div>
            <div class="col"><?= __('Value') ?></div>
        </div>
        <div class="d-flex flex-column gap-2" id="rest-headers" data-placeholder="<?= h(__('YOUR_API_KEY')) ?>"></div>
        <div class="d-none text-warning-emphasis small mt-2" id="rest-header-warning">
            <i class="fas fa-triangle-exclamation me-1"></i><?= __('Authorization still holds the placeholder. Replace it with one of your auth keys.') ?>
        </div>
        <button type="button" class="btn btn-sm btn-link text-decoration-none px-0 mt-2" id="rest-header-add">
            <i class="fas fa-plus me-1"></i><?= __('Add header') ?>
        </button>
        <template id="rest-header-row">
            <div class="row g-2 align-items-center" data-rest-header>
                <div class="col-4">
                    <input type="text" class="form-control form-control-sm font-monospace header-key" spellcheck="false"
                           placeholder="<?= __('Header') ?>" aria-label="<?= __('Header name') ?>">
                </div>
                <div class="col">
                    <input type="text" class="form-control form-control-sm font-monospace header-value" spellcheck="false"
                           placeholder="<?= __('Value') ?>" aria-label="<?= __('Header value') ?>">
                </div>
                <div class="col-auto">
                    <button type="button" class="btn btn-sm btn-link link-secondary px-1" data-rest-header-remove
                            aria-label="<?= __('Remove header') ?>">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
            </div>
        </template>
    </div>
</div>

<?= $this->Form->end() ?>

<div class="modal fade" id="rest-bookmark-modal" tabindex="-1" aria-labelledby="rest-bookmark-title" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content border-0 overflow-hidden">
            <?= $this->element('genericElementsBS5/Forms/modal_header', [
                'accent' => 'warning',
                'eyebrow' => __('REST Client'),
                'title' => __('Bookmark this request'),
                'titleIcon' => 'fas fa-star',
                'titleId' => 'rest-bookmark-title',
                'description' => __('Saving sends the request once and keeps it, with its headers, body and options, in the Bookmarks tab.'),
                'icon' => 'fas fa-star',
            ]) ?>
            <div class="px-4 py-3 d-flex flex-column gap-3">
                <div>
                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                        'accent' => 'warning',
                        'label' => __('Name'),
                        'required' => true,
                        'for' => 'rest-bookmark-name',
                    ]) ?>
                    <input type="text" class="form-control" id="rest-bookmark-name" autocomplete="off"
                           placeholder="<?= __('e.g. TLP:green events this week') ?>">
                    <div class="invalid-feedback"><?= __('Give the bookmark a name.') ?></div>
                </div>
                <div>
                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                        'accent' => 'warning',
                        'label' => __('Request'),
                    ]) ?>
                    <div class="d-flex align-items-center gap-2 p-2 bg-body-tertiary border rounded font-monospace small text-break"
                         id="rest-bookmark-preview"></div>
                </div>
            </div>
            <?= $this->element('genericElementsBS5/Forms/modal_footer', [
                'accent' => 'warning',
                'bleed' => true,
                'align' => 'end',
                'cancel' => ['label' => __('Cancel')],
                'submit' => [
                    'label' => __('Save bookmark'),
                    'icon' => 'fas fa-star',
                    'id' => 'rest-bookmark-save',
                    'type' => 'button',
                ],
            ]) ?>
        </div>
    </div>
</div>
