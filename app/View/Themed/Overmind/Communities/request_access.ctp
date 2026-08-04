<?php
echo $this->Form->create('Server', [
    'url' => $baseurl . '/communities/requestAccess/' . $community['uuid'],
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">

            <div class="card-body">

                <!-- TITLE -->
                <h3 class="mb-2">
                    <?= __('Request access to ') . h($community['name']) ?>
                </h3>

                <p class="text-muted mb-4">
                    <?= __('Describe both yourself and your organisation as best as you can. This information will be used by the community administrators to determine whether you are a good fit. By default, your server metadata (URL, UUID, version) is shared. You can disable this via the anonymisation option.') ?>
                </p>

                <!-- EMAIL -->
                <div class="mb-3">
                    <?= $this->Form->label('email', __('Requestor E-mail address'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('email', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'required' => true
                    ]) ?>
                </div>

                <!-- ORG NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('org_name', __('Organisation name'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('org_name', [
                        'label' => false,
                        'class' => 'form-control bg-light'
                    ]) ?>
                </div>

                <!-- ORG UUID -->
                <div class="mb-3">
                    <?= $this->Form->label('org_uuid', __('Organisation UUID'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('org_uuid', [
                        'label' => false,
                        'class' => 'form-control bg-light'
                    ]) ?>
                </div>

                <!-- ORG DESCRIPTION -->
                <div class="mb-3">
                    <?= $this->Form->label('org_description', __('Organisation description'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('org_description', [
                        'class' => 'form-control bg-light',
                        'rows' => 3,
                        'placeholder' => __('Describe your organisation...')
                    ]) ?>
                </div>

                <!-- MESSAGE -->
                <div class="mb-3">
                    <?= $this->Form->label('message', __('Message to the community'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('message', [
                        'class' => 'form-control bg-light',
                        'rows' => 3,
                        'placeholder' => __('Explain why you want to join...')
                    ]) ?>
                </div>

                <!-- GPG KEY -->
                <div class="mb-4">
                    <?= $this->Form->label('gpgkey', __('PGP Public Key'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('gpgkey', [
                        'class' => 'form-control bg-light font-monospace',
                        'rows' => 4,
                        'placeholder' => '-----BEGIN PGP PUBLIC KEY BLOCK-----'
                    ]) ?>
                </div>

                <!-- OPTIONS -->
                <div class="mb-4">

                    <div class="form-check form-switch mb-2">
                        <?= $this->Form->checkbox('sync', [
                            'class' => 'form-check-input'
                        ]) ?>
                        <?= $this->Form->label('sync', __('Request sync access'), ['class' => 'form-check-label']) ?>
                    </div>

                    <div class="form-check form-switch mb-2">
                        <?= $this->Form->checkbox('anonymise', [
                            'class' => 'form-check-input'
                        ]) ?>
                        <?= $this->Form->label('anonymise', __('Anonymise server information'), ['class' => 'form-check-label']) ?>
                    </div>

                    <div class="form-check form-switch">
                        <?= $this->Form->checkbox('mock', [
                            'class' => 'form-check-input',
                            'disabled' => !empty(Configure::read('MISP.disable_emailing')),
                            'checked' => !empty(Configure::read('MISP.disable_emailing'))
                        ]) ?>
                        <?= $this->Form->label('mock', __('Generate email only (do not send)'), ['class' => 'form-check-label']) ?>
                    </div>

                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" onclick="history.back()">
                        <?= __('Cancel') ?>
                    </button>

                    <?= $this->Form->button(
                        '<i class="fas fa-paper-plane me-1"></i> ' . __('Send request'),
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