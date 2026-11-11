<?php
/**
 * Overmind BS5 — add a signing key to a protected Event.
 *
 * Rendered layout-less as a modal fragment (see
 * CryptographicKeysController::add, theme === 'Overmind' branch). The form
 * submits natively; on success CRUD->add redirects to the parent Event view.
 * Fields match the legacy genericForm: type (PGP), key contents, and a helper
 * button that pastes the instance's own signing key into the textarea.
 */
echo $this->Form->create('CryptographicKey', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2"><?= __('Add signing key') ?></h3>

                <div class="form-text mb-3">
                    <?= __('Add a signing key to be used to validate the origin of event updates. By putting an event into protected mode, the event cannot reliably be propagated to / updated at instances beyond the reach of those that can sign with the listed keys below.') ?>
                </div>

                <!-- TYPE -->
                <div class="mb-3">
                    <?= $this->Form->label('type', __('Type'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('type', ['pgp' => 'PGP'], ['class' => 'form-select', 'empty' => false]) ?>
                </div>

                <!-- KEY DATA -->
                <div class="mb-2">
                    <?= $this->Form->label('key_data', __('Key contents'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('key_data', [
                        'class' => 'form-control font-monospace',
                        'rows' => 8,
                        'required' => true
                    ]) ?>
                </div>

                <div class="mb-4">
                    <button type="button" class="btn btn-sm btn-outline-secondary" id="useInstanceKeyBtn">
                        <i class="fas fa-key me-1"></i> <?= __('Use the instance\'s signing key') ?>
                    </button>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . __('Add key'),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => __('Add key'),
                            'aria-label' => __('Add key'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>

<script type="text/javascript">
    var cryptoInstanceKey = <?= json_encode(h($instanceKey)); ?>;
    (function () {
        var btn = document.getElementById('useInstanceKeyBtn');
        var ta = document.getElementById('CryptographicKeyKeyData');
        if (btn && ta) {
            btn.addEventListener('click', function () {
                ta.value = cryptoInstanceKey;
            });
        }
    })();
</script>
