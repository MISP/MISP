<?php
$this->set('headerTitle', __('Change password'));
$requireCurrent = (bool)Configure::read('Security.require_password_confirmation');
?>

<div class="container-fluid">
    <div class="row justify-content-center">
        <div class="col-lg-6 col-md-8">
            <div class="card shadow-sm">
                <div class="card-header d-flex align-items-center gap-2 bg-light">
                    <i class="fas fa-key text-primary"></i>
                    <span class="fw-semibold"><?= __('Change your password') ?></span>
                </div>
                <div class="card-body">

                    <?php
                    echo $this->Form->create('User', [
                        'id' => 'ChangePwForm',
                        'class' => 'needs-validation',
                        'novalidate' => true,
                        'url' => ['controller' => 'users', 'action' => 'change_pw'],
                    ]);
                    ?>

                    <!-- New password -->
                    <div class="mb-3">
                        <label for="UserPassword" class="form-label fw-semibold">
                            <?= __('New password') ?> <span class="text-danger">*</span>
                        </label>
                        <div class="position-relative">
                            <?= $this->Form->password('password', [
                                'id' => 'UserPassword',
                                'class' => 'form-control',
                                'required' => true,
                                'autocomplete' => 'new-password',
                                'autofocus' => true,
                                'value' => '',
                            ]) ?>
                            <button type="button"
                                    class="btn position-absolute top-50 end-0 translate-middle-y me-2 p-0 border-0 bg-transparent"
                                    data-toggle-password="UserPassword">
                                <i class="fa-solid fa-eye text-muted"></i>
                            </button>
                        </div>
                        <div class="form-text">
                            <?= __('Minimal length: %s — complexity: %s', h($length), h($complexity)) ?>
                        </div>
                        <div class="invalid-feedback">
                            <?= __('Please provide a new password.') ?>
                        </div>
                    </div>

                    <!-- Confirm new password -->
                    <div class="mb-3">
                        <label for="UserConfirmPassword" class="form-label fw-semibold">
                            <?= __('Confirm new password') ?> <span class="text-danger">*</span>
                        </label>
                        <div class="position-relative">
                            <?= $this->Form->password('confirm_password', [
                                'id' => 'UserConfirmPassword',
                                'class' => 'form-control',
                                'required' => true,
                                'autocomplete' => 'new-password',
                                'value' => '',
                            ]) ?>
                            <button type="button"
                                    class="btn position-absolute top-50 end-0 translate-middle-y me-2 p-0 border-0 bg-transparent"
                                    data-toggle-password="UserConfirmPassword">
                                <i class="fa-solid fa-eye text-muted"></i>
                            </button>
                        </div>
                        <div class="invalid-feedback" id="confirmPasswordFeedback">
                            <?= __('Please confirm your new password.') ?>
                        </div>
                    </div>

                    <?php if ($requireCurrent): ?>
                        <!-- Current password confirmation -->
                        <hr class="my-3">
                        <div class="mb-3">
                            <label for="UserCurrentPassword" class="form-label fw-semibold">
                                <?= __('Confirm with your current password') ?> <span class="text-danger">*</span>
                            </label>
                            <div class="position-relative">
                                <?= $this->Form->password('current_password', [
                                    'id' => 'UserCurrentPassword',
                                    'class' => 'form-control',
                                    'required' => true,
                                    'autocomplete' => 'current-password',
                                    'value' => '',
                                ]) ?>
                                <button type="button"
                                        class="btn position-absolute top-50 end-0 translate-middle-y me-2 p-0 border-0 bg-transparent"
                                        data-toggle-password="UserCurrentPassword">
                                    <i class="fa-solid fa-eye text-muted"></i>
                                </button>
                            </div>
                            <div class="invalid-feedback">
                                <?= __('Please enter your current password.') ?>
                            </div>
                        </div>
                    <?php endif; ?>

                    <div class="d-flex justify-content-end gap-2 mt-4">
                        <a href="<?= $baseurl ?>/users/view/me" class="btn btn-outline-secondary">
                            <?= __('Cancel') ?>
                        </a>
                        <?= $this->Form->button(
                            '<i class="fas fa-check me-1"></i>' . __('Change password'),
                            [
                                'class' => 'btn btn-primary',
                                'escapeTitle' => false,
                            ]
                        ) ?>
                    </div>

                    <?= $this->Form->end() ?>

                </div>
            </div>
        </div>
    </div>
</div>

<script>
(function () {
    var form = document.getElementById('ChangePwForm');
    if (!form) {
        return;
    }
    var pw = document.getElementById('UserPassword');
    var confirm = document.getElementById('UserConfirmPassword');
    var confirmFeedback = document.getElementById('confirmPasswordFeedback');
    var mismatchText = <?= json_encode(__('The passwords do not match.')) ?>;
    var emptyConfirmText = <?= json_encode(__('Please confirm your new password.')) ?>;

    // Show/hide password toggles.
    form.querySelectorAll('[data-toggle-password]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var input = document.getElementById(btn.getAttribute('data-toggle-password'));
            var icon = btn.querySelector('i');
            if (!input) {
                return;
            }
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    });

    // Keep a custom validity message so the two-password match is enforced.
    function checkMatch() {
        if (!confirm) {
            return;
        }
        if (confirm.value !== '' && pw.value !== confirm.value) {
            confirm.setCustomValidity('mismatch');
            if (confirmFeedback) {
                confirmFeedback.textContent = mismatchText;
            }
        } else {
            confirm.setCustomValidity('');
            if (confirmFeedback) {
                confirmFeedback.textContent = emptyConfirmText;
            }
        }
    }
    if (pw && confirm) {
        pw.addEventListener('input', checkMatch);
        confirm.addEventListener('input', checkMatch);
    }

    form.addEventListener('submit', function (event) {
        checkMatch();
        if (!form.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
        }
        form.classList.add('was-validated');
    }, false);
})();
</script>
