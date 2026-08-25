<div class="d-flex align-items-center justify-content-center overflow-y-auto" style="position: fixed; inset: 0;">
    <div class="col-md-auto py-4" style="max-width: 560px; width: 100%;">
        <div class="card shadow-lg p-4" style="background-color: #ffffff">

            <!-- Logo -->
            <div class="d-flex align-items-center justify-content-center mb-4">
                <?php
                if (Configure::read('MISP.main_logo') && file_exists(APP . '/files/img/custom/' . Configure::read('MISP.main_logo'))) {
                    echo $this->Html->image('files/img/custom/' . Configure::read('MISP.main_logo'), [
                        'alt' => __('Main Logo'),
                        'class' => 'main-logo',
                        'style' => 'max-height: 80px; height: auto; width: auto;'
                    ]);
                } else {
                    echo $this->Html->image('misp-logo-main-cmyk-hori-.png', [
                        'alt' => __('MISP Logo'),
                        'class' => 'main-logo',
                        'style' => 'max-height: 80px; height: auto; width: auto;'
                    ]);
                }
                ?>
            </div>

            <!-- Title -->
            <div class="d-flex align-items-center justify-content-center gap-3 mb-4">
                <h4 class="fw-semibold text-center" style="color: #28191B;">
                    <?= __('Register for a new user account') ?>
                </h4>
                <!-- Self-registration message -->
                <?php if (!empty($message)): ?>
                    <i class="fa-solid fa-info-circle text-primary mb-1"
                    tabindex="0"
                    title="<?= h($message) ?>"
                    aria-label="<?= h($message) ?>"></i>
                <?php endif; ?>
            </div>

            <!-- Form -->
            <?php
            echo $this->Form->create('User', [
                'class' => 'needs-validation',
                'novalidate' => true,
                'url' => ['controller' => 'users', 'action' => 'register']
            ]);
            ?>

            <!-- Email (required) -->
            <label for="UserEmail" class="form-label fw-semibold">
                <?= __('Please provide your email') ?> <span class="text-danger">*</span>
            </label>
            <div class="form-floating mb-4">
                <?= $this->Form->input('email', [
                    'type' => 'email',
                    'id' => 'UserEmail',
                    'class' => 'form-control',
                    'placeholder' => __('Email'),
                    'required' => true,
                    'label' => false,
                    'div' => false
                ]) ?>
                <label for="UserEmail"><?= __('Email') ?></label>
            </div>

            <!-- Organisation name -->
            <div class="form-label fw-semibold">
                <?= __("You can also provide your organisation's name and/or its MISP UUID.") ?>
            </div>
            <div class="form-floating mb-3">
                <?= $this->Form->input('org_name', [
                    'type' => 'text',
                    'id' => 'UserOrgName',
                    'class' => 'form-control',
                    'placeholder' => __("Org name"),
                    'label' => false,
                    'div' => false
                ]) ?>
                <label for="UserOrgName"><?= __("Org name") ?></label>
            </div>

            <!-- Organisation UUID -->
            <div class="form-floating mb-4">
                <?= $this->Form->input('org_uuid', [
                    'type' => 'text',
                    'id' => 'UserOrgUuid',
                    'class' => 'form-control',
                    'placeholder' => __('Org uuid'),
                    'label' => false,
                    'div' => false
                ]) ?>
                <label for="UserOrgUuid"><?= __('Org uuid') ?></label>
            </div>

            <!-- Custom role request -->
            <div class="form-switch d-flex align-items-center justify-content-between ps-0 mb-4" id="CustomWrapper">
                <label class="form-check-label fw-semibold mb-0" for="UserCustomPerms">
                    <?= __('Request custom role') ?>
                </label>
                <?= $this->Form->checkbox('custom_perms', [
                    'id' => 'UserCustomPerms',
                    'class' => 'form-check-input m-0',
                    'role' => 'switch'
                ]) ?>
            </div>

            <!-- Permission switches (revealed when a custom role is requested) -->
            <div id="rolePermsWrapper" class="collapse mb-4">
                <div class="border rounded p-3 bg-light">
                    <!-- Publish -->
                    <div class="mb-3">
                        <div class="form-switch d-flex align-items-center justify-content-between ps-0">
                            <label class="form-check-label" for="UserPermPublish">
                                <?= __('Publish permission') ?>
                            </label>
                            <?= $this->Form->checkbox('perm_publish', [
                                'id' => 'UserPermPublish',
                                'class' => 'form-check-input role-field m-0',
                                'role' => 'switch'
                            ]) ?>
                        </div>
                        <div style="color:var(--bs-secondary-color); font-size:0.875rem">
                            <?= __('Publish events so they can be shared with and distributed to other users and communities.') ?>
                        </div>
                    </div>

                    <!-- Org admin -->
                    <div class="mb-3">
                        <div class="form-switch d-flex align-items-center justify-content-between ps-0">
                            <label class="form-check-label" for="UserPermAdmin">
                                <?= __('Org admin permission') ?>
                            </label>
                            <?= $this->Form->checkbox('perm_admin', [
                                'id' => 'UserPermAdmin',
                                'class' => 'form-check-input role-field m-0',
                                'role' => 'switch'
                            ]) ?>
                        </div>
                        <div style="color:var(--bs-secondary-color); font-size:0.875rem">
                            <?= __("Manage the users and settings of your own organisation.") ?>
                        </div>
                    </div>

                    <!-- Sync -->
                    <div>
                        <div class="form-switch d-flex align-items-center justify-content-between ps-0">
                            <label class="form-check-label" for="UserPermSync">
                                <?= __('Sync permission') ?>
                            </label>
                            <?= $this->Form->checkbox('perm_sync', [
                                'id' => 'UserPermSync',
                                'class' => 'form-check-input role-field m-0',
                                'role' => 'switch'
                            ]) ?>
                        </div>
                        <div style="color:var(--bs-secondary-color); font-size:0.875rem">
                            <?= __('Synchronise events with connected MISP servers, used for server-to-server connections.') ?>
                        </div>
                    </div>
                </div>
            </div>

            <!-- PGP key -->
            <div class="mb-4">
                <label for="UserPgp" class="form-label fw-semibold"><?= __('Your PGP key') ?></label>
                <?= $this->Form->input('pgp', [
                    'type' => 'textarea',
                    'id' => 'UserPgp',
                    'class' => 'form-control',
                    'rows' => 4,
                    'label' => false,
                    'div' => false
                ]) ?>
            </div>

            <!-- Message to admins -->
            <div class="mb-4">
                <label for="UserMessage" class="form-label fw-semibold"><?= __('Message to the admins') ?></label>
                <?= $this->Form->input('message', [
                    'type' => 'textarea',
                    'id' => 'UserMessage',
                    'class' => 'form-control',
                    'rows' => 3,
                    'label' => false,
                    'div' => false
                ]) ?>
            </div>

            <!-- Submit -->
            <div class="d-grid mb-3">
                <?= $this->Form->button(
                    '<i class="fa-solid fa-user-plus me-2"></i>' . __('Submit registration'),
                    [
                        'class' => 'btn btn-primary btn-login btn-lg',
                        'escape' => false
                    ]
                ); ?>
            </div>

            <?= $this->Form->end(); ?>

            <!-- Back to login -->
            <div class="text-center">
                <a href="<?= $baseurl ?>/users/login" class="text-decoration-none">
                    <i class="fa-solid fa-arrow-left me-2"></i><?= __('Back to login') ?>
                </a>
            </div>

        </div>
    </div>
</div>

<script>
// Reveal the permission checkboxes only when a custom role is requested
(function () {
    var wrapper = document.getElementById('CustomWrapper');
    var customPerms = document.getElementById('UserCustomPerms');
    var rolesWrapper = document.getElementById('rolePermsWrapper');
    if (customPerms && rolesWrapper) {
        customPerms.addEventListener('change', function () {
            if (customPerms.checked) {
                wrapper.classList.remove('mb-4');
                wrapper.classList.add('mb-2');
                rolesWrapper.classList.add('show');
            } else {
                wrapper.classList.add('mb-4');
                wrapper.classList.remove('mb-2');
                rolesWrapper.classList.remove('show');
                // Reset the role checkboxes when the custom role request is cleared
                rolesWrapper.querySelectorAll('.role-field').forEach(function (cb) {
                    cb.checked = false;
                });
            }
        });
    }
})();

// Flag email input if not filled
(function () {
    var form = document.querySelector('form.needs-validation');
    if (!form) {
        return;
    }
    form.addEventListener('submit', function (event) {
        if (!form.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
        }
        form.classList.add('was-validated');
    }, false);
})();
</script>

