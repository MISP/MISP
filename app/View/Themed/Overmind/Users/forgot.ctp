<div class="d-flex align-items-center justify-content-center overflow-y-auto" style="position: fixed; inset: 0;">
    <div class="col-md-auto py-4" style="max-width: 480px; width: 100%;">
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
            <h4 class="mb-2 fw-semibold text-center" style="color: #28191B;">
                <?= __('Forgotten password') ?>
            </h4>

            <!-- Description -->
            <p class="text-muted small text-center mb-4">
                <?= __('If you are enrolled on this instance but forgot your password, request a new one below.') ?>
                <?= __('An e-mail with a reset link (valid for 10 minutes) will be sent to you.') ?>
            </p>

            <!-- Form -->
            <?php
            echo $this->Form->create('User', [
                'class' => 'needs-validation',
                'novalidate' => true,
                'url' => ['controller' => 'users', 'action' => 'forgot']
            ]);
            ?>

            <label for="UserEmail" class="form-label fw-semibold">
                <?= __('Email') ?> <span class="text-danger">*</span>
            </label>
            <div class="mb-4">
                <?= $this->Form->input('email', [
                    'type' => 'email',
                    'id' => 'UserEmail',
                    'class' => 'form-control',
                    'placeholder' => __('Email'),
                    'required' => true,
                    'label' => false,
                    'div' => false,
                    'error' => false
                ]) ?>
                <div class="invalid-feedback">
                    <?= __('Please provide your email address.') ?>
                </div>
            </div>

            <div class="d-grid mb-3">
                <?= $this->Form->button(
                    '<i class="fa-solid fa-paper-plane me-2"></i>' . __('Send reset link'),
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
