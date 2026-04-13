
<?php
    echo $this->Session->flash('auth');
?>

<div class="container pb-5">
    <div class="d-flex align-items-center justify-content-center">
        <div class="row justify-content-center">
            <div class="col-md-auto">
                <div class="card shadow-lg p-4">
                    <!-- Welcome message -->
                    <div class="mb-4 text-center">
                        <h2 class="fw-bold">
                            <?php
                                if (Configure::read('MISP.welcome_text_top')) {
                                    echo h(Configure::read('MISP.welcome_text_top'));
                                }
                            ?>
                        </h2>
                    </div>

                    <!-- Logos : welcome_logo | main_logo | welcome_logo2 -->
                    <div class="d-flex align-items-center justify-content-center gap-5 mb-4">

                        <div>
                            <?php 
                            if (Configure::read('MISP.welcome_logo') && file_exists(APP . '/files/img/custom/' . Configure::read('MISP.welcome_logo'))) {
                                $logoPath = APP . 'files/img/custom/' . Configure::read('MISP.welcome_logo');
                                $logoBase64 = $this->Image->base64($logoPath);
                            ?>
                                    <img src="<?= $logoBase64 ?>" 
                                        alt="<?= __('Welcome Logo') ?>"
                                        class="welcome-logo"
                                        onerror="this.style.display='none';">
                            <?php } ?>
                        </div>

                        <div>
                            <?php
                            if (Configure::read('MISP.main_logo') && file_exists(APP . '/files/img/custom/' . Configure::read('MISP.main_logo'))) {
                                echo $this->Html->image('files/img/custom/' . Configure::read('MISP.main_logo'), [
                                    'alt' => __('Main Logo'),
                                    'class' => 'main-logo'
                                ]);
                            } else {
                                echo $this->Html->image('misp-logo-main-cmyk-hori-.png', [
                                    'alt' => __('MISP Logo'), 
                                    'class' => 'main-logo'
                                ]);
                            }
                            ?>
                        </div>

                        <div>
                            <?php 
                            if (Configure::read('MISP.welcome_logo2') && file_exists(APP . '/files/img/custom/' . Configure::read('MISP.welcome_logo2'))) {
                                $logoPath2 = APP . 'files/img/custom/' . Configure::read('MISP.welcome_logo2');
                                $logoBase642 = $this->Image->base64($logoPath2);
                            ?>
                                <img src="<?= $logoBase642 ?>" 
                                    alt="<?= __('Welcome Logo 2') ?>"
                                    class="welcome-logo"
                                    onerror="this.style.display='none';">
                            <?php } ?>
                        </div>
                    </div>

                    <!-- Bottom message -->
                    <div class="mb-4 text-center">
                        <?php
                            if (Configure::read('MISP.welcome_text_bottom')) {
                                echo h(Configure::read('MISP.welcome_text_bottom'));
                            }
                        ?>
                    </div>

                    <!-- Form -->
                    <?php if ($formLoginEnabled): ?>
                        <?php
                        echo $this->Form->create('User', [
                            'class' => 'needs-validation',
                            'novalidate' => true
                        ]);
                        ?>
                        <h4 class="mb-3 fw-semibold">Sign in</h4>

                        <!-- Email -->
                        <div class="form-floating mb-3">
                            <?= $this->Form->input('email', [
                                'type' => 'email',
                                'id' => 'UserEmail',
                                'class' => 'form-control',
                                'placeholder' => __('Email'),
                                'label' => false,
                                'div' => false
                            ]) ?>
                            <label for="UserEmail"><?= __('Email') ?></label>
                        </div>

                        <!-- Password -->
                        <div class="form-floating mb-3 position-relative">
                            <?= $this->Form->input('password', [
                                'type' => 'password',
                                'id' => 'UserPassword',
                                'class' => 'form-control ',
                                'placeholder' => __('Password'),
                                'label' => false,
                                'div' => false
                            ]) ?>
                            <label for="UserPassword"><?= __('Password') ?></label>

                            <button type="button"
                                    class="btn position-absolute top-50 end-0 translate-middle-y me-3 p-0 border-0 bg-transparent"
                                    onclick="togglePassword()">
                                <i id="toggleIcon" class="fa-solid fa-eye text-muted"></i>
                            </button>
                        </div>


                        <!-- OTP -->
                        <?php if (!empty(Configure::read('LinOTPAuth')) && Configure::read('LinOTPAuth.enabled') !== FALSE): ?>
                            <div class="form-floating mb-3">
                                <?= $this->Form->input('otp', [
                                    'type' => 'integer',
                                    'id' => 'UserOtp',
                                    'class' => 'form-control',
                                    'placeholder' => __('One-Time Password'),
                                    'label' => false,
                                    'div' => false
                                ]) ?>
                                <label for="UserOtp"><?= __('OTP') ?></label>
                            </div>
                            <div class="alert alert-secondary d-flex align-items-center small mb-3" role="alert">
                                <i class="fa-solid fa-info-circle me-2 text-primary"></i>
                                <div>
                                    <?= __('Visit') ?>
                                    <a href="<?= h(Configure::read('LinOTPAuth.baseUrl')) ?>/selfservice"
                                    class="link-primary text-decoration-none fw-semibold"
                                    title="LinOTP Selfservice">
                                        LinOTP Selfservice
                                    </a>
                                    <?= __('for the One-Time-Password selfservice.') ?>
                                </div>
                            </div>
                        <?php endif; ?>

                        <!-- Login Button -->
                        <div class="d-grid mb-4">
                            <?= $this->Form->button(
                            '<i class="fa-solid fa-sign-out-alt me-2"></i>' . __('Login'),
                            [
                                'class' => 'btn btn-primary btn-login btn-lg',
                                'escape' => false
                            ]
                        ); ?>
                        </div>


                        <!-- Password reset / Registration -->
                        <div class="d-flex justify-content-between mb-4">
                            <?= empty(Configure::read('Security.allow_self_registration')) ? '' :
                                sprintf('<a href="%s/users/register" class="btn-lg text-decoration-none">
                                    <i class="fa-solid fa-user-plus me-2"></i> %s </a>',
                                $baseurl,
                                __('Sign up')) ?>
                            <?= empty(Configure::read('Security.allow_password_forgotten')) ? '' :
                                sprintf('<a href="%s/users/forgot" class="text-decoration-none">%s</a>',
                                $baseurl,
                                __('Forgot password?')) ?>
                        </div>

                        <?= $this->Form->end(); ?>

                        <!-- Auth alternatives -->
                        <?php if (Configure::read('ApacheShibbAuth') || Configure::read('AadAuth') || (Configure::read('OidcAuth') && Configure::read('OidcAuth.mixedAuth'))): ?>
                            <div class="text-center text-muted mb-3 separator">
                                <?= __('Or login with') ?>
                            </div>
                        <?php endif; ?>

                        <?php if (Configure::read('ApacheShibbAuth')): ?>
                            <div class="d-grid mb-3">
                                    <?= $this->Html->link(
                                        '<i class="fa-solid fa-shield-alt text-danger me-2"></i>' . __('Login with SAML'),
                                        '/Shibboleth.sso/Login',
                                        [
                                            'class' => 'btn btn-outline-primary btn-login btn-lg',
                                            'escape' => false
                                        ]
                                    ) ?>
                            </div>
                        <?php endif; ?>

                        <?php if (Configure::read('AadAuth')): ?>
                            <div class="d-grid mb-3">
                                    <?= $this->Html->link(
                                    '<i class="fa-brands fa-microsoft text-info me-2"></i>' . __('Login with Azure AD'),
                                    [
                                        'controller' => 'users',
                                        'action' => 'login',
                                        '?' => ['AzureAD' => 'enable']
                                    ],
                                    [
                                        'class' =>  'btn btn-outline-primary btn-login btn-lg',
                                        'escape' => false
                                    ]
                                ) ?>
                            </div>
                        <?php endif; ?>

                        <?php if (Configure::read('OidcAuth') && Configure::read('OidcAuth.mixedAuth')): ?>
                            <div class="d-grid mb-3">
                                    <?= $this->Html->link(
                                        '<i class="fa-solid fa-id-badge text-warning me-2"></i>' . __('Login with OIDC'),
                                        [
                                            'controller' => 'users',
                                            'action' => 'login',
                                            '?' => ['OidcAuth' => 'enable']
                                        ],
                                        [
                                            'class' =>  'btn btn-outline-primary btn-login btn-lg',
                                            'escape' => false
                                        ]
                                    ) ?>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function togglePassword() {
    const passwordInput = document.getElementById("UserPassword");
    const icon = document.getElementById("toggleIcon");

    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
    } else {
        passwordInput.type = "password";
        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
    }
}
</script>
