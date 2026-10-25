<?php
$customLogo = function ($setting) {
    $file = Configure::read($setting);
    if (empty($file) || !file_exists(APP . 'files/img/custom/' . $file)) {
        return null;
    }
    return $this->Image->base64(APP . 'files/img/custom/' . $file);
};
$mainLogo = $customLogo('MISP.main_logo');
$partnerLogos = [
    'left' => $customLogo('MISP.welcome_logo'),
    'right' => $customLogo('MISP.welcome_logo2'),
];
$hasPartners = !empty(array_filter($partnerLogos));

// Rendered inside the panel rather than in the layout's flash overlay.
$flashes = [];
foreach (['flash', 'auth'] as $flashKey) {
    $messages = CakeSession::read('Message.' . $flashKey);
    if (empty($messages)) {
        continue;
    }
    CakeSession::delete('Message.' . $flashKey);
    foreach ($messages as $flash) {
        $flashes[] = [
            'message' => $flash['message'],
            'error' => isset($flash['element']) && basename($flash['element']) === 'error',
        ];
    }
}

$ssoButtons = [];
if (Configure::read('ApacheShibbAuth')) {
    $ssoButtons[] = [
        'url' => '/Shibboleth.sso/Login',
        'icon' => 'fa-solid fa-key',
        'label' => __('Log in with SAML'),
    ];
}
if (Configure::read('AadAuth')) {
    $ssoButtons[] = [
        'url' => $baseurl . '/users/login?AzureAD=enable',
        'icon' => 'fa-brands fa-microsoft',
        'label' => __('Log in with Azure AD'),
    ];
}
if (Configure::read('OidcAuth') && Configure::read('OidcAuth.mixedAuth')) {
    $ssoButtons[] = [
        'url' => $baseurl . '/users/login?OidcAuth=enable',
        'icon' => 'fa-solid fa-id-card',
        'label' => Configure::read('OidcAuth.login_button_text') ?: __('Log in with OIDC'),
    ];
}

$otpEnabled = !empty(Configure::read('LinOTPAuth')) && Configure::read('LinOTPAuth.enabled') !== false;
$welcomeTop = Configure::read('MISP.welcome_text_top');
$welcomeBottom = Configure::read('MISP.welcome_text_bottom');

echo $this->element('genericElements/assetLoader', [
    'css' => ['overmind-login'],
]);
?>
<div class="oml">
    <canvas class="oml-sky" id="omlSky" aria-hidden="true"></canvas>
    <div class="oml-stage">
        <section class="oml-panel" aria-labelledby="omlTitle">
            <div class="oml-rule" aria-hidden="true"></div>
            <?php foreach (['omlPortHub' => 'oml-port-hub', 'omlPortSide' => 'oml-port-side'] as $portId => $portClass): ?>
                <svg class="oml-port <?= $portClass ?>" id="<?= $portId ?>" viewBox="-12 -12 24 24" aria-hidden="true" focusable="false">
                    <polygon class="oml-port-ring" points="0,-7 6.06,-3.5 6.06,3.5 0,7 -6.06,3.5 -6.06,-3.5"/>
                    <polygon class="oml-port-core" points="0,-7 6.06,-3.5 6.06,3.5 0,7 -6.06,3.5 -6.06,-3.5"/>
                </svg>
            <?php endforeach; ?>
            <?php if ($welcomeTop): ?>
                <p class="oml-welcome-top"><?= h($welcomeTop) ?></p>
            <?php endif; ?>

            <header class="oml-brand<?= $hasPartners ? ' oml-has-partners' : '' ?>">
                <?php if ($hasPartners): ?>
                    <div class="oml-brand-partner oml-brand-partner-left">
                        <?php if ($partnerLogos['left']): ?>
                            <img src="<?= $partnerLogos['left'] ?>" alt="<?= h(__('Logo')) ?>" onerror="this.style.display='none';">
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                <div class="oml-brand-main">
                    <?php if ($mainLogo): ?>
                        <img src="<?= $mainLogo ?>" alt="<?= h(__('Logo')) ?>">
                    <?php else: ?>
                        <img class="oml-logo-light" src="<?= $baseurl ?>/img/misp-logo-horizontal.png" alt="<?= h(__('MISP — Intelligence Sharing')) ?>" width="1200" height="352">
                        <img class="oml-logo-dark" src="<?= $baseurl ?>/img/misp-logo-horizontal-light.png" alt="<?= h(__('MISP — Intelligence Sharing')) ?>" width="1200" height="352">
                    <?php endif; ?>
                </div>
                <?php if ($hasPartners): ?>
                    <div class="oml-brand-partner oml-brand-partner-right">
                        <?php if ($partnerLogos['right']): ?>
                            <img src="<?= $partnerLogos['right'] ?>" alt="<?= h(__('Logo')) ?>" onerror="this.style.display='none';">
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </header>

            <?php foreach ($flashes as $flash): ?>
                <?php if ($flash['error']): ?>
                    <div class="oml-flash oml-flash-error" role="alert">
                        <i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>
                        <span><?= h($flash['message']) ?></span>
                    </div>
                <?php else: ?>
                    <div class="oml-flash oml-flash-info" role="status">
                        <i class="fa-solid fa-circle-info" aria-hidden="true"></i>
                        <span><?= h($flash['message']) ?></span>
                    </div>
                <?php endif; ?>
            <?php endforeach; ?>

            <h1 class="oml-title" id="omlTitle"><?= h(__('Log in')) ?></h1>

            <?php if (!$formLoginEnabled && $ssoButtons): ?>
                <p class="oml-sso-lead"><?= h(__('This instance uses single sign-on. Choose your identity provider.')) ?></p>
            <?php endif; ?>

            <?php if ($formLoginEnabled): ?>
                <?= $this->Form->create('User', ['novalidate' => true]) ?>
                    <div class="oml-field">
                        <div class="oml-field-head">
                            <label for="UserEmail"><?= h(__('Email')) ?></label>
                        </div>
                        <?= $this->Form->input('email', [
                            'type' => 'email',
                            'id' => 'UserEmail',
                            'class' => 'oml-input',
                            'autocomplete' => 'username',
                            'autofocus' => true,
                            'required' => true,
                            'label' => false,
                            'div' => false,
                            'error' => false,
                        ]) ?>
                    </div>

                    <div class="oml-field">
                        <div class="oml-field-head">
                            <label for="UserPassword"><?= h(__('Password')) ?></label>
                            <?php if (Configure::read('Security.allow_password_forgotten')): ?>
                                <a href="<?= $baseurl ?>/users/forgot"><?= h(__('Forgot your password?')) ?></a>
                            <?php endif; ?>
                        </div>
                        <div class="oml-control">
                            <?= $this->Form->input('password', [
                                'type' => 'password',
                                'id' => 'UserPassword',
                                'class' => 'oml-input oml-input-pw',
                                'autocomplete' => 'current-password',
                                'required' => true,
                                'label' => false,
                                'div' => false,
                                'error' => false,
                            ]) ?>
                            <button type="button" class="oml-reveal" id="omlPasswordToggle"
                                aria-controls="UserPassword" aria-pressed="false"
                                aria-label="<?= h(__('Show password')) ?>"
                                data-label-show="<?= h(__('Show password')) ?>"
                                data-label-hide="<?= h(__('Hide password')) ?>">
                                <i class="fa-regular fa-eye" aria-hidden="true"></i>
                            </button>
                        </div>
                    </div>

                    <?php if ($otpEnabled): ?>
                        <div class="oml-field">
                            <div class="oml-field-head">
                                <label for="UserOtp"><?= h(__('One-time password')) ?></label>
                            </div>
                            <?= $this->Form->input('otp', [
                                'type' => 'text',
                                'id' => 'UserOtp',
                                'class' => 'oml-input oml-input-otp',
                                'inputmode' => 'numeric',
                                'autocomplete' => 'one-time-code',
                                'label' => false,
                                'div' => false,
                                'error' => false,
                            ]) ?>
                            <p class="oml-hint">
                                <?= __('Enter the code from your token. Manage your tokens in %s.', sprintf(
                                    '<a href="%s/selfservice">LinOTP Selfservice</a>',
                                    h(Configure::read('LinOTPAuth.baseUrl'))
                                )) ?>
                            </p>
                        </div>
                    <?php endif; ?>

                    <button class="oml-btn oml-btn-primary" type="submit"><?= h(__('Log in')) ?></button>
                <?= $this->Form->end() ?>

                <?php if ($ssoButtons): ?>
                    <div class="oml-divider" aria-hidden="true"><?= h(__('or')) ?></div>
                <?php endif; ?>
            <?php endif; ?>

            <?php foreach ($ssoButtons as $sso): ?>
                <a class="oml-btn oml-btn-sso" href="<?= h($sso['url']) ?>">
                    <i class="<?= $sso['icon'] ?>" aria-hidden="true"></i>
                    <?= h($sso['label']) ?>
                </a>
            <?php endforeach; ?>

            <?php if ($formLoginEnabled && Configure::read('Security.allow_self_registration')): ?>
                <p class="oml-register">
                    <?= h(__('No account yet?')) ?>
                    <a href="<?= $baseurl ?>/users/register" title="<?= h(__('Registration will be sent to the administrators of the instance for consideration.')) ?>"><?= h(__('Request access')) ?></a>
                </p>
            <?php endif; ?>

            <?php if ($welcomeBottom): ?>
                <p class="oml-welcome-bottom"><?= h($welcomeBottom) ?></p>
            <?php endif; ?>
        </section>
    </div>
</div>
<?= $this->element('genericElements/assetLoader', [
    'js' => ['overmind-login'],
]) ?>
