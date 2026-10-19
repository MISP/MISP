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

// A forced change cannot be skipped: every other page redirects back here.
$forced = !empty($me['change_pw']);
$requireCurrent = (bool)Configure::read('Security.require_password_confirmation');

$passwordFields = [
    'password' => [
        'id' => 'UserPassword',
        'label' => __('New password'),
        'autocomplete' => 'new-password',
    ],
    'confirm_password' => [
        'id' => 'UserConfirmPassword',
        'label' => __('Confirm new password'),
        'autocomplete' => 'new-password',
        'match' => 'UserPassword',
    ],
];
if ($requireCurrent) {
    $passwordFields['current_password'] = [
        'id' => 'UserCurrentPassword',
        'label' => __('Confirm with your current password'),
        'autocomplete' => 'current-password',
        'confirm' => true,
    ];
}

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

            <header class="oml-brand<?= $hasPartners ? ' oml-has-partners' : '' ?>">
                <?php if ($hasPartners): ?>
                    <div class="oml-brand-partner oml-brand-partner-left">
                        <?php if ($partnerLogos['left']): ?>
                            <img src="<?= $partnerLogos['left'] ?>" alt="<?= __('Logo') ?>" onerror="this.style.display='none';">
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                <div class="oml-brand-main">
                    <?php if ($mainLogo): ?>
                        <img src="<?= $mainLogo ?>" alt="<?= __('Logo') ?>">
                    <?php else: ?>
                        <img class="oml-logo-light" src="<?= $baseurl ?>/img/misp-logo-horizontal.png" alt="<?= __('MISP — Intelligence Sharing') ?>" width="1200" height="352">
                        <img class="oml-logo-dark" src="<?= $baseurl ?>/img/misp-logo-horizontal-light.png" alt="<?= __('MISP — Intelligence Sharing') ?>" width="1200" height="352">
                    <?php endif; ?>
                </div>
                <?php if ($hasPartners): ?>
                    <div class="oml-brand-partner oml-brand-partner-right">
                        <?php if ($partnerLogos['right']): ?>
                            <img src="<?= $partnerLogos['right'] ?>" alt="<?= __('Logo') ?>" onerror="this.style.display='none';">
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

            <h1 class="oml-title" id="omlTitle"><?= __('Change password') ?></h1>

            <?php if (!empty($me['email'])): ?>
                <p class="oml-account">
                    <i class="fa-regular fa-circle-user" aria-hidden="true"></i>
                    <span><?= h($me['email']) ?></span>
                </p>
            <?php endif; ?>

            <p class="oml-lead">
                <?= $forced
                    ? __('A new password is required before you can continue.')
                    : __('Choose a new password for your account.') ?>
            </p>

            <?= $this->Form->create('User', [
                'novalidate' => true,
                'url' => ['controller' => 'users', 'action' => 'change_pw'],
            ]) ?>
                <?php foreach ($passwordFields as $field => $opt): ?>
                    <div class="oml-field<?= !empty($opt['confirm']) ? ' oml-field-confirm' : '' ?>">
                        <div class="oml-field-head">
                            <label for="<?= $opt['id'] ?>"><?= $opt['label'] ?></label>
                        </div>
                        <div class="oml-control">
                            <?= $this->Form->input($field, [
                                'type' => 'password',
                                'id' => $opt['id'],
                                'class' => 'oml-input oml-input-pw',
                                'autocomplete' => $opt['autocomplete'],
                                'autofocus' => $field === 'password',
                                'required' => true,
                                'value' => '',
                                'data-oml-match' => $opt['match'] ?? null,
                                'data-oml-mismatch' => isset($opt['match']) ? __('The passwords do not match.') : null,
                                'label' => false,
                                'div' => false,
                                'error' => false,
                            ]) ?>
                            <button type="button" class="oml-reveal"
                                aria-controls="<?= $opt['id'] ?>" aria-pressed="false"
                                aria-label="<?= __('Show password') ?>"
                                data-label-show="<?= __('Show password') ?>"
                                data-label-hide="<?= __('Hide password') ?>">
                                <i class="fa-regular fa-eye" aria-hidden="true"></i>
                            </button>
                        </div>
                        <?= $this->Form->error($field, null, ['wrap' => 'div', 'class' => 'oml-error']) ?>
                        <?php if ($field === 'password'): ?>
                            <p class="oml-hint">
                                <?= __('Minimal length: %s', h($length)) ?>
                                <?php if (!empty($complexity)): ?>
                                    <br><?= __('Complexity: %s', '<code class="oml-code">' . h($complexity) . '</code>') ?>
                                <?php endif; ?>
                            </p>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>

                <button class="oml-btn oml-btn-primary" type="submit"><?= __('Change password') ?></button>
            <?= $this->Form->end() ?>

            <p class="oml-back">
                <?php if ($forced): ?>
                    <a href="<?= $baseurl ?>/users/logout"><?= __('Log out') ?></a>
                <?php else: ?>
                    <a href="<?= $baseurl ?>/users/view/me"><?= __('Back to my profile') ?></a>
                <?php endif; ?>
            </p>
        </section>
    </div>
</div>
<?= $this->element('genericElements/assetLoader', [
    'js' => ['overmind-login'],
]) ?>
