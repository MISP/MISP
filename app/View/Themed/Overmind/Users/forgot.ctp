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

            <h1 class="oml-title" id="omlTitle"><?= __('Forgotten password') ?></h1>

            <p class="oml-lead">
                <?= __('If you are enrolled on this instance but forgot your password, request a new one below.') ?>
                <?= __('An e-mail with a reset link (valid for 10 minutes) will be sent to you.') ?>
            </p>

            <?= $this->Form->create('User', ['novalidate' => true]) ?>
                <div class="oml-field">
                    <div class="oml-field-head">
                        <label for="UserEmail"><?= __('Email') ?></label>
                    </div>
                    <?= $this->Form->input('email', [
                        'type' => 'email',
                        'id' => 'UserEmail',
                        'class' => 'oml-input',
                        'autocomplete' => 'email',
                        'autofocus' => true,
                        'required' => true,
                        'label' => false,
                        'div' => false,
                        'error' => false,
                    ]) ?>
                </div>

                <button class="oml-btn oml-btn-primary" type="submit"><?= __('Send reset link') ?></button>
            <?= $this->Form->end() ?>

            <p class="oml-back">
                <a href="<?= $baseurl ?>/users/login"><?= __('Back to login') ?></a>
            </p>
        </section>
    </div>
</div>
<?= $this->element('genericElements/assetLoader', [
    'js' => ['overmind-login'],
]) ?>
