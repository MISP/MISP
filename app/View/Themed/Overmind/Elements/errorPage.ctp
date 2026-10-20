<?php
/**
 * Error panel on the login backdrop, under the navbar when a user is logged in.
 *
 * @var string $label Kicker above the title, e.g. "Error 404"
 * @var string $icon Font Awesome classes for the kicker
 * @var string $title Already escaped
 * @var string $message HTML, any user input in it already escaped
 * @var Exception $error
 */
$showTrace = Configure::read('debug') > 0 && !empty($error);

// Only a page the browser navigated to gets the backdrop; a fragment fetched
// into a modal, or read by the debug strip, keeps the plain markup.
if ($this->request->is('ajax') || !$this->request->accepts('text/html')): ?>
    <div class="misp-error-container">
        <h2><?= $title ?></h2>
        <p class="error">
            <strong><?= h($label) ?>:</strong>
            <?= $message ?>
        </p>
        <?php if ($showTrace): ?>
            <?= $this->element('exception_stack_trace', ['error' => $error]) ?>
        <?php endif; ?>
    </div>
<?php
    return;
endif;

App::uses('OvermindPages', 'Tools');

// The navbar needs a user, and an auth page stays bare even when one is
// logged in (a forced password change, for instance).
$withNavbar = !empty($me)
    && !OvermindPages::isAuthPage($this->params['controller'], $this->params['action']);

// Read by the layout.
$this->set('isErrorPage', true);
$this->set('errorPageNavbar', $withNavbar);
$this->set('hideHeaderSection', true);
$this->assign('title', $label);

// Without the navbar, the panel carries the branding itself.
if (!$withNavbar) {
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
}

// A fresh GET of the previous page, which also renews an expired CSRF token.
$backPath = $this->request->referer(true);
if (
    $backPath === '/'
    || !preg_match('#^/(?![/\\\\])#', $backPath)
    || ($this->request->is('get') && $backPath === $this->request->here(false))
) {
    $backPath = null;
}
$homeLabel = empty($me) ? __('Go to the login page') : __('Go to the start page');

echo $this->element('genericElements/assetLoader', [
    'css' => ['overmind-login'],
]);
?>
<div class="oml<?= $withNavbar ? ' oml-under-nav' : '' ?>">
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

            <?php if (!$withNavbar): ?>
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
            <?php endif; ?>

            <p class="oml-kicker">
                <i class="<?= h($icon) ?>" aria-hidden="true"></i>
                <span><?= h($label) ?></span>
            </p>
            <h1 class="oml-title" id="omlTitle"><?= $title ?></h1>
            <?php if ($message !== ''): ?>
                <p class="oml-lead"><?= $message ?></p>
            <?php endif; ?>

            <?php if ($backPath): ?>
                <a class="oml-btn oml-btn-primary" href="<?= $baseurl . h($backPath) ?>"><?= __('Go back') ?></a>
                <p class="oml-back">
                    <a href="<?= $baseurl ?>/"><?= $homeLabel ?></a>
                </p>
            <?php else: ?>
                <a class="oml-btn oml-btn-primary" href="<?= $baseurl ?>/"><?= $homeLabel ?></a>
            <?php endif; ?>

            <?php if ($showTrace): ?>
                <details class="oml-debug">
                    <summary><?= __('Technical details') ?></summary>
                    <div class="oml-debug-body">
                        <?= $this->element('exception_stack_trace', ['error' => $error]) ?>
                    </div>
                </details>
            <?php endif; ?>
        </section>
    </div>
</div>
<?= $this->element('genericElements/assetLoader', [
    'js' => ['overmind-login'],
]) ?>
