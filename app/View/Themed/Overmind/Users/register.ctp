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

$rolePerms = [
    'perm_publish' => [
        'id' => 'UserPermPublish',
        'label' => __('Publish permission'),
        'hint' => __('Publish events so they can be shared with and distributed to other users and communities.'),
    ],
    'perm_admin' => [
        'id' => 'UserPermAdmin',
        'label' => __('Org admin permission'),
        'hint' => __('Manage the users and settings of your own organisation.'),
    ],
    'perm_sync' => [
        'id' => 'UserPermSync',
        'label' => __('Sync permission'),
        'hint' => __('Synchronise events with connected MISP servers, used for server-to-server connections.'),
    ],
];

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

            <h1 class="oml-title" id="omlTitle"><?= __('Request access') ?></h1>

            <?php if (!empty($message)): ?>
                <p class="oml-lead"><?= h($message) ?></p>
            <?php endif; ?>

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

                <div class="oml-field">
                    <div class="oml-field-head">
                        <label for="UserOrgName"><?= __('Organisation name') ?></label>
                        <span class="oml-optional"><?= __('Optional') ?></span>
                    </div>
                    <?= $this->Form->input('org_name', [
                        'type' => 'text',
                        'id' => 'UserOrgName',
                        'class' => 'oml-input',
                        'autocomplete' => 'organization',
                        'label' => false,
                        'div' => false,
                        'error' => false,
                    ]) ?>
                </div>

                <div class="oml-field">
                    <div class="oml-field-head">
                        <label for="UserOrgUuid"><?= __('Organisation UUID') ?></label>
                        <span class="oml-optional"><?= __('Optional') ?></span>
                    </div>
                    <?= $this->Form->input('org_uuid', [
                        'type' => 'text',
                        'id' => 'UserOrgUuid',
                        'class' => 'oml-input oml-input-mono',
                        'autocomplete' => 'off',
                        'spellcheck' => 'false',
                        'label' => false,
                        'div' => false,
                        'error' => false,
                    ]) ?>
                    <p class="oml-hint"><?= __("You can also provide your organisation's name and/or its MISP UUID.") ?></p>
                </div>

                <div class="oml-field oml-switch">
                    <label for="UserCustomPerms"><?= __('Request custom role') ?></label>
                    <?= $this->Form->checkbox('custom_perms', [
                        'id' => 'UserCustomPerms',
                        'role' => 'switch',
                        'aria-controls' => 'omlRolePerms',
                        'aria-expanded' => 'false',
                    ]) ?>
                </div>

                <div class="oml-perms" id="omlRolePerms" hidden>
                    <?php foreach ($rolePerms as $field => $perm): ?>
                        <div class="oml-perm">
                            <div class="oml-switch">
                                <label for="<?= $perm['id'] ?>"><?= $perm['label'] ?></label>
                                <?= $this->Form->checkbox($field, [
                                    'id' => $perm['id'],
                                    'role' => 'switch',
                                ]) ?>
                            </div>
                            <p class="oml-hint"><?= $perm['hint'] ?></p>
                        </div>
                    <?php endforeach; ?>
                </div>

                <div class="oml-field">
                    <div class="oml-field-head">
                        <label for="UserPgp"><?= __('Your PGP key') ?></label>
                        <span class="oml-optional"><?= __('Optional') ?></span>
                    </div>
                    <?= $this->Form->input('pgp', [
                        'type' => 'textarea',
                        'id' => 'UserPgp',
                        'class' => 'oml-input oml-input-mono',
                        'rows' => 4,
                        'spellcheck' => 'false',
                        'label' => false,
                        'div' => false,
                        'error' => false,
                    ]) ?>
                </div>

                <div class="oml-field">
                    <div class="oml-field-head">
                        <label for="UserMessage"><?= __('Message to the admins') ?></label>
                        <span class="oml-optional"><?= __('Optional') ?></span>
                    </div>
                    <?= $this->Form->input('message', [
                        'type' => 'textarea',
                        'id' => 'UserMessage',
                        'class' => 'oml-input',
                        'rows' => 3,
                        'label' => false,
                        'div' => false,
                        'error' => false,
                    ]) ?>
                </div>

                <button class="oml-btn oml-btn-primary" type="submit"><?= __('Submit registration') ?></button>
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
