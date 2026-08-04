<?php
/**
 * To be reworked
 */
$u       = $data['User'];
$role    = $data['Role'] ?? [];
$server  = $data['Server'] ?? [];
$adminView = !empty($admin_view);

// Small helper to render a "label + value" cell in the meta grid.
$field = function ($label, $valueHtml, $cols = 4) {
    return sprintf(
        '<div class="col-md-%d mb-3">
            <div class="text-muted small text-uppercase fw-bold mb-1">%s</div>
            <div class="fw-semibold">%s</div>
        </div>',
        (int)$cols,
        h($label),
        $valueHtml
    );
};

// Icon + label + value cell for the identity grid.
$item = function ($icon, $label, $valueHtml, $cols = 6) {
    return sprintf(
        '<div class="col-md-%d">
            <div class="d-flex align-items-start gap-3">
                <div class="rounded bg-light d-flex align-items-center justify-content-center flex-shrink-0" style="width:38px; height:38px;">
                    <i class="fas fa-%s text-primary"></i>
                </div>
                <div style="min-width:0;">
                    <div class="text-muted text-uppercase fw-bold mb-1" style="font-size:.62rem; letter-spacing:.07em;">%s</div>
                    <div class="fw-semibold text-break">%s</div>
                </div>
            </div>
        </div>',
        (int)$cols,
        h($icon),
        h($label),
        $valueHtml
    );
};

$boolBadge = function ($bool) {
    return $this->element('genericElementsBS5/Badges/boolean', [
        'boolean'    => !empty($bool),
        'full'       => true,
        'true'       => __('Yes'),
        'false'      => __('No'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check',
        'falseIcon'  => 'fa-xmark',
    ]);
};
?>

<!-- IDENTITY CARD -->
<div class="card mb-3 shadow-sm overflow-hidden">

    <!-- HERO HEADER -->
    <div class="p-4 d-flex align-items-center gap-3"
         style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--primary);">
        <div class="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center shadow-sm flex-shrink-0"
             style="width:64px; height:64px; font-size:1.6rem;">
            <i class="fas fa-user"></i>
        </div>
        <div class="flex-grow-1" style="min-width:0;">
            <div class="d-flex align-items-center gap-2 flex-wrap">
                <h4 class="mb-0 fw-bold text-break"><?= h($u['email']) ?></h4>
                <?php if ($adminView): ?>
                    <a class="text-decoration-none text-muted"
                       href="<?= $baseurl ?>/admin/users/quickEmail/<?= h($u['id']) ?>"
                       title="<?= __('Send email to user') ?>"
                       aria-label="<?= __('Send email to user') ?>">
                        <i class="fas fa-envelope"></i>
                    </a>
                <?php endif; ?>
            </div>
            <div class="d-flex align-items-center gap-2 mt-2 flex-wrap">
                <span class="text-muted small"><?= $this->OrgImg->getNameWithImg($data) ?></span>
                <?= $this->element('genericElementsBS5/IndexTable/Fields/role', [
                    'row' => $data,
                    'field' => ['data_path' => 'Role'],
                ]) ?>
            </div>
        </div>
        <?php if ($adminView): $disabled = !empty($u['disabled']); ?>
            <span class="badge rounded-pill <?= $disabled ? 'text-bg-danger' : 'text-bg-success' ?> flex-shrink-0 align-self-start">
                <i class="fas fa-<?= $disabled ? 'ban' : 'circle-check' ?> me-1"></i>
                <?= $disabled ? __('Disabled') : __('Active') ?>
            </span>
        <?php endif; ?>
    </div>

    <!-- INFO GRID -->
    <div class="card-body p-4">
        <div class="row g-4">
            <?= $item('hashtag', __('ID'), h($u['id'])) ?>

            <?php if (!empty($server['id'])): ?>
                <?= $item('server', __('Bound server'), $this->Html->link(
                    h($server['name']),
                    ['controller' => 'servers', 'action' => 'previewIndex', $server['id']]
                )) ?>
            <?php endif; ?>

            <?= $item('shield-halved', __('NIDS start SID'),
                ($u['nids_sid'] !== null && $u['nids_sid'] !== '')
                    ? h($u['nids_sid'])
                    : '<span class="text-muted">&mdash;</span>') ?>

            <?= $item('calendar-plus', __('Created'), $u['date_created']
                ? $this->Time->time($u['date_created'])
                : __('N/A')) ?>

            <?= $item('key', __('Last password change'), !empty($u['last_pw_change'])
                ? $this->Time->time($u['last_pw_change'])
                : __('N/A')) ?>

            <?php if ($adminView): ?>
                <?= $item('newspaper', __('News read at'), !empty($u['newsread'])
                    ? $this->Time->time($u['newsread'])
                    : __('N/A')) ?>
            <?php endif; ?>

            <?= $item('user-plus', __('Invited by'), (isset($invitedBy) && !empty($invitedBy['User']['email']))
                ? sprintf(
                    '<a href="%s/admin/users/view/%s">%s</a>',
                    $baseurl,
                    h($invitedBy['User']['id']),
                    h($invitedBy['User']['email'])
                )
                : '<span class="text-muted">' . __('N/A') . '</span>') ?>
        </div>
    </div>
</div>

<!-- SECURITY & ACCESS CARD -->
<div class="card mb-3 shadow-sm">
    <div class="card-header bg-light fw-bold">
        <i class="fas fa-shield-halved me-2 text-muted"></i><?= __('Security & access') ?>
    </div>
    <div class="card-body p-4">
        <div class="row g-0">

            <?php if (empty(Configure::read('Security.otp_disabled'))):
                $isTotp = isset($u['totp']); ?>
                <div class="col-md-6 mb-3">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('TOTP') ?></div>
                    <div class="d-flex align-items-center gap-3">
                        <?= $boolBadge($isTotp) ?>
                        <?php if (!$isTotp && !$adminView): ?>
                            <a href="#" class="small"
                               onclick="event.preventDefault(); openModal('<?= $baseurl ?>/users/totp_new', 'lg');">
                                <?= __('Generate') ?>
                            </a>
                        <?php endif; ?>
                        <?php if ($isTotp && !$adminView): ?>
                            <?= $this->Html->link(__('View paper tokens'), ['action' => 'hotp', $u['id']], ['class' => 'small']) ?>
                        <?php endif; ?>
                        <?php if (!empty($isAdmin) && $isTotp): ?>
                            <a href="#" class="small text-danger"
                               onclick="event.preventDefault(); openModal('<?= $baseurl ?>/users/totp_delete/<?= h($u['id']) ?>', 'sm');">
                                <?= __('Delete') ?>
                            </a>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>

            <div class="col-md-6 mb-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Contact alert enabled') ?></div>
                <?= $boolBadge($u['contactalert'] ?? false) ?>
            </div>

            <?php if ($adminView): ?>
                <div class="col-md-6 mb-3">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Terms accepted') ?></div>
                    <?= $boolBadge($u['termsaccepted'] ?? false) ?>
                </div>
                <div class="col-md-6 mb-3">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Must change password') ?></div>
                    <?= $boolBadge($u['change_pw'] ?? false) ?>
                </div>
                <div class="col-md-6 mb-3">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Disabled') ?></div>
                    <?= $boolBadge($u['disabled'] ?? false) ?>
                </div>
            <?php endif; ?>
        </div>

        <?php
            // Legacy inline auth key (only when advanced auth keys are disabled and the user has API perm).
            $showInlineAuthkey = empty(Configure::read('Security.advanced_authkeys'))
                && !empty($role['perm_auth'])
                && isset($u['authkey']);
        ?>
        <?php if ($showInlineAuthkey): ?>
            <hr>
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Auth key') ?></div>
            <div class="input-group input-group-sm mb-2" style="max-width:520px;">
                <input type="text" readonly
                       class="form-control font-monospace"
                       id="inline-authkey"
                       value="****************************************"
                       data-hidden-value="<?= h($u['authkey']) ?>">
                <button class="btn btn-outline-secondary" type="button"
                        title="<?= __('Reveal hidden value') ?>"
                        onclick="var i=document.getElementById('inline-authkey');
                                 var real=i.getAttribute('data-hidden-value');
                                 if(i.value===real){i.value='****************************************';}
                                 else{i.value=real;}">
                    <i class="fas fa-eye"></i>
                </button>
            </div>
            <?= $this->Form->postLink(__('Reset auth key'), ['action' => 'resetauthkey', $u['id']], [
                'class' => 'btn btn-sm btn-outline-warning',
            ]) ?>
        <?php elseif (!$adminView && empty($role['perm_auth'])): ?>
            <hr>
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Auth key') ?></div>
            <a class="btn btn-sm btn-outline-primary" href="#"
               onclick="event.preventDefault(); if (typeof requestAPIAccess === 'function') { requestAPIAccess(); }">
                <i class="fas fa-paper-plane me-1"></i><?= __('Request API access') ?>
            </a>
        <?php endif; ?>

        <?php if (Configure::read('Plugin.CustomAuth_enable') && !empty($u['external_auth_key'])):
            $header = Configure::read('Plugin.CustomAuth_header') ?: 'AUTHORIZATION'; ?>
            <hr>
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Customauth header') ?></div>
            <div><?= h($header) ?>: <span class="text-success fw-bold"><?= h($u['external_auth_key']) ?></span></div>
        <?php endif; ?>

        <?php if (!empty($u['gpgkey'])): ?>
            <hr>
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('PGP key') ?></div>
            <div class="mb-2"><?= $this->element('genericElements/key', ['key' => $u['gpgkey']]) ?></div>
            <div class="row g-0">
                <?= $field(__('PGP fingerprint'),
                    !empty($u['fingerprint'])
                        ? '<span class="font-monospace">' . h(chunk_split($u['fingerprint'], 4, ' ')) . '</span>'
                        : __('N/A'), 6) ?>
                <?php
                    $pgpOk = !empty($u['pgp_status']) && $u['pgp_status'] === 'OK';
                    $pgpStatusHtml = sprintf(
                        '<span class="%s">%s</span>',
                        $pgpOk ? 'text-success' : 'text-danger',
                        !empty($u['pgp_status']) ? h($u['pgp_status']) : __('N/A')
                    );
                ?>
                <?= $field(__('PGP key status'), $pgpStatusHtml, 6) ?>
            </div>
        <?php else: ?>
            <hr>
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('PGP key') ?></div>
            <?= $boolBadge(false) ?>
        <?php endif; ?>

        <?php if (Configure::read('SMIME.enabled')): ?>
            <hr>
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('S/MIME public certificate') ?></div>
            <div><?= $this->element('genericElements/key', ['key' => $u['certif_public'] ?? '']) ?></div>
        <?php endif; ?>

        <?php if ($adminView && !empty($u['orgAdmins'])): ?>
            <hr>
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Org admins') ?></div>
            <div class="d-flex flex-wrap gap-2">
                <?php foreach ($u['orgAdmins'] as $orgAdminId => $orgAdminEmail): ?>
                    <a class="badge text-bg-light border text-decoration-none"
                       href="<?= $baseurl ?>/admin/users/view/<?= h($orgAdminId) ?>">
                        <i class="fas fa-user-shield me-1"></i><?= h($orgAdminEmail) ?>
                    </a>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- NOTIFICATIONS CARD -->
<?php
$notificationTypes = [
    'autoalert'            => __('Event published notification'),
    'notification_daily'   => __('Daily notifications'),
    'notification_weekly'  => __('Weekly notifications'),
    'notification_monthly' => __('Monthly notifications'),
];
?>
<div class="card mb-3 shadow-sm">
    <div class="card-header bg-light fw-bold">
        <i class="fas fa-bell me-2 text-muted"></i><?= __('Email notifications') ?>
    </div>
    <div class="card-body p-0">
        <table class="table table-sm mb-0 align-middle">
            <tbody>
                <?php foreach ($notificationTypes as $key => $label): ?>
                    <tr>
                        <td class="ps-3"><?= h($label) ?></td>
                        <td class="text-end pe-3" style="width:80px;">
                            <?= $this->element('genericElementsBS5/Badges/boolean', [
                                'boolean' => !empty($u[$key]),
                                'full'    => false,
                                'true'    => __('Yes'),
                                'false'   => __('No'),
                            ]) ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
