<?php
/*
 * The user's identity card: the role, drawn large, over the fields that
 * describe the account.
 *
 * The disc is the only thing in the aside — name, email, organisation and
 * role all belong to the rows beside it, and repeating them twice on one card
 * is what the banner used to do. What the rows cannot say is which role this
 * is at a glance, so that is what the aside is for. RoleGlyph is the one table
 * that knows what a role looks like (icon, ink, tint at 12%), so the disc
 * here, the chip in the Role row and the badge in the users index cannot
 * drift apart.
 *
 * The two sit side by side, the aside on the left, and stack only when the
 * page is too narrow to hold them.
 *
 * The rows are the organisation view's table — label left, value right — and
 * each value is drawn by the IndexTable field element that already knows how
 * that kind of value looks, rather than by a local idea of it.
 */

$u         = $data['User'];
$role      = $data['Role'] ?? [];
$server    = $data['Server'] ?? [];
$org       = $data['Organisation'] ?? [];
$adminView = !empty($admin_view);

$glyph = $this->RoleGlyph->get($role);
$dash  = '<span class="text-muted">&mdash;</span>';

/* Date line under the page title, as every other view page sets it. */
$descParts = [];
if (!empty($u['date_created'])) {
    $descParts[] = '<span title="' . h(__('Created')) . '"><i class="fas fa-calendar-plus me-1 opacity-50"></i>'
        . $this->Time->time($u['date_created']) . '</span>';
}
if (!empty($u['date_modified'])) {
    $descParts[] = '<span title="' . h(__('Last modified')) . '"><i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($u['date_modified']) . '</span>';
}
$this->set(
    'headerDescription',
    '<span class="d-inline-flex align-items-center gap-3 flex-wrap">' . implode('', $descParts) . '</span>'
);

/*
 * Connection state. `current_login` is the timestamp of the latest sign-in
 * (`last_login` is the one before it — User::updateLoginTimes shifts them).
 *
 * "Online" is claimed for one case only: the account is the one being served
 * this page, which is the single moment we actually know it. MISP keeps no
 * presence flag, and a recent `current_login` is not one — a token that signed
 * in this morning and left says nothing about now, and a badge that guesses is
 * worse than a timestamp that is true.
 */
$isSelf       = !empty($me['id']) && (string)$me['id'] === (string)$u['id'];
$currentLogin = (int)($u['current_login'] ?? 0);

if ($isSelf) {
    $loginPill = sprintf(
        '<span class="badge rounded-pill text-bg-success d-inline-flex align-items-center gap-1">
            <i class="fas fa-circle fa-2xs"></i>%s
         </span>',
        __('Online now')
    );
} elseif ($currentLogin > 0) {
    $loginPill = sprintf(
        '<span class="badge rounded-pill text-bg-light border d-inline-flex align-items-center gap-1 fw-normal">
            <i class="fas fa-right-to-bracket text-muted"></i>
            <span class="text-muted">%s</span>%s
         </span>',
        __('Last login'),
        $this->Time->time($currentLogin)
    );
} else {
    $loginPill = sprintf(
        '<span class="badge rounded-pill text-bg-light border d-inline-flex align-items-center gap-1 fw-normal text-muted">
            <i class="fas fa-right-to-bracket"></i>%s
         </span>',
        __('Never signed in')
    );
}

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle  = 'width:1.75rem;height:1.75rem;';

/* One fact: a tile, the value, and what the value is. Same shape as the
   organisation view's tiles. */
$fact = function ($tileHtml, $valueHtml, $label, $muted = false) use ($tileStyle) {
    return '<div class="col"><div class="d-flex align-items-center gap-2 min-w-0' . ($muted ? ' opacity-75' : '') . '">'
        . '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary text-body-secondary overflow-hidden" style="' . $tileStyle . '">'
        . $tileHtml . '</span>'
        . '<div class="min-w-0"><div class="fw-semibold lh-sm text-truncate">' . $valueHtml . '</div>'
        . '<div class="small text-body-secondary text-truncate">' . h($label) . '</div></div></div></div>';
};
$notSet = '<span class="text-body-secondary fst-italic fw-normal">' . __('Not set') . '</span>';

$facts = [];
$facts[] = $fact(
    (!empty($org) ? $this->OrgImg->getOrgLogoV2($org, 20, false) : '') ?: '<i class="fas fa-building"></i>',
    empty($org['id'])
        ? $notSet
        : '<a class="text-decoration-none" href="' . h($baseurl . '/organisations/view/' . $org['id']) . '">' . h($org['name'] ?? '') . '</a>',
    __('Organisation')
);
$facts[] = '<div class="col"><div class="d-flex align-items-center gap-2 min-w-0">'
    . '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3" style="' . $tileStyle
    . 'background:' . h($glyph['tint']) . ';color:' . h($glyph['colour']) . ';"><i class="' . h($glyph['icon']) . '"></i></span>'
    . '<div class="min-w-0"><div class="fw-semibold lh-sm text-truncate">'
    . (empty($role['id'])
        ? h($role['name'] ?? __('No role'))
        : '<a class="text-decoration-none" href="' . h($baseurl . '/roles/view/' . $role['id']) . '">' . h($role['name'] ?? '') . '</a>')
    . '</div><div class="small text-body-secondary">' . h(__('Role')) . '</div></div></div></div>';
$facts[] = $fact(
    '<i class="fas fa-terminal"></i>',
    empty($u['last_api_access']) ? '<span class="text-body-secondary fw-normal">' . __('Never') . '</span>' : $this->Time->time($u['last_api_access']),
    __('Last API access'),
    empty($u['last_api_access'])
);

$more = [];
$more[] = $fact(
    '<i class="fas fa-hashtag"></i>',
    (isset($u['nids_sid']) && $u['nids_sid'] !== '') ? '<span class="font-monospace">' . h($u['nids_sid']) . '</span>' : $notSet,
    __('NIDS start SID')
);
$more[] = $fact(
    '<i class="fas fa-user-plus"></i>',
    !empty($invitedBy['User']['email'])
        ? '<a class="text-decoration-none" href="' . h($baseurl . '/admin/users/view/' . $invitedBy['User']['id']) . '" title="' . h($invitedBy['User']['email']) . '">'
            . h($invitedBy['User']['email']) . '</a>'
        : '<span class="text-body-secondary fw-normal">' . __('Nobody') . '</span>',
    __('Invited by'),
    empty($invitedBy['User']['email'])
);
if (!empty($server['id'])) {
    $more[] = $fact(
        '<i class="fas fa-server"></i>',
        '<a class="text-decoration-none" href="' . h($baseurl . '/servers/previewIndex/' . $server['id']) . '">' . h($server['name']) . '</a>',
        __('Bound server')
    );
} elseif ($adminView) {
    $more[] = $fact(
        '<i class="fas fa-newspaper"></i>',
        empty($u['newsread']) ? '<span class="text-body-secondary fw-normal">' . __('Never') . '</span>' : $this->Time->time($u['newsread']),
        __('News read at'),
        empty($u['newsread'])
    );
}
?>

<!-- ══ IDENTITY ════════════════════════════════════════════════════════ -->
<div class="card shadow-sm mb-3 overflow-hidden">
    <div class="row g-0">

        <!-- ASIDE — the role, and nothing else -->
        <div class="col-12 col-md-4 col-xl-3 ov-identity-aside p-3 d-flex flex-column gap-3"
             style="background:linear-gradient(180deg, <?= h($glyph['tint']) ?> 0%, transparent 90%);">

            <div class="align-self-start"><?= $loginPill ?></div>

            <div class="d-flex justify-content-center align-items-center flex-grow-1 pb-2">
                <div class="rounded-circle d-flex align-items-center justify-content-center"
                     style="width:110px; height:110px;
                            background:<?= h($glyph['tint']) ?>;
                            border:2px solid <?= h($glyph['colour']) ?>33;
                            color:<?= h($glyph['colour']) ?>;"
                     title="<?= h($role['name'] ?? __('No role')) ?>">
                    <i class="<?= h($glyph['icon']) ?> fa-3x"></i>
                </div>
            </div>
        </div>

        <div class="col">
            <div class="p-3 d-flex flex-column gap-3 h-100">

                <div>
                    <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                        <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                            <i class="fas fa-user text-primary me-1"></i><?= __('User') ?>
                        </span>
                        <?php if ($adminView): ?>
                            <span class="badge rounded-pill fw-normal <?= empty($u['disabled']) ? 'text-bg-success' : 'text-bg-danger' ?>">
                                <i class="fas <?= empty($u['disabled']) ? 'fa-circle-check' : 'fa-user-slash' ?> me-1"></i>
                                <?= empty($u['disabled']) ? __('Active') : __('Disabled') ?>
                            </span>
                        <?php endif; ?>
                    </div>
                    <div class="d-flex align-items-center gap-2 flex-wrap">
                        <span class="fs-5 fw-semibold text-break"><?= h($u['email']) ?></span>
                        <button type="button" class="btn btn-sm btn-link text-body-secondary p-0"
                                data-copy-value="<?= h($u['email']) ?>"
                                data-copy-msg="<?= h(__('Email address copied to clipboard')) ?>"
                                title="<?= h(__('Copy email address')) ?>" aria-label="<?= h(__('Copy email address')) ?>"
                                onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">
                            <i class="fas fa-copy"></i>
                        </button>
                        <?php if ($adminView): ?>
                            <a class="btn btn-sm btn-link text-body-secondary p-0"
                               href="<?= h($baseurl . '/admin/users/quickEmail/' . $u['id']) ?>"
                               onclick="event.preventDefault(); openModal('<?= h($baseurl . '/admin/users/quickEmail/' . $u['id']) ?>');"
                               title="<?= h(__('Send email to user')) ?>" aria-label="<?= h(__('Send email to user')) ?>">
                                <i class="fas fa-paper-plane"></i>
                            </a>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="row row-cols-1 row-cols-sm-3 g-2"><?= implode('', $facts) ?></div>
                <div class="row row-cols-1 row-cols-sm-3 g-2"><?= implode('', $more) ?></div>

            </div>
        </div>

    </div>
</div>

<?php
/* ══ SECURITY & ACCESS + EMAIL NOTIFICATIONS ═══════════════════════════════
 *
 * Both cards state each setting as a tile: a glyph tinted by the state, what
 * the state is, and one line on what it means for the account. Actions sit
 * under the tile they act on.
 */
$isTotp         = isset($u['totp']);
$otpOn          = empty(Configure::read('Security.otp_disabled'));
$advancedKeys   = !empty(Configure::read('Security.advanced_authkeys'));
$showInlineKey  = !$advancedKeys && !empty($role['perm_auth']) && isset($u['authkey']);
$canRequestApi  = !$adminView && empty($role['perm_auth']);
$customAuthOn   = (bool)Configure::read('Plugin.CustomAuth_enable');
$customAuthName = Configure::read('Plugin.CustomAuth_name') ?: __('External authentication');
$smimeOn        = (bool)Configure::read('SMIME.enabled');
$hasOrgAdmins   = $adminView && !empty($u['orgAdmins']);
$pgpOk          = !empty($u['pgp_status']) && $u['pgp_status'] === 'OK';

/* A state tile. $tone colours the glyph; null greys the whole tile out. */
$tile = function ($icon, $tone, $title, $sub, $actionsHtml = '') use ($tileStyle) {
    $tileClass = $tone === null
        ? 'bg-body-secondary text-body-secondary'
        : 'bg-' . $tone . '-subtle text-' . $tone . '-emphasis';
    return '<div class="col"><div class="d-flex align-items-start gap-2 min-w-0 h-100' . ($tone === null ? ' opacity-75' : '') . '">'
        . '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 ' . $tileClass . '" style="' . $tileStyle . '">'
        . '<i class="' . h($icon) . '"></i></span>'
        . '<div class="min-w-0 flex-grow-1"><div class="fw-semibold lh-sm">' . $title . '</div>'
        . '<div class="small text-body-secondary">' . $sub . '</div>'
        . ($actionsHtml !== '' ? '<div class="d-flex flex-wrap gap-1 mt-1">' . $actionsHtml . '</div>' : '')
        . '</div></div></div>';
};
$actionButton = function ($label, $icon, $onclick, $variant = 'outline-secondary', $title = null) {
    return '<button type="button" class="btn btn-sm btn-' . $variant . ' py-0 px-2" onclick="' . h($onclick) . '"'
        . ($title ? ' title="' . h($title) . '" aria-label="' . h($title) . '"' : '') . '>'
        . '<i class="' . h($icon) . ($label !== '' ? ' me-1' : '') . '"></i>' . h($label) . '</button>';
};
$section = function ($label) use ($labelClass, $labelStyle) {
    return '<div class="' . $labelClass . ' mb-2" style="' . $labelStyle . '">' . h($label) . '</div>';
};
$keyBlock = function ($key, $copyMessage) {
    return '<details class="mt-1"><summary class="small text-body-secondary">' . h(__('Show key')) . '</summary>'
        . '<div class="position-relative mt-1">'
        . '<button type="button" class="btn btn-sm btn-light border position-absolute top-0 end-0 m-1"'
        . ' title="' . h(__('Copy to clipboard')) . '" aria-label="' . h(__('Copy to clipboard')) . '"'
        . ' data-copy-msg="' . h($copyMessage) . '"'
        . ' onclick="copyValueToClipboard(this.nextElementSibling.textContent, this.dataset.copyMsg)">'
        . '<i class="fas fa-copy opacity-100 text-dark"></i></button>'
        . '<pre class="border rounded-3 bg-body-tertiary small p-3 pe-5 mb-0 overflow-auto" style="max-height:14rem;">' . h($key) . '</pre>'
        . '</div></details>';
};
?>

<!-- ══ SECURITY & ACCESS ═══════════════════════════════════════════════ -->
<div class="card shadow-sm mb-3">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary flex-shrink-0" style="width:36px;height:36px;">
                <i class="fas fa-shield-halved"></i>
            </div>
            <div>
                <div class="fw-bold lh-1"><?= __('Security & access') ?></div>
                <div class="small text-muted mt-1"><?= __('How this account signs in and reaches the API') ?></div>
            </div>
        </div>
    </div>
    <div class="card-body py-3 d-flex flex-column gap-4">

        <!-- SIGN-IN -->
        <div>
            <?= $section(__('Sign-in')) ?>
            <div class="row row-cols-1 row-cols-md-2 row-cols-xxl-3 g-3">
                <?php
                $passwordSub = empty($u['last_pw_change'])
                    ? h(__('Never changed'))
                    : h(__('Changed')) . ' ' . $this->Time->time($u['last_pw_change']);
                $mustChange = $adminView && !empty($u['change_pw']);
                if ($mustChange) {
                    $passwordSub .= '<br><span class="text-warning-emphasis"><i class="fas fa-rotate me-1"></i>' . h(__('Must be changed at the next sign-in')) . '</span>';
                }
                echo $tile('fas fa-key', $mustChange ? 'warning' : 'primary', h(__('Password')), $passwordSub);

                if ($otpOn) {
                    $totpActions = '';
                    if (!$isTotp && !$adminView) {
                        $totpActions .= $actionButton(__('Set up'), 'fas fa-qrcode', "openModal('" . $baseurl . "/users/totp_new', 'lg')", 'outline-primary');
                    }
                    if ($isTotp && !$adminView) {
                        $totpActions .= '<a class="btn btn-sm btn-outline-secondary py-0 px-2" href="' . h($baseurl . '/users/hotp/' . $u['id']) . '">'
                            . '<i class="fas fa-list-ol me-1"></i>' . h(__('Paper tokens')) . '</a>';
                    }
                    if (!empty($isAdmin) && $isTotp) {
                        $totpActions .= $actionButton(__('Remove'), 'fas fa-trash', "openModal('" . $baseurl . "/users/totp_delete/" . (int)$u['id'] . "', 'md')", 'outline-danger');
                    }
                    echo $tile(
                        'fas fa-mobile-screen',
                        $isTotp ? 'success' : 'warning',
                        h($isTotp ? __('Two-factor enabled') : __('No two-factor')),
                        h($isTotp ? __('A TOTP token is enrolled') : __('Signing in takes the password alone')),
                        $totpActions
                    );
                }

                if ($customAuthOn) {
                    $external = !empty($u['external_auth_required']);
                    $externalSub = $external
                        ? h(__('No MISP password is used'))
                        : h(__('Uses a MISP password'));
                    if ($external && !empty($u['external_auth_key'])) {
                        $externalSub .= '<br><span class="font-monospace text-body-emphasis text-break">'
                            . h(Configure::read('Plugin.CustomAuth_header') ?: 'AUTHORIZATION') . ': ' . h($u['external_auth_key']) . '</span>';
                    }
                    echo $tile('fas fa-id-badge', $external ? 'info' : null,
                        h($external ? __('Signs in through %s', $customAuthName) : __('Not through %s', $customAuthName)),
                        $externalSub);
                }
                ?>
            </div>
        </div>

        <!-- API ACCESS -->
        <div>
            <?= $section(__('API access')) ?>
            <?php if ($showInlineKey): ?>
                <div class="d-flex align-items-center gap-2 flex-wrap">
                    <div class="d-flex align-items-stretch border rounded-pill bg-body-tertiary font-monospace overflow-hidden lh-base mw-100">
                        <span class="d-inline-flex align-items-center px-2 small text-truncate"
                              data-authkey-value data-mask="<?= h(str_repeat('•', 24)) ?>" data-secret="<?= h($u['authkey']) ?>"><?= h(str_repeat('•', 24)) ?></span>
                        <span class="vr my-1"></span>
                        <button type="button" class="btn btn-sm btn-link text-body-secondary px-2 py-0"
                                title="<?= h(__('Reveal hidden value')) ?>" aria-label="<?= h(__('Reveal hidden value')) ?>"
                                onclick="var v=this.parentNode.querySelector('[data-authkey-value]');v.textContent=(v.textContent===v.dataset.secret)?v.dataset.mask:v.dataset.secret;">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button type="button" class="btn btn-sm btn-link text-body-secondary px-2 py-0"
                                title="<?= h(__('Copy to clipboard')) ?>" aria-label="<?= h(__('Copy to clipboard')) ?>"
                                data-copy-msg="<?= h(__('Auth key copied to clipboard')) ?>"
                                onclick="copyValueToClipboard(this.parentNode.querySelector('[data-authkey-value]').dataset.secret, this.dataset.copyMsg)">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                    <?= $this->Form->postLink(
                        '<i class="fas fa-rotate me-1"></i>' . __('Reset'),
                        ['action' => 'resetauthkey', $u['id']],
                        ['class' => 'btn btn-sm btn-outline-warning py-0 px-2', 'escape' => false, 'title' => __('Reset auth key')]
                    ) ?>
                </div>
                <div class="small text-body-secondary mt-1"><?= __('A reset takes effect at once and invalidates the current key.') ?></div>
            <?php elseif ($canRequestApi): ?>
                <div class="row row-cols-1 g-3">
                    <?= $tile('fas fa-key', null, h(__('No API access')),
                        h(__('This account has no API permission yet.')),
                        '<button type="button" class="btn btn-sm btn-outline-primary py-0 px-2" data-request-api>'
                            . '<i class="fas fa-paper-plane me-1"></i>' . h(__('Ask an admin for access')) . '</button>') ?>
                </div>
            <?php else: ?>
                <div class="row row-cols-1 g-3">
                    <?php
                    $apiAllowed = !empty($role['perm_auth']);
                    $apiActions = ($apiAllowed && $advancedKeys)
                        ? '<a href="#tab-authkeys" class="btn btn-sm btn-outline-primary py-0 px-2" data-user-tab="authkeys">'
                            . '<i class="fas fa-key me-1"></i>' . h(__('Manage auth keys')) . '</a>'
                        : '';
                    echo $tile('fas fa-key', $apiAllowed ? 'success' : null,
                        h($apiAllowed ? __('API access allowed') : __('No API access')),
                        h($apiAllowed
                            ? ($advancedKeys ? __('Through the auth keys of this account') : __('This account holds no inline auth key'))
                            : __('Its role does not grant auth keys')),
                        $apiActions);
                    ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- ENCRYPTION KEYS -->
        <div>
            <?= $section(__('Encryption keys')) ?>
            <div class="row row-cols-1 row-cols-md-2 g-3">
                <?php
                if (empty($u['gpgkey'])) {
                    echo $tile('fas fa-lock', null, h(__('No PGP key')), h(__('Encrypted notifications need one')));
                } else {
                    $fingerprint = (!empty($u['fingerprint']) && $u['fingerprint'] !== 'N/A')
                        ? '<span class="font-monospace text-break">' . h(trim(chunk_split($u['fingerprint'], 4, ' '))) . '</span>'
                        : h(__('No fingerprint reported'));
                    echo $tile('fas fa-lock', $pgpOk ? 'success' : 'danger',
                        h(__('PGP key')) . ' <span class="badge rounded-pill fw-normal ms-1 ' . ($pgpOk ? 'text-bg-success' : 'text-bg-danger') . '">' . h($u['pgp_status'] ?? __('N/A')) . '</span>',
                        $fingerprint . $keyBlock($u['gpgkey'], __('Key copied to clipboard')));
                }
                if ($smimeOn) {
                    echo empty($u['certif_public'])
                        ? $tile('fas fa-certificate', null, h(__('No S/MIME certificate')), h(__('PEM format')))
                        : $tile('fas fa-certificate', 'success', h(__('S/MIME certificate')), h(__('PEM format')) . $keyBlock($u['certif_public'], __('Certificate copied to clipboard')));
                }
                ?>
            </div>
        </div>

        <!-- ACCOUNT -->
        <div>
            <?= $section(__('Account')) ?>
            <div class="row row-cols-1 row-cols-md-2 g-3">
                <?php
                $contact = !empty($u['contactalert']);
                echo $tile('fas fa-comment-dots', $contact ? 'primary' : null,
                    h($contact ? __('Receives contact requests') : __('No contact requests')),
                    h(__('Emails sent through "Contact reporter"')));
                if ($adminView) {
                    $terms = !empty($u['termsaccepted']);
                    echo $tile('fas fa-file-signature', $terms ? 'success' : 'warning',
                        h($terms ? __('Terms accepted') : __('Terms not accepted')),
                        h(__('Instance terms of use')));
                }
                ?>
            </div>
            <?php if ($hasOrgAdmins): ?>
                <div class="d-flex flex-wrap align-items-center gap-1 mt-3">
                    <span class="small text-body-secondary me-1"><i class="fas fa-user-shield me-1 opacity-50"></i><?= __('Organisation admins') ?></span>
                    <?php foreach ($u['orgAdmins'] as $orgAdminId => $orgAdminEmail): ?>
                        <a class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal text-decoration-none"
                           href="<?= h($baseurl . '/admin/users/view/' . $orgAdminId) ?>"><?= h($orgAdminEmail) ?></a>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

    </div>
</div>

<!-- ══ EMAIL NOTIFICATIONS ═════════════════════════════════════════════ -->
<?php
$notificationMeta = [
    'autoalert' => ['fas fa-bullhorn', __('Event published'), __('One email per published event it can see')],
    'notification_daily' => ['fas fa-calendar-day', __('Daily digest'), __('Once a day')],
    'notification_weekly' => ['fas fa-calendar-week', __('Weekly digest'), __('Once a week')],
    'notification_monthly' => ['fas fa-calendar-days', __('Monthly digest'), __('Once a month')],
];
$notificationKeys = array_merge(
    ['autoalert'],
    $periodic_notifications ?? ['notification_daily', 'notification_weekly', 'notification_monthly']
);
$notificationsOn = 0;
foreach ($notificationKeys as $notificationKey) {
    if (!empty($u[$notificationKey])) {
        $notificationsOn++;
    }
}
?>
<div class="card shadow-sm mb-3">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary flex-shrink-0" style="width:36px;height:36px;">
                <i class="fas fa-bell"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Email notifications') ?></div>
                <div class="small text-muted mt-1">
                    <?= $notificationsOn === 0
                        ? __('No email is sent to this account')
                        : h(__('%s of %s enabled', $notificationsOn, count($notificationKeys))) ?>
                </div>
            </div>
        </div>
    </div>
    <div class="card-body py-3">
        <div class="row row-cols-1 row-cols-sm-2 row-cols-xl-4 g-3">
            <?php foreach ($notificationKeys as $notificationKey): ?>
                <?php
                $meta = $notificationMeta[$notificationKey] ?? ['fas fa-envelope', Inflector::humanize($notificationKey), ''];
                $on = !empty($u[$notificationKey]);
                ?>
                <?= $tile($meta[0], $on ? 'primary' : null,
                    h($meta[1]) . ' <span class="badge rounded-pill fw-normal ms-1 ' . ($on ? 'text-bg-primary' : 'border bg-body text-body-secondary') . '">' . h($on ? __('On') : __('Off')) . '</span>',
                    h($meta[2])) ?>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<script>
(function () {
    document.querySelectorAll('[data-user-tab]:not([data-user-tab-bound])').forEach(function (link) {
        link.setAttribute('data-user-tab-bound', '');
        link.addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-' + link.dataset.userTab + '"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    });
    /* users/request_API answers JSON and takes the CSRF token as a header. */
    document.querySelectorAll('[data-request-api]:not([data-request-api-bound])').forEach(function (button) {
        button.setAttribute('data-request-api-bound', '');
        button.addEventListener('click', function () {
            button.disabled = true;
            fetch(<?= json_encode($baseurl . '/users/request_API') ?>, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': window.csrfToken || ''}
            })
                .then(function (response) { return response.json(); })
                .then(function (result) {
                    var ok = result && result.saved;
                    if (typeof showToast === 'function') {
                        showToast(ok ? result.success : (result.errors || <?= json_encode(__('Could not request API access.')) ?>), ok ? 'success' : 'danger');
                    }
                    button.disabled = ok;
                })
                .catch(function () {
                    if (typeof showToast === 'function') {
                        showToast(<?= json_encode(__('Could not request API access.')) ?>, 'danger');
                    }
                    button.disabled = false;
                });
        });
    });
})();
</script>
