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
$descParts = [
    '<span><i class="fas fa-calendar-day me-1 opacity-50"></i>'
        . (empty($u['date_created']) ? __('N/A') : h($u['date_created']))
        . '</span>',
];
if (!empty($u['date_modified'])) {
    $descParts[] = '<span><i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($u['date_modified'])
        . '</span>';
}
$this->set(
    'headerDescription',
    '<span class="d-inline-flex gap-3 flex-wrap">' . implode('', $descParts) . '</span>'
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

/* A value drawn by the field element that owns that kind of value. */
$fieldCell = function ($element, array $field, array $extra = []) use ($data) {
    return $this->element(
        'genericElementsBS5/IndexTable/Fields/' . $element,
        ['row' => $data, 'field' => $field] + $extra
    );
};

/* The org view's own shape for a date: glyph, then the time, right-aligned. */
$timeCell = function ($value, $icon) use ($dash) {
    if (empty($value)) {
        return $dash;
    }
    return '<span class="d-inline-flex align-items-center gap-2 justify-content-end text-nowrap">'
        . '<i class="fas fa-' . h($icon) . ' text-muted"></i>'
        . $this->Time->time($value)
        . '</span>';
};

$rows = [];

$emailCell = '<span class="d-inline-flex align-items-center gap-2 justify-content-end flex-wrap">'
    . '<span class="text-break">' . h($u['email']) . '</span>'
    . '<button type="button" class="text-muted border-0 bg-transparent p-0"'
    . ' data-copy-value="' . h($u['email']) . '"'
    . ' data-copy-msg="' . h(__('Email address copied to clipboard')) . '"'
    . ' title="' . h(__('Copy email address')) . '"'
    . ' aria-label="' . h(__('Copy email address')) . '"'
    . ' onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">'
    . '<i class="fas fa-copy fa-xs"></i></button>';
if ($adminView) {
    $emailCell .= sprintf(
        '<a class="text-muted" href="%s/admin/users/quickEmail/%s"'
        . ' onclick="event.preventDefault(); openModal(\'%s/admin/users/quickEmail/%s\');"'
        . ' title="%s" aria-label="%s"><i class="fas fa-paper-plane fa-xs"></i></a>',
        h($baseurl),
        h($u['id']),
        h($baseurl),
        h($u['id']),
        h(__('Send email to user')),
        h(__('Send email to user'))
    );
}
$emailCell .= '</span>';
$rows[] = ['label' => __('Email'), 'html' => $emailCell];

$rows[] = [
    'label' => __('Organisation'),
    'html'  => empty($org)
        ? $dash
        : '<div class="d-flex justify-content-end">'
            . $fieldCell('organisation', ['data_path' => 'Organisation'], ['data_path' => 'Organisation'])
            . '</div>',
];

$rows[] = [
    'label' => __('Role'),
    'html'  => empty($role['name'])
        ? $dash
        : '<div class="d-flex justify-content-end">'
            . $fieldCell('role', ['data_path' => 'Role'])
            . '</div>',
];

if ($adminView) {
    $rows[] = [
        'label' => __('Status'),
        'html'  => $fieldCell('user_status', ['data_path' => 'User.disabled']),
    ];
}

$rows[] = [
    'label' => __('ID'),
    'html'  => (isset($u['id']) && $u['id'] !== '')
        ? '<span class="bg-light border rounded px-2 py-1 fw-semibold small font-monospace">#'
            . h($u['id']) . '</span>'
        : $dash,
];

$rows[] = [
    'label' => __('NIDS start SID'),
    'html'  => (isset($u['nids_sid']) && $u['nids_sid'] !== '')
        ? '<span class="font-monospace small">' . h($u['nids_sid']) . '</span>'
        : $dash,
];

if (!empty($server['id'])) {
    $rows[] = [
        'label' => __('Bound server'),
        'html'  => sprintf(
            '<a class="text-decoration-none fw-semibold" href="%s/servers/previewIndex/%s">'
            . '<i class="fas fa-server text-muted me-2"></i>%s</a>',
            h($baseurl),
            h($server['id']),
            h($server['name'])
        ),
    ];
}

$rows[] = [
    'label' => __('Last password change'),
    'html'  => $timeCell($u['last_pw_change'] ?? null, 'key'),
];

$rows[] = [
    'label' => __('Last API access'),
    'html'  => $timeCell($u['last_api_access'] ?? null, 'terminal'),
];

if ($adminView) {
    $rows[] = [
        'label' => __('News read at'),
        'html'  => $timeCell($u['newsread'] ?? null, 'newspaper'),
    ];
}

$rows[] = [
    'label' => __('Invited by'),
    'html'  => !empty($invitedBy['User']['email'])
        ? sprintf(
            '<a class="text-decoration-none fw-semibold" href="%s/admin/users/view/%s">'
            . '<i class="fas fa-user-plus text-muted me-2"></i>%s</a>',
            h($baseurl),
            h($invitedBy['User']['id']),
            h($invitedBy['User']['email'])
        )
        : $dash,
];
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

        <!-- FIELDS -->
        <div class="col">
            <table class="table align-middle mb-0">
                <tbody>
                    <?php foreach ($rows as $row): ?>
                        <tr>
                            <th scope="row" class="text-dark fw-semibold p-3 text-nowrap w-25">
                                <?= h($row['label']) ?>
                            </th>
                            <td class="text-end pe-3">
                                <?= $row['html'] ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

    </div>
</div>

<?php
/* ══ SECURITY & ACCESS + EMAIL NOTIFICATIONS ═══════════════════════════════
 *
 * Both cards wear the event view's card chrome — a `p-3 border-bottom` strip
 * with a 36px tinted square, a title, a line of context and the action that
 * edits what the card shows — and state their contents in the read-only twin
 * of the switch tile admin_edit/admin_add are built from, so the screen that
 * reports these settings and the form that sets them read as one thing.
 */

$accent  = $this->ModalAccent->get('primary');
$editUrl = $adminView
    ? $baseurl . '/admin/users/edit/' . h($u['id'])
    : $baseurl . '/users/edit';

$cardHead = function ($icon, $title, $subtitle) {
    return sprintf(
        '<div class="p-3 border-bottom">
            <div class="d-flex align-items-center gap-2">
                <div class="rounded-2 d-flex align-items-center justify-content-center flex-shrink-0 p-2 bg-primary-subtle text-primary">
                    <i class="%s fa-fw"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1">%s</div>
                    <div class="small text-muted mt-1">%s</div>
                </div>
            </div>
        </div>',
        h($icon),
        h($title),
        h($subtitle)
    );
};

/* The read-only twin of $switchTile in admin_edit.ctp: same border, same
   metrics, same glyph / label / note column — only the switch on the right
   becomes a badge or a button, since nothing here is settable. The two are
   deliberately identical so the view does not look like a different product
   from the form; change one and change the other. */
$stateTile = function ($icon, $label, $rightHtml, array $opts = []) {
    $tileAccent = $this->ModalAccent->get($opts['accent'] ?? 'primary');
    return sprintf(
        '<div class="%s">
            <div class="d-flex align-items-center justify-content-between gap-3 h-100 w-100 border rounded-3 px-3 py-2 bg-light">
                <span class="d-flex align-items-center gap-2 overflow-hidden">
                    <i class="%s %s flex-shrink-0 fa-fw fa-sm" style="%s"></i>
                    <span class="small lh-sm overflow-hidden">
                        <span class="fw-semibold d-block">%s</span>%s
                    </span>
                </span>
                <span class="d-flex align-items-center gap-2 flex-shrink-0">%s</span>
            </div>
        </div>',
        h($opts['col'] ?? 'col-md-6'),
        h($icon),
        h($tileAccent['textClass']),
        $tileAccent['textStyle'],
        h($label),
        empty($opts['note'])
            ? ''
            : '<small class="text-muted d-block">' . h($opts['note']) . '</small>',
        $rightHtml
    );
};

/* The badge that stands where the tile's switch would be. A span, not the
   shared Badges/boolean element — that one wraps itself in a <div>, which
   cannot sit inside the tile's inline right-hand slot. */
$statePill = function ($on, $onLabel = null, $offLabel = null, $onColor = 'success') {
    return sprintf(
        '<span class="badge rounded-pill text-bg-%s"><i class="fas %s me-1"></i>%s</span>',
        $on ? $onColor : 'secondary',
        $on ? 'fa-check' : 'fa-xmark',
        h($on ? ($onLabel ?? __('On')) : ($offLabel ?? __('Off')))
    );
};

/* A full-width bordered block for what is not a single state: a key, a list. */
$panel = function ($bodyHtml, $class = '') {
    return sprintf(
        '<div class="border rounded-3 px-3 py-2 %s">%s</div>',
        h($class),
        $bodyHtml
    );
};

/* A long key, folded away behind its own summary and copyable in one click.
   The button reads the text out of the <pre> rather than carrying it in an
   attribute — a PGP block has newlines, and no attribute survives those — and
   its toast wording out of a data attribute rather than a JS string literal,
   which an apostrophe in a translation would cut in half. */
$keyBlock = function ($key) {
    if (empty($key)) {
        return '<span class="text-muted small">' . __('None') . '</span>';
    }
    return sprintf(
        '<details class="ov-key mt-2">
            <summary class="small text-body-secondary">%s</summary>
            <div class="position-relative mt-2">
                <button type="button"
                        class="btn btn-sm btn-light border position-absolute top-0 end-0 m-1"
                        title="%s"
                        data-copy-msg="%s"
                        onclick="copyValueToClipboard(this.nextElementSibling.textContent, this.dataset.copyMsg)">
                    <i class="fas fa-copy"></i>
                </button>
                <pre class="border rounded-3 bg-body-tertiary small p-3 mb-0 ov-key-body">%s</pre>
            </div>
        </details>',
        __('Show key'),
        h(__('Copy to clipboard')),
        h(__('Key copied to clipboard')),
        h($key)
    );
};

$isTotp          = isset($u['totp']);
$otpOn           = empty(Configure::read('Security.otp_disabled'));
$advancedKeys    = !empty(Configure::read('Security.advanced_authkeys'));
$showInlineKey   = !$advancedKeys && !empty($role['perm_auth']) && isset($u['authkey']);
$canRequestApi   = !$adminView && empty($role['perm_auth']);
$customAuthOn    = (bool)Configure::read('Plugin.CustomAuth_enable');
$customAuthName  = Configure::read('Plugin.CustomAuth_name') ?: __('External authentication');
$smimeOn         = (bool)Configure::read('SMIME.enabled');
$hasOrgAdmins    = $adminView && !empty($u['orgAdmins']);
$pgpOk           = !empty($u['pgp_status']) && $u['pgp_status'] === 'OK';
?>

<!-- ══ SECURITY & ACCESS ═══════════════════════════════════════════════ -->
<div class="card shadow-sm mb-3">

    <?= $cardHead(
        'fas fa-shield-halved',
        __('Security & access'),
        __('How this account signs in and what it may reach')
    ) ?>

    <div class="card-body p-3">
        <div class="d-flex flex-column gap-4">

            <!-- ── AUTHENTICATION ──────────────────────────────── -->
            <div>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Authentication'),
                ]) ?>
                <div class="row g-2">

                    <?php if ($otpOn): ?>
                        <?php
                        $totpRight = $statePill($isTotp, __('Enrolled'), __('Not set'));
                        if (!$isTotp && !$adminView) {
                            $totpRight .= sprintf(
                                '<button type="button" class="btn btn-sm btn-outline-primary"
                                         onclick="openModal(\'%s/users/totp_new\', \'lg\')">%s</button>',
                                h($baseurl),
                                __('Generate')
                            );
                        }
                        if ($isTotp && !$adminView) {
                            $totpRight .= sprintf(
                                '<a class="btn btn-sm btn-outline-secondary" href="%s/users/hotp/%s">%s</a>',
                                h($baseurl),
                                h($u['id']),
                                __('Paper tokens')
                            );
                        }
                        if (!empty($isAdmin) && $isTotp) {
                            $totpRight .= sprintf(
                                '<button type="button" class="btn btn-sm btn-outline-danger"
                                         title="%s" aria-label="%s"
                                         onclick="openModal(\'%s/users/totp_delete/%s\', \'md\')">
                                    <i class="fas fa-trash"></i>
                                 </button>',
                                h(__('Remove token')),
                                h(__('Remove token')),
                                h($baseurl),
                                h($u['id'])
                            );
                        }
                        ?>
                        <?= $stateTile('fas fa-mobile-screen', __('Two-factor authentication'), $totpRight, [
                            'accent' => 'warning',
                            'col' => 'col-12',
                            'note' => $isTotp
                                ? __('A TOTP token is enrolled on this account.')
                                : __('No TOTP token enrolled — sign-in relies on the password alone.'),
                        ]) ?>
                    <?php endif; ?>

                    <?= $stateTile('fas fa-key', __('Password'),
                        '<span class="small text-muted">' . (
                            empty($u['last_pw_change'])
                                ? __('Never changed')
                                : $this->Time->time($u['last_pw_change'])
                        ) . '</span>',
                        [
                            'col' => 'col-md-6',
                            'note' => __('Last changed'),
                        ]) ?>

                    <?php if ($adminView): ?>
                        <?= $stateTile('fas fa-rotate', __('Must change password'),
                            $statePill(!empty($u['change_pw']), __('Yes'), __('No'), 'warning'),
                            [
                                'col' => 'col-md-6',
                                'note' => __('Asked for a new password on the next sign-in.'),
                            ]) ?>
                    <?php endif; ?>

                    <?php if ($customAuthOn): ?>
                        <?= $stateTile('fas fa-id-badge', __('%s user', $customAuthName),
                            $statePill(!empty($u['external_auth_required']), __('Yes'), __('No')),
                            [
                                'col' => 'col-12',
                                'note' => __('The account signs in through %s instead of a MISP password.', $customAuthName),
                            ]) ?>
                        <?php if (!empty($u['external_auth_key'])): ?>
                            <div class="col-12">
                                <?= $panel(sprintf(
                                    '<div class="d-flex align-items-center gap-2 flex-wrap small">
                                        <span class="text-muted text-uppercase fw-bold">%s</span>
                                        <span class="font-monospace">%s</span>
                                        <span class="font-monospace text-success fw-bold text-break">%s</span>
                                     </div>',
                                    h(__('Custom auth header')),
                                    h(Configure::read('Plugin.CustomAuth_header') ?: 'AUTHORIZATION'),
                                    h($u['external_auth_key'])
                                )) ?>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>

                </div>
            </div>

            <!-- ── API ACCESS ──────────────────────────────────── -->
            <div>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('API access'),
                ]) ?>

                <?php if ($showInlineKey): ?>
                    <?= $panel(sprintf(
                        '<div class="d-flex align-items-center justify-content-between gap-3 flex-wrap py-1">
                            <span class="d-flex align-items-center gap-2 overflow-hidden">
                                <i class="fas fa-key %s flex-shrink-0 fa-fw fa-sm"></i>
                                <span class="small lh-sm overflow-hidden">
                                    <span class="fw-semibold d-block">%s</span>
                                    <small class="text-muted d-block">%s</small>
                                </span>
                            </span>
                            <span class="d-flex align-items-center gap-2 flex-shrink-0">
                                <span class="input-group input-group-sm" style="width:min(22rem, 100%%);">
                                    <input type="text" readonly class="form-control font-monospace"
                                           value="%s" data-mask="%s" data-secret="%s">
                                    <button class="btn btn-outline-secondary" type="button"
                                            title="%s" aria-label="%s"
                                            onclick="var i=this.previousElementSibling;
                                                     i.value = (i.value === i.dataset.secret) ? i.dataset.mask : i.dataset.secret;">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                    <button class="btn btn-outline-secondary" type="button"
                                            title="%s" aria-label="%s" data-copy-msg="%s"
                                            onclick="copyValueToClipboard(this.parentNode.querySelector(\'input\').dataset.secret, this.dataset.copyMsg)">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </span>
                                %s
                            </span>
                        </div>',
                        h($accent['textClass']),
                        h(__('Auth key')),
                        h(__('A reset takes effect at once and invalidates the current key.')),
                        str_repeat('*', 40),
                        str_repeat('*', 40),
                        h($u['authkey']),
                        h(__('Reveal hidden value')),
                        h(__('Reveal hidden value')),
                        h(__('Copy to clipboard')),
                        h(__('Copy to clipboard')),
                        h(__('Auth key copied to clipboard')),
                        $this->Form->postLink(
                            '<i class="fas fa-rotate"></i>',
                            ['action' => 'resetauthkey', $u['id']],
                            [
                                'class' => 'btn btn-sm btn-outline-warning',
                                'escape' => false,
                                'title' => __('Reset auth key'),
                                'aria-label' => __('Reset auth key'),
                            ]
                        )
                    )) ?>
                <?php elseif ($canRequestApi): ?>
                    <div class="row g-2">
                        <?= $stateTile('fas fa-key', __('Auth key'), sprintf(
                            '<button type="button" class="btn btn-sm btn-outline-primary"
                                     onclick="if (typeof requestAPIAccess === \'function\') { requestAPIAccess(); }">
                                <i class="fas fa-paper-plane me-1"></i>%s
                             </button>',
                            __('Request access')
                        ), [
                            'col' => 'col-12',
                            'note' => __('This account has no API permission yet.'),
                        ]) ?>
                    </div>
                <?php else: ?>
                    <div class="row g-2">
                        <?= $stateTile('fas fa-key', __('Auth keys'),
                            $statePill(!empty($role['perm_auth']), __('Allowed'), __('Not allowed')),
                            [
                                'col' => 'col-12',
                                'note' => $advancedKeys
                                    ? __('Individual keys are listed under the Auth keys tab.')
                                    : __('This account holds no inline auth key.'),
                            ]) ?>
                    </div>
                <?php endif; ?>
            </div>

            <!-- ── ACCOUNT FLAGS ───────────────────────────────── -->
            <div>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Account flags'),
                ]) ?>
                <div class="row g-2">

                    <?= $stateTile('fas fa-comment-dots', __('Contact reporter requests'),
                        $statePill(!empty($u['contactalert']), __('On'), __('Off')),
                        ['note' => __('Receives the emails sent through "Contact reporter".')]) ?>

                    <?php if ($adminView): ?>
                        <?= $stateTile('fas fa-file-signature', __('Terms accepted'),
                            $statePill(!empty($u['termsaccepted']), __('Yes'), __('No'))) ?>

                        <?= $stateTile('fas fa-user-slash', __('Account disabled'),
                            $statePill(!empty($u['disabled']), __('Yes'), __('No'), 'danger'),
                            [
                                'accent' => 'danger',
                                'note' => __('Blocks sign-in and API access immediately.'),
                            ]) ?>
                    <?php endif; ?>

                </div>
            </div>

            <!-- ── CRYPTO KEYS ─────────────────────────────────── -->
            <div>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Crypto keys'),
                ]) ?>
                <div class="row g-2">

                    <div class="col-12">
                        <?php ob_start(); ?>
                        <div class="d-flex align-items-center justify-content-between gap-3 flex-wrap">
                            <span class="d-flex align-items-center gap-2 overflow-hidden">
                                <i class="fas fa-lock <?= h($accent['textClass']) ?> flex-shrink-0 fa-fw fa-sm"></i>
                                <span class="small lh-sm overflow-hidden">
                                    <span class="fw-semibold d-block">
                                        <?= __('PGP key') ?>
                                    </span>
                                    <small class="text-muted d-block">
                                        <?= empty($u['gpgkey'])
                                            ? __('Encrypted notifications need one.')
                                            : (!empty($u['fingerprint']) && $u['fingerprint'] !== 'N/A'
                                                ? h(chunk_split($u['fingerprint'], 4, ' '))
                                                : __('No fingerprint reported.')) ?>
                                    </small>
                                </span>
                            </span>
                            <span class="d-flex align-items-center gap-2 flex-shrink-0">
                                <?php if (empty($u['gpgkey'])): ?>
                                    <?= $statePill(false, __('Set'), __('Not set')) ?>
                                <?php else: ?>
                                    <span class="badge rounded-pill text-bg-<?= $pgpOk ? 'success' : 'danger' ?>">
                                        <i class="fas <?= $pgpOk ? 'fa-check' : 'fa-triangle-exclamation' ?> me-1"></i>
                                        <?= h($u['pgp_status'] ?? __('N/A')) ?>
                                    </span>
                                <?php endif; ?>
                            </span>
                        </div>
                        <?php if (!empty($u['gpgkey'])): ?>
                            <?= $keyBlock($u['gpgkey']) ?>
                        <?php endif; ?>
                        <?php $pgpBody = ob_get_clean(); ?>
                        <?= $panel($pgpBody) ?>
                    </div>

                    <?php if ($smimeOn): ?>
                        <div class="col-12">
                            <?php ob_start(); ?>
                            <div class="d-flex align-items-center justify-content-between gap-3 flex-wrap">
                                <span class="d-flex align-items-center gap-2 overflow-hidden">
                                    <i class="fas fa-certificate <?= h($accent['textClass']) ?> flex-shrink-0 fa-fw fa-sm"></i>
                                    <span class="small lh-sm overflow-hidden">
                                        <span class="fw-semibold d-block">
                                            <?= __('S/MIME public certificate') ?>
                                        </span>
                                        <small class="text-muted d-block">
                                            <?= __('PEM format.') ?>
                                        </small>
                                    </span>
                                </span>
                                <span class="flex-shrink-0">
                                    <?= $statePill(!empty($u['certif_public']), __('Set'), __('Not set')) ?>
                                </span>
                            </div>
                            <?php if (!empty($u['certif_public'])): ?>
                                <?= $keyBlock($u['certif_public']) ?>
                            <?php endif; ?>
                            <?php $smimeBody = ob_get_clean(); ?>
                            <?= $panel($smimeBody) ?>
                        </div>
                    <?php endif; ?>

                </div>
            </div>

            <!-- ── ORG ADMINS ──────────────────────────────────── -->
            <?php if ($hasOrgAdmins): ?>
                <div>
                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                        'label' => __('Org admins'),
                    ]) ?>
                    <?php
                    $adminChips = '<div class="d-flex flex-wrap gap-2">';
                    foreach ($u['orgAdmins'] as $orgAdminId => $orgAdminEmail) {
                        $adminChips .= sprintf(
                            '<a class="badge text-bg-light border text-decoration-none fw-normal"
                                href="%s/admin/users/view/%s">
                                <i class="fas fa-user-shield me-1"></i>%s
                             </a>',
                            h($baseurl),
                            h($orgAdminId),
                            h($orgAdminEmail)
                        );
                    }
                    $adminChips .= '</div>';
                    ?>
                    <?= $panel($adminChips) ?>
                </div>
            <?php endif; ?>

        </div>
    </div>
</div>


<!-- ══ EMAIL NOTIFICATIONS ═════════════════════════════════════════════ -->
<?php
/* The periodic three come from the model's own constant so this card cannot
   fall behind it; the publish alert is not periodic and is named here. Icons
   and notes are admin_edit's, to the word. */
$notificationMeta = [
    'autoalert' => [
        'fas fa-bullhorn',
        __('Event published'),
        __('One email per published event this account can see.'),
    ],
    'notification_daily'   => ['fas fa-calendar-day',  __('Daily digest'), ''],
    'notification_weekly'  => ['fas fa-calendar-week', __('Weekly digest'), ''],
    'notification_monthly' => ['fas fa-calendar-days', __('Monthly digest'), ''],
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

    <?= $cardHead(
        'fas fa-bell',
        __('Email notifications'),
        __('%s of %s enabled', $notificationsOn, count($notificationKeys))
    ) ?>

    <div class="card-body p-3">
        <div class="row g-2">
            <?php foreach ($notificationKeys as $notificationKey): ?>
                <?php
                $meta = $notificationMeta[$notificationKey]
                    ?? ['fas fa-envelope', Inflector::humanize($notificationKey), ''];
                ?>
                <?= $stateTile($meta[0], $meta[1],
                    $statePill(!empty($u[$notificationKey])),
                    ['note' => $meta[2]]) ?>
            <?php endforeach; ?>
        </div>
    </div>
</div>
