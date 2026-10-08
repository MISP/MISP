<?php
/**
 * Edit user (admin only)
 *
 * Submits via AJAX so a rejected save (wrong confirmation password, weak new
 * password, taken email) reports itself in place instead of throwing the admin
 * back to a re-rendered page.
 */

if (empty($ajax)) {
    $this->set('headerTitle', __('Edit user'));
}

$u = $this->request->data['User'] ?? [];
$isTotp = isset($u['totp']);
$advancedAuthkeys = !empty(Configure::read('Security.advanced_authkeys'));
$customAuth = (bool)Configure::read('Plugin.CustomAuth_enable');
$customAuthName = Configure::read('Plugin.CustomAuth_name') ?: __('External authentication');
$syncRoleIds = array_values(array_map('strval', array_keys($syncRoles)));
$canFetchPgpKey = !empty($canFetchPgpKey);
$roleChoices = [];
foreach ($roles as $roleId => $roleName) {
    $glyph = $this->RoleGlyph->get($roleName);
    $roleChoices[] = [
        'value' => $roleId,
        'title' => $roleName,
        'icon' => $glyph['icon'],
        'tone' => $glyph['colour'],
        'toneBg' => $glyph['tint'],
    ];
}

// Strip PCRE delimiters from the complexity regex so it can feed a JS RegExp.
$pwRegexBody = (string)$complexity;
if (strlen($pwRegexBody) >= 2 && $pwRegexBody[0] === '/') {
    $pwRegexBody = substr($pwRegexBody, 1, strrpos($pwRegexBody, '/') - 1);
}

/* One switch as a bordered tile — glyph and label on the left, the control on
 * the right, the whole row clickable. Same shape as the scope tile on the
 * organisation form, at the density a grid of eight of them needs.
 *
 * $opts: note, icon, accent (see ModalAccent), disabled, col, id.
 */
$switchTile = function ($field, $label, array $opts = []) {
    $disabled = !empty($opts['disabled']);
    $accent = $this->ModalAccent->get($opts['accent'] ?? 'primary');

    return sprintf(
        '<div class="%s">'
            . '<label class="d-flex align-items-center justify-content-between gap-3 h-100 w-100 border rounded-3 px-3 py-2 bg-light%s" style="cursor:%s;">'
            . '<span class="d-flex align-items-center gap-2" style="min-width:0;">'
            . '<i class="%s %s flex-shrink-0" style="width:1rem; font-size:.8rem; %s"></i>'
            . '<span style="min-width:0;"><span class="fw-semibold d-block" style="font-size:.85rem; line-height:1.25;">%s</span>%s</span>'
            . '</span>'
            . '<span class="form-check form-switch m-0 ps-0 flex-shrink-0">%s</span>'
            . '</label></div>',
        h($opts['col'] ?? 'col-md-6'),
        $disabled ? ' opacity-75' : '',
        $disabled ? 'not-allowed' : 'pointer',
        h($opts['icon'] ?? 'fas fa-toggle-on'),
        h($accent['textClass']),
        $accent['textStyle'],
        h($label),
        empty($opts['note'])
            ? ''
            : '<span class="text-muted d-block" style="font-size:.7rem; line-height:1.3;">' . h($opts['note']) . '</span>',
        $this->Form->checkbox($field, [
            'class' => 'form-check-input ms-0',
            'id' => $opts['id'] ?? ('sw_' . $field),
            'role' => 'switch',
            'hiddenField' => true,
            'disabled' => $disabled,
            'style' => 'width:2.4rem; height:1.2rem; cursor:' . ($disabled ? 'not-allowed' : 'pointer') . ';',
        ])
    );
};

echo $this->Form->create('User', [
    'id' => 'AdminUserEditForm',
    'url' => '/admin/users/edit/' . h($id),
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Administration'),
    'title' => __('Edit user'),
    'description' => __('Change what this account may do, how it signs in and which notifications it receives.'),
    'icon' => 'fas fa-user-pen',
    'isEdit' => true,
]) ?>

<!-- Server-side errors returned by the AJAX submit (kept in the modal). -->
<div class="px-4 pt-3 d-none" id="editUserAlertWrapper">
    <div class="alert alert-danger d-flex align-items-start gap-2 mb-0">
        <i class="fas fa-circle-exclamation mt-1"></i>
        <div id="editUserAlert"></div>
    </div>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ACCOUNT -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Account'),
                'required' => true,
            ]) ?>
            <div class="row g-3">
                <div class="<?= $isSiteAdmin ? 'col-md-6' : 'col-12' ?>">
                    <?= $this->Form->label('email', __('Email'), ['class' => 'form-label fw-semibold']) ?>
                    <div class="input-group">
                        <span class="input-group-text bg-light"><i class="fas fa-at text-muted"></i></span>
                        <?= $this->Form->text('email', [
                            'class' => 'form-control' . ($canChangeLogin ? '' : ' bg-light'),
                            'disabled' => !$canChangeLogin,
                            'data-pgp-email' => true,
                        ]) ?>
                    </div>
                    <?php if (!$canChangeLogin): ?>
                        <?= $this->element('genericElementsBS5/Forms/field_hint', [
                            'text' => __('The login address is managed outside MISP on this instance.'),
                        ]) ?>
                    <?php endif; ?>
                </div>

                <?php if ($isSiteAdmin): ?>
                    <div class="col-md-6">
                        <?= $this->Form->label('org_id', __('Organisation'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->select('org_id', $orgs, [
                            'class' => 'form-select tom-select',
                            'empty' => false,
                            'data-placeholder' => __('Choose an organisation'),
                        ]) ?>
                    </div>
                <?php endif; ?>

                <div class="col-md-6">
                    <?= $this->Form->label('role_id', __('Role'), ['class' => 'form-label fw-semibold', 'for' => 'adminRoleId']) ?>
                    <?= $this->element('genericElementsBS5/Forms/choice_select', [
                        'field' => 'role_id',
                        'options' => $roleChoices,
                        'id' => 'adminRoleId',
                        'ariaLabel' => __('Role'),
                    ]) ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'text' => __('The role decides every permission this account has.'),
                    ]) ?>
                </div>

                <!-- Sync server (shown only for sync roles) -->
                <div class="col-md-6 d-none" id="syncServersBlock">
                    <?= $this->Form->label('server_id', __('Sync user for'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('server_id', $servers, [
                        'class' => 'form-select',
                        'empty' => false,
                    ]) ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'text' => __('The remote server this account pulls from and pushes to.'),
                    ]) ?>
                </div>

                <div class="col-md-6">
                    <?= $this->Form->label('nids_sid', __('NIDS SID'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('nids_sid', ['class' => 'form-control font-monospace']) ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'text' => __('Starting rule ID for the NIDS exports this account generates.'),
                    ]) ?>
                </div>
            </div>
        </div>

        <?php if (!$advancedAuthkeys && isset($u['authkey'])): ?>
            <!-- API ACCESS -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('API access'),
                ]) ?>
                <?= $this->Form->label('authkey', __('Auth key'), ['class' => 'form-label fw-semibold']) ?>
                <div class="input-group">
                    <?= $this->Form->text('authkey', [
                        'class' => 'form-control bg-light font-monospace',
                        'disabled' => true,
                    ]) ?>
                    <button type="button" class="btn btn-outline-warning"
                            title="<?= h(__('Generate a new auth key for this account')) ?>"
                            onclick="document.getElementById('resetAuthKeyForm').submit();">
                        <i class="fas fa-rotate me-1"></i><?= __('Reset') ?>
                    </button>
                </div>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('A reset takes effect at once and discards any change left unsaved here.'),
                ]) ?>
            </div>
        <?php endif; ?>

        <?php if ($customAuth): ?>
            <!-- EXTERNAL AUTH -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => h($customAuthName),
                ]) ?>
                <div class="row g-2">
                    <?= $switchTile('external_auth_required', __('%s user', $customAuthName), [
                        'id' => 'adminExternalAuthReq',
                        'icon' => 'fas fa-id-badge',
                        'col' => 'col-12',
                        'note' => __('The account signs in through %s instead of a MISP password.', $customAuthName),
                    ]) ?>
                </div>
                <div id="externalAuthKeyBlock" class="d-none mt-3">
                    <?= $this->Form->label('external_auth_key', __('External auth key'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('external_auth_key', ['class' => 'form-control font-monospace']) ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- PASSWORD -->
        <div class="w-100 px-2" id="adminPasswordSection">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Password'),
            ]) ?>
            <div class="row g-2">
                <?= $switchTile('enable_password', __('Set a new password'), [
                    'id' => 'adminEnablePassword',
                    'icon' => 'fas fa-key',
                    'col' => 'col-12',
                    'disabled' => !$canChangePassword,
                    'note' => $canChangePassword
                        ? __('Leave off to keep the password the user already has.')
                        : __('Password changes are disabled on this instance.'),
                ]) ?>
            </div>
            <div id="adminPasswordFields" class="d-none mt-3 p-3 border rounded-3">
                <div class="row g-3">
                    <div class="col-md-6">
                        <?= $this->Form->label('password', __('Password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('password', [
                            'class' => 'form-control',
                            'id' => 'editPassword',
                            'autocomplete' => 'new-password',
                            'value' => '',
                        ]) ?>
                        <?= $this->element('genericElementsBS5/Forms/field_hint', [
                            'text' => __('At least %s characters, mixing case with a number or a symbol.', h($length)),
                        ]) ?>
                        <div id="editPasswordFeedback" class="small mt-1"></div>
                    </div>
                    <div class="col-md-6">
                        <?= $this->Form->label('confirm_password', __('Confirm password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('confirm_password', [
                            'class' => 'form-control',
                            'id' => 'editConfirm',
                            'autocomplete' => 'new-password',
                            'value' => '',
                        ]) ?>
                        <div id="editConfirmFeedback" class="small mt-1"></div>
                    </div>
                </div>
            </div>
            <?php if ($isTotp): ?>
                <div class="d-flex align-items-center justify-content-between gap-3 border rounded-3 px-3 py-2 mt-3">
                    <span class="d-flex align-items-center gap-2" style="min-width:0;">
                        <i class="fas fa-mobile-screen text-warning flex-shrink-0" style="width:1rem; font-size:.8rem;"></i>
                        <span style="min-width:0;">
                            <span class="fw-semibold d-block" style="font-size:.85rem; line-height:1.25;">
                                <?= __('Two-factor authentication') ?>
                            </span>
                            <span class="text-muted d-block" style="font-size:.7rem; line-height:1.3;">
                                <?= __('A TOTP token is enrolled — remove it to let the user enrol a new one.') ?>
                            </span>
                        </span>
                    </span>
                    <button type="button" class="btn btn-sm btn-outline-danger flex-shrink-0"
                            onclick="openModalChained('<?= $baseurl ?>/users/totp_delete/<?= h($u['id']) ?>', 'md');">
                        <i class="fas fa-trash me-1"></i><?= __('Remove token') ?>
                    </button>
                </div>
            <?php endif; ?>
        </div>

        <!-- CRYPTO KEYS -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-end justify-content-between gap-2 mb-1">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('PGP key'),
                ]) ?>
                <?php if ($canFetchPgpKey): ?>
                    <button type="button" class="btn btn-sm btn-outline-primary flex-shrink-0"
                            data-pgp-lookup
                            data-pgp-busy-label="<?= h(__('Searching…')) ?>"
                            data-pgp-empty-message="<?= h(__('The key server has no key for this address.')) ?>"
                            data-pgp-error-message="<?= h(__('The key server could not be reached.')) ?>"
                            data-pgp-disabled-message="<?= h(__('Key fetching is disabled on this instance.')) ?>"
                            data-pgp-found-message="<?= h(__('PGP key loaded into the field.')) ?>"
                            title="<?= h(__('Search the CIRCL key server for the email address above')) ?>">
                        <i class="fas fa-cloud-arrow-down me-1"></i><?= __('Fetch PGP key') ?>
                    </button>
                <?php endif; ?>
            </div>
            <?= $this->Form->textarea('gpgkey', [
                'class' => 'form-control font-monospace',
                'rows' => 4,
                'style' => 'font-size:.75rem;',
                'data-pgp-target' => true,
                'placeholder' => "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => $canFetchPgpKey
                    ? __('Paste the armoured public key, or look it up on the CIRCL key server by the email address above.')
                    : __('Paste the armoured public key. Encrypted notifications need it.'),
            ]) ?>
            <!-- Key-server results land here, see initPgpKeyLookup(). -->
            <div class="mt-2 d-none" data-pgp-results></div>
            <?php if (Configure::read('SMIME.enabled')): ?>
                <div class="mt-3">
                    <?= $this->Form->label('certif_public', __('S/MIME public certificate'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('certif_public', [
                        'class' => 'form-control font-monospace',
                        'rows' => 4,
                        'style' => 'font-size:.75rem;',
                        'placeholder' => "-----BEGIN CERTIFICATE-----",
                    ]) ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'text' => __('PEM format.'),
                    ]) ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- FLAGS -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Account flags'),
            ]) ?>
            <div class="row g-2">
                <?= $switchTile('termsaccepted', __('Terms accepted'), [
                    'icon' => 'fas fa-file-signature',
                ]) ?>
                <?= $switchTile('change_pw', __('Must change password'), [
                    'icon' => 'fas fa-key',
                    'disabled' => !$canChangePassword,
                    'note' => __('Asked for a new password on the next sign-in.'),
                ]) ?>
                <?= $switchTile('contactalert', __('Contact reporter requests'), [
                    'icon' => 'fas fa-comment-dots',
                    'note' => __('Receives the emails sent through "Contact reporter".'),
                ]) ?>
                <?= $switchTile('disabled', __('Account disabled'), [
                    'icon' => 'fas fa-user-slash',
                    'accent' => 'danger',
                    'note' => __('Blocks sign-in and API access immediately.'),
                ]) ?>
            </div>
        </div>

        <!-- NOTIFICATIONS -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Notifications'),
            ]) ?>
            <div class="row g-2">
                <?= $switchTile('autoalert', __('Event published'), [
                    'icon' => 'fas fa-bullhorn',
                    'note' => __('One email per published event this account can see.'),
                ]) ?>
                <?= $switchTile('notification_daily', __('Daily digest'), [
                    'icon' => 'fas fa-calendar-day',
                ]) ?>
                <?= $switchTile('notification_weekly', __('Weekly digest'), [
                    'icon' => 'fas fa-calendar-week',
                ]) ?>
                <?= $switchTile('notification_monthly', __('Monthly digest'), [
                    'icon' => 'fas fa-calendar-days',
                ]) ?>
            </div>
        </div>

        <?php if (Configure::read('Security.require_password_confirmation')): ?>
            <!-- CONFIRM -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Confirm changes'),
                    'required' => true,
                ]) ?>
                <?= $this->Form->label('current_password', __('Your own password'), ['class' => 'form-label fw-semibold']) ?>
                <div class="row">
                    <div class="col-md-6">
                        <?= $this->Form->password('current_password', [
                            'class' => 'form-control',
                            'id' => 'editCurrentPassword',
                            'autocomplete' => 'current-password',
                            'value' => '',
                        ]) ?>
                        <div id="editCurrentPasswordFeedback" class="small mt-1"></div>
                    </div>
                </div>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('This instance asks an administrator to confirm their identity before saving another account.'),
                ]) ?>
            </div>
        <?php endif; ?>

    </div>
</div>

<?= $this->element('genericElementsBS5/Forms/modal_footer', [
    'bleed' => true,
    'isEdit' => true,
    'meta' => [['label' => __('Connected as'), 'value' => $u['email']]],
    'submit' => ['label' => __('Save changes'), 'icon' => 'fas fa-check'],
]) ?>

<?= $this->Form->end() ?>

<?php
// Legacy auth-key reset — separate sibling form (never nested in the main form),
// submitted by the "Reset" button above.
if (!$advancedAuthkeys && isset($u['authkey'])) {
    echo $this->Form->create('User', [
        'url' => '/users/resetauthkey/' . h($id),
        'id' => 'resetAuthKeyForm',
    ]);
    echo $this->Form->end();
}
?>

<script>
(function () {
    var form = document.getElementById('AdminUserEditForm');
    if (!form) return;

    /* Both live in mispOvermind.js, which the layout loads at the end of the
     * body — after this script on a full-page render. openModal() already
     * calls them for the modal path, so wait for the document either way;
     * initPgpKeyLookup() is idempotent, so calling it twice is free. */
    function boot() {
        if (typeof initPgpKeyLookup === 'function') { initPgpKeyLookup(form); }
        if (typeof initTomSelect === 'function') { initTomSelect(form); }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    // Toggle the password fields with the "Set a new password" switch.
    var enablePw = document.getElementById('adminEnablePassword');
    var pwFields = document.getElementById('adminPasswordFields');
    function togglePw() {
        if (pwFields) { pwFields.classList.toggle('d-none', !(enablePw && enablePw.checked)); }
    }
    if (enablePw) { enablePw.addEventListener('change', togglePw); }
    togglePw();

    // Show the sync-server picker only when the selected role is a sync role.
    var roleSel = document.getElementById('adminRoleId');
    var syncBlock = document.getElementById('syncServersBlock');
    var syncIds = <?= json_encode($syncRoleIds) ?>;
    function toggleSync() {
        if (syncBlock && roleSel) {
            syncBlock.classList.toggle('d-none', syncIds.indexOf(String(roleSel.value)) === -1);
        }
    }
    if (roleSel) { roleSel.addEventListener('change', toggleSync); }
    toggleSync();

    // External-auth toggle (CustomAuth plugin): swap password section for key.
    var extReq = document.getElementById('adminExternalAuthReq');
    var extBlock = document.getElementById('externalAuthKeyBlock');
    var pwSection = document.getElementById('adminPasswordSection');
    function toggleExt() {
        var on = extReq && extReq.checked;
        if (extBlock) { extBlock.classList.toggle('d-none', !on); }
        if (pwSection) { pwSection.classList.toggle('d-none', !!on); }
    }
    if (extReq) { extReq.addEventListener('change', toggleExt); toggleExt(); }

    // ── Real-time password validation ─────────────────────────────
    var pw = document.getElementById('editPassword');
    var cf = document.getElementById('editConfirm');
    var pwFb = document.getElementById('editPasswordFeedback');
    var cfFb = document.getElementById('editConfirmFeedback');
    var PW_MIN = <?= (int)$length ?>;
    var PW_RE = null;
    try { PW_RE = new RegExp(<?= json_encode($pwRegexBody) ?>); } catch (e) { PW_RE = null; }
    var MSG_SHORT = <?= json_encode(__('Too short — at least %s characters', '%N%')) ?>.replace('%N%', PW_MIN);
    var MSG_WEAK  = <?= json_encode(__('Does not meet the complexity requirements')) ?>;
    var MSG_OK    = <?= json_encode(__('Strong password')) ?>;
    var MSG_NOMATCH = <?= json_encode(__('Passwords do not match')) ?>;
    var MSG_MATCH   = <?= json_encode(__('Passwords match')) ?>;

    function setState(input, fb, ok, msg) {
        if (!input) return;
        input.classList.remove('is-valid', 'is-invalid');
        if (msg === '') { if (fb) { fb.textContent = ''; } return; }
        input.classList.add(ok ? 'is-valid' : 'is-invalid');
        if (fb) {
            fb.textContent = msg;
            fb.className = 'small mt-1 ' + (ok ? 'text-success' : 'text-danger');
        }
    }
    function checkPw() {
        if (!pw) return;
        var v = pw.value;
        if (v === '') { setState(pw, pwFb, false, ''); checkCf(); return; }
        if (v.length < PW_MIN) { setState(pw, pwFb, false, MSG_SHORT); }
        else if (PW_RE && !PW_RE.test(v)) { setState(pw, pwFb, false, MSG_WEAK); }
        else { setState(pw, pwFb, true, MSG_OK); }
        checkCf();
    }
    function checkCf() {
        if (!cf) return;
        if (cf.value === '') { setState(cf, cfFb, false, ''); return; }
        var ok = !!pw && cf.value === pw.value;
        setState(cf, cfFb, ok, ok ? MSG_MATCH : MSG_NOMATCH);
    }
    if (pw) { pw.addEventListener('input', checkPw); }
    if (cf) { cf.addEventListener('input', checkCf); }

    // ── AJAX submit: stay in the modal on a rejected save ─────────
    if (!form.closest('#mainModal')) { return; }

    var curPw = document.getElementById('editCurrentPassword');
    var curFb = document.getElementById('editCurrentPasswordFeedback');
    var alertWrapper = document.getElementById('editUserAlertWrapper');
    var alertBox = document.getElementById('editUserAlert');

    // Clear the "incorrect password" state as soon as the admin retypes.
    if (curPw) { curPw.addEventListener('input', function () { setState(curPw, curFb, false, ''); }); }

    function fieldFor(name) {
        if (name === 'current_password') return curPw;
        if (name === 'password') return pw;
        if (name === 'confirm_password') return cf;
        return form.querySelector('[name="data[User][' + name + ']"]');
    }
    function feedbackFor(name) {
        if (name === 'current_password') return curFb;
        if (name === 'password') return pwFb;
        if (name === 'confirm_password') return cfFb;
        return null;
    }
    function flatten(err) {
        if (Array.isArray(err)) { return err.join(' '); }
        if (err && typeof err === 'object') {
            return Object.keys(err).map(function (k) { return flatten(err[k]); }).join(' ');
        }
        return String(err);
    }
    function showErrors(data) {
        var errors = (data && data.errors) || {};
        var leftovers = [];
        var firstInput = null;
        Object.keys(errors).forEach(function (name) {
            var msg = flatten(errors[name]);
            var input = fieldFor(name);
            if (!input) { leftovers.push(msg); return; }
            var fb = feedbackFor(name);
            if (fb) {
                setState(input, fb, false, msg);
            } else {
                input.classList.remove('is-valid');
                input.classList.add('is-invalid');
                leftovers.push(msg);
            }
            if (!firstInput) { firstInput = input; }
        });
        if (data && data.message && !Object.keys(errors).length) { leftovers.push(data.message); }
        if (alertWrapper && alertBox) {
            alertBox.textContent = leftovers.join(' ');
            alertWrapper.classList.toggle('d-none', leftovers.length === 0);
        }
        if (firstInput) {
            firstInput.focus();
            firstInput.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }
    }

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        if (alertWrapper) { alertWrapper.classList.add('d-none'); }
        fetch(form.getAttribute('action'), {
            method: 'POST',
            body: new FormData(form),
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
        .then(function (r) {
            var ct = r.headers.get('Content-Type') || '';
            return r.text().then(function (t) { return { ct: ct, text: t }; });
        })
        .then(function (res) {
            if (res.ct.indexOf('application/json') !== -1) {
                var d = null;
                try { d = JSON.parse(res.text); } catch (err) { d = null; }
                if (d && d.success) {
                    window.location.href = '<?= $baseurl ?>/admin/users/index';
                    return;
                }
                if (d) { showErrors(d); return; }
            }
            // Unexpected HTML (session expiry, exception page) → re-render in place.
            if (typeof renderMainModalContent === 'function') {
                renderMainModalContent(res.text);
            }
        })
        .catch(function () { /* network error: leave the form as-is */ });
    });
})();
</script>
