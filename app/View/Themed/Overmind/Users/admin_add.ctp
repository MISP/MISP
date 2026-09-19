<?php
/**
 * Add user (admin only)
 *
 * Near-identical to admin_edit.ctp but for a fresh account: no id, a "notify"
 * option, a pre-generated auth key (legacy authkeys only), and none of the
 * TOTP / current-password / terms / change-pw / periodic-notification fields.
 *
 * Submits via AJAX so a validation error (a taken email, a weak password)
 * re-renders inside the modal instead of throwing the admin back to a page.
 */

if (empty($ajax)) {
    $this->set('headerTitle', __('Add user'));
}

$u = $this->request->data['User'] ?? [];
$validationErrors = $validationErrors ?? [];
$advancedAuthkeys = !empty(Configure::read('Security.advanced_authkeys'));
$customAuth = (bool)Configure::read('Plugin.CustomAuth_enable');
$customAuthName = Configure::read('Plugin.CustomAuth_name') ?: __('External authentication');
$syncRoleIds = array_values(array_map('strval', array_keys($syncRoles)));
$defaultPublishAlert = Configure::read('MISP.default_publish_alert');
$defaultPublishAlert = ($defaultPublishAlert === null) ? true : (bool)$defaultPublishAlert;
$roleDefault = (!empty($default_role_id) && isset($roles[(int)$default_role_id])) ? $default_role_id : null;
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

// Value for a "default-on" switch, respecting a re-rendered POST.
$checkedOr = function ($field, $default) use ($u) {
    return array_key_exists($field, $u) ? !empty($u[$field]) : $default;
};

/* One switch as a bordered tile — glyph and label on the left, the control on
 * the right, the whole row clickable. Same shape as the scope tile on the
 * organisation form, at the density a grid of them needs.
 *
 * $opts: note, icon, accent (see ModalAccent), checked (null leaves the
 * FormHelper default), disabled, col, id.
 */
$switchTile = function ($field, $label, array $opts = []) {
    $disabled = !empty($opts['disabled']);
    $accent = $this->ModalAccent->get($opts['accent'] ?? 'primary');
    $checkbox = [
        'class' => 'form-check-input ms-0',
        'id' => $opts['id'] ?? ('sw_' . $field),
        'role' => 'switch',
        'hiddenField' => true,
        'disabled' => $disabled,
        'style' => 'width:2.4rem; height:1.2rem; cursor:' . ($disabled ? 'not-allowed' : 'pointer') . ';',
    ];
    if (isset($opts['checked'])) {
        $checkbox['checked'] = (bool)$opts['checked'];
    }

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
        $this->Form->checkbox($field, $checkbox)
    );
};

// One field's validation message, flattened for display.
$errorFor = function ($field) use ($validationErrors) {
    if (!isset($validationErrors[$field])) {
        return '';
    }

    return is_array($validationErrors[$field])
        ? implode(' ', $validationErrors[$field])
        : (string)$validationErrors[$field];
};

echo $this->Form->create('User', [
    'id' => 'AdminUserAddForm',
    'url' => '/admin/users/add',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Administration'),
    'title' => __('Add user'),
    'description' => __('Create an account, choose what it may do and how its credentials reach the user.'),
    'icon' => 'fas fa-user-plus',
]) ?>

<?php if (!empty($validationErrors)): ?>
    <!-- VALIDATION ERRORS -->
    <div class="px-4 pt-3">
        <div class="alert alert-danger d-flex align-items-start gap-2 mb-0">
            <i class="fas fa-circle-exclamation mt-1"></i>
            <div>
                <?php foreach ($validationErrors as $field => $errs): ?>
                    <?php foreach ((array)$errs as $er): ?>
                        <div><?= h(is_array($er) ? implode(' ', $er) : $er) ?></div>
                    <?php endforeach; ?>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
<?php endif; ?>

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
                            'class' => 'form-control' . ($errorFor('email') === '' ? '' : ' is-invalid'),
                            'placeholder' => __('user@example.com'),
                            'data-pgp-email' => true,
                        ]) ?>
                    </div>
                    <?php if ($errorFor('email') !== ''): ?>
                        <div class="invalid-feedback d-block"><?= h($errorFor('email')) ?></div>
                    <?php endif; ?>
                </div>

                <?php if ($isSiteAdmin): ?>
                    <div class="col-md-6">
                        <?= $this->Form->label('org_id', __('Organisation'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->select('org_id', $orgs, [
                            'class' => 'form-select tom-select',
                            'empty' => __('Choose organisation'),
                            // initTomSelect() reads this; without it the control
                            // falls back to TomSelect's own "Select options...".
                            'data-placeholder' => __('Choose an organisation'),
                        ]) ?>
                    </div>
                <?php endif; ?>

                <div class="col-md-6">
                    <?= $this->Form->label('role_id', __('Role'), ['class' => 'form-label fw-semibold', 'for' => 'adminRoleId']) ?>
                    <?= $this->element('genericElementsBS5/Forms/choice_select', [
                        'field' => 'role_id',
                        'options' => $roleChoices,
                        'value' => $roleDefault,
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

        <?php if (!$advancedAuthkeys): ?>
            <!-- API ACCESS -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('API access'),
                ]) ?>
                <?= $this->Form->label('authkey', __('Auth key'), ['class' => 'form-label fw-semibold']) ?>
                <div class="input-group">
                    <?= $this->Form->text('authkey', [
                        'class' => 'form-control bg-light font-monospace',
                        'id' => 'adminNewAuthkey',
                        'value' => $authkey,
                        'readonly' => 'readonly',
                    ]) ?>
                    <button type="button" class="btn btn-outline-secondary"
                            onclick="copyValueToClipboard(document.getElementById('adminNewAuthkey').value, '<?= h(__('Auth key copied')) ?>');"
                            title="<?= h(__('Copy the auth key')) ?>">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('Generated for this account — the only time it is shown in full.'),
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
                <?= $switchTile('enable_password', __('Set a password now'), [
                    'id' => 'adminEnablePassword',
                    'icon' => 'fas fa-key',
                    'col' => 'col-12',
                    'note' => __('Leave off to let MISP generate one and mail it with the credentials.'),
                ]) ?>
            </div>
            <div id="adminPasswordFields" class="d-none mt-3 p-3 border rounded-3">
                <div class="row g-3">
                    <div class="col-md-6">
                        <?= $this->Form->label('password', __('Password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('password', [
                            'class' => 'form-control',
                            'id' => 'addPassword',
                            'autocomplete' => 'new-password',
                            'value' => '',
                        ]) ?>
                        <?= $this->element('genericElementsBS5/Forms/field_hint', [
                            'text' => __('At least %s characters, mixing case with a number or a symbol.', h($length)),
                        ]) ?>
                        <div id="addPasswordFeedback" class="small mt-1"></div>
                    </div>
                    <div class="col-md-6">
                        <?= $this->Form->label('confirm_password', __('Confirm password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('confirm_password', [
                            'class' => 'form-control',
                            'id' => 'addConfirm',
                            'autocomplete' => 'new-password',
                            'value' => '',
                        ]) ?>
                        <div id="addConfirmFeedback" class="small mt-1"></div>
                    </div>
                </div>
            </div>
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

        <!-- OPTIONS -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Options'),
            ]) ?>
            <div class="row g-2">
                <?= $switchTile('notify', __('Email the credentials'), [
                    'icon' => 'fas fa-paper-plane',
                    'checked' => $checkedOr('notify', true),
                    'note' => __('Sends the new user their login details right away.'),
                ]) ?>
                <?= $switchTile('autoalert', __('Event published'), [
                    'icon' => 'fas fa-bullhorn',
                    'checked' => $checkedOr('autoalert', $defaultPublishAlert),
                    'note' => __('One email per published event this account can see.'),
                ]) ?>
                <?= $switchTile('contactalert', __('Contact reporter requests'), [
                    'icon' => 'fas fa-comment-dots',
                    'checked' => $checkedOr('contactalert', true),
                    'note' => __('Receives the emails sent through "Contact reporter".'),
                ]) ?>
                <?= $switchTile('disabled', __('Account disabled'), [
                    'icon' => 'fas fa-user-slash',
                    'accent' => 'danger',
                    'note' => __('Create the account now, but keep it from signing in.'),
                ]) ?>
            </div>
        </div>

    </div>
</div>

<?= $this->element('genericElementsBS5/Forms/modal_footer', [
    'bleed' => true,
    'submit' => ['label' => __('Create user'), 'icon' => 'fas fa-user-plus'],
]) ?>

<?= $this->Form->end() ?>

<script>
(function () {
    var form = document.getElementById('AdminUserAddForm');
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

    // ── Toggles (password / sync server / external auth) ──────────
    var enablePw = document.getElementById('adminEnablePassword');
    var pwFields = document.getElementById('adminPasswordFields');
    function togglePw() {
        if (pwFields) { pwFields.classList.toggle('d-none', !(enablePw && enablePw.checked)); }
    }
    if (enablePw) { enablePw.addEventListener('change', togglePw); }
    togglePw();

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
    var pw = document.getElementById('addPassword');
    var cf = document.getElementById('addConfirm');
    var pwFb = document.getElementById('addPasswordFeedback');
    var cfFb = document.getElementById('addConfirmFeedback');
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

    // ── AJAX submit: stay in the modal on validation error ────────
    if (!form.closest('#mainModal')) { return; }
    form.addEventListener('submit', function (e) {
        e.preventDefault();
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
                try {
                    var d = JSON.parse(res.text);
                    if (d && d.success) {
                        window.location.href = '<?= $baseurl ?>/admin/users/index';
                        return;
                    }
                } catch (err) { /* fall through to re-render */ }
            }
            // Validation error (or unexpected HTML) → re-render the modal in place.
            if (typeof renderMainModalContent === 'function') {
                renderMainModalContent(res.text);
            }
        })
        .catch(function () { /* network error: leave the form as-is */ });
    });
})();
</script>
