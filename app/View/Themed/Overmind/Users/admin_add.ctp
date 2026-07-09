<?php
/**
 * Add user (admin only)Overmind "Admin add user" shown in a modal. 
 * Near-identical to admin_edit.ctp but for a fresh user: no id, "notify" option, pre-generated
 * authkey (legacy), no TOTP/current-password/terms/change-pw/periodic-notif.
 *
 * Submits via AJAX so validation errors (e.g. duplicate email) stay in the modal;
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

// Strip PCRE delimiters from the complexity regex so it can feed a JS RegExp.
$pwRegexBody = (string)$complexity;
if (strlen($pwRegexBody) >= 2 && $pwRegexBody[0] === '/') {
    $pwRegexBody = substr($pwRegexBody, 1, strrpos($pwRegexBody, '/') - 1);
}

// Value for a "default-on" switch, respecting a re-rendered POST.
$checkedOr = function ($field, $default) use ($u) {
    return array_key_exists($field, $u) ? !empty($u[$field]) : $default;
};

// BS5 switch (checkbox) helper. $checked null => Form default (unchecked on add).
$switch = function ($field, $label, $checked = null) {
    $sid = 'sw_' . $field;
    $opts = ['class' => 'form-check-input', 'id' => $sid, 'hiddenField' => true];
    if ($checked !== null) {
        $opts['checked'] = (bool)$checked;
    }
    return '<div class="col-md-6"><div class="form-check form-switch">'
        . $this->Form->checkbox($field, $opts)
        . $this->Form->label($sid, $label, ['class' => 'form-check-label'])
        . '</div></div>';
};

echo $this->Form->create('User', [
    'id' => 'AdminUserAddForm',
    'url' => '/admin/users/add',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-primary"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Administration') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-circle-plus text-primary" style="font-size:1.25rem;"></i>
            <?= __('Add user') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Create a new account.') ?>
        </p>
    </div>
    <i class="fas fa-user-plus text-primary" style="font-size:2rem; opacity:.5;"></i>
</div>

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
            <div class="text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Account') ?>
            </div>
            <div class="row g-3">
                <div class="col-md-8">
                    <?= $this->Form->label('email', __('Email'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('email', [
                        'class' => 'form-control bg-light' . (isset($validationErrors['email']) ? ' is-invalid' : ''),
                    ]) ?>
                    <?php if (isset($validationErrors['email'])): ?>
                        <div class="invalid-feedback d-block">
                            <?= h(is_array($validationErrors['email']) ? implode(' ', $validationErrors['email']) : $validationErrors['email']) ?>
                        </div>
                    <?php endif; ?>
                </div>
                <div class="col-md-4">
                    <?= $this->Form->label('nids_sid', __('NIDS SID'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('nids_sid', ['class' => 'form-control bg-light']) ?>
                </div>

                <?php if ($isSiteAdmin): ?>
                    <div class="col-md-6">
                        <?= $this->Form->label('org_id', __('Organisation'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->select('org_id', $orgs, [
                            'class' => 'form-select bg-light',
                            'empty' => __('Choose organisation'),
                        ]) ?>
                    </div>
                <?php endif; ?>

                <div class="col-md-6">
                    <?= $this->Form->label('role_id', __('Role'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('role_id', $roles, [
                        'class' => 'form-select bg-light',
                        'id' => 'adminRoleId',
                        'default' => $roleDefault,
                        'empty' => false,
                    ]) ?>
                </div>

                <?php if (!$advancedAuthkeys): ?>
                    <div class="col-md-12">
                        <?= $this->Form->label('authkey', __('Auth key'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->text('authkey', [
                            'class' => 'form-control bg-light font-monospace',
                            'value' => $authkey,
                            'readonly' => 'readonly',
                        ]) ?>
                        <div class="form-text"><?= __('Auto-generated key for the new user.') ?></div>
                    </div>
                <?php endif; ?>

                <!-- Sync server (shown only for sync roles) -->
                <div class="col-md-6" id="syncServersBlock" style="display:none;">
                    <?= $this->Form->label('server_id', __('Sync user for'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('server_id', $servers, [
                        'class' => 'form-select bg-light',
                        'empty' => false,
                    ]) ?>
                </div>
            </div>
        </div>

        <?php if ($customAuth): ?>
            <!-- EXTERNAL AUTH -->
            <div class="w-100 px-2">
                <div class="text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                    <?= h($customAuthName) ?>
                </div>
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('external_auth_required', [
                        'class' => 'form-check-input',
                        'id' => 'adminExternalAuthReq',
                        'hiddenField' => true,
                    ]) ?>
                    <?= $this->Form->label('adminExternalAuthReq', __('%s user', h($customAuthName)), ['class' => 'form-check-label']) ?>
                </div>
                <div id="externalAuthKeyBlock" style="display:none;">
                    <?= $this->Form->label('external_auth_key', __('External auth key'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('external_auth_key', ['class' => 'form-control bg-light']) ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- PASSWORD -->
        <div class="w-100 px-2" id="adminPasswordSection">
            <div class="text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Password') ?>
            </div>
            <div class="form-check form-switch mb-2">
                <?= $this->Form->checkbox('enable_password', [
                    'class' => 'form-check-input',
                    'id' => 'adminEnablePassword',
                    'hiddenField' => true,
                ]) ?>
                <?= $this->Form->label('adminEnablePassword', __('Set a password'), ['class' => 'form-check-label']) ?>
            </div>
            <div id="adminPasswordFields" style="display:none;">
                <div class="row g-3">
                    <div class="col-md-6">
                        <?= $this->Form->label('password', __('Password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('password', [
                            'class' => 'form-control bg-light',
                            'id' => 'addPassword',
                            'autocomplete' => 'new-password',
                            'value' => '',
                        ]) ?>
                        <div class="form-text">
                            <?= __('Min %s characters — upper & lower case and a number or symbol.', h($length)) ?>
                        </div>
                        <div id="addPasswordFeedback" class="small mt-1"></div>
                    </div>
                    <div class="col-md-6">
                        <?= $this->Form->label('confirm_password', __('Confirm password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('confirm_password', [
                            'class' => 'form-control bg-light',
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
            <div class="text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Cryptographic keys') ?>
            </div>
            <?= $this->Form->label('gpgkey', __('PGP key'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->textarea('gpgkey', [
                'class' => 'form-control bg-light font-monospace',
                'rows' => 4,
                'placeholder' => __("Paste the user's PGP key here"),
            ]) ?>
            <?php if (Configure::read('SMIME.enabled')): ?>
                <div class="mt-3">
                    <?= $this->Form->label('certif_public', __('S/MIME public certificate (PEM)'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('certif_public', [
                        'class' => 'form-control bg-light font-monospace',
                        'rows' => 4,
                    ]) ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- OPTIONS -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Options') ?>
            </div>
            <div class="row g-2">
                <?= $switch('autoalert', __('Receive email alerts when events are published'), $checkedOr('autoalert', $defaultPublishAlert)) ?>
                <?= $switch('contactalert', __('Receive "Contact reporter" request emails'), $checkedOr('contactalert', true)) ?>
                <?= $switch('disabled', __('Immediately disable this account')) ?>
                <?= $switch('notify', __('Send credentials automatically'), $checkedOr('notify', true)) ?>
            </div>
        </div>

    </div>
</div>

<!-- ── FOOTER ───────────────────────────────────────────────── -->
<div class="px-4 py-3 d-flex align-items-center justify-content-end gap-2 border-top">
    <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
        <i class="fas fa-times me-1"></i><?= __('Discard') ?>
    </button>
    <?= $this->Form->button(
        '<i class="fas fa-user-plus me-1"></i>' . __('Create user'),
        ['class' => 'btn btn-primary btn-sm', 'escapeTitle' => false]
    ) ?>
</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var form = document.getElementById('AdminUserAddForm');
    if (!form) return;

    // ── Toggles (password / sync server / external auth) ──────────
    var enablePw = document.getElementById('adminEnablePassword');
    var pwFields = document.getElementById('adminPasswordFields');
    function togglePw() { if (pwFields) pwFields.style.display = (enablePw && enablePw.checked) ? '' : 'none'; }
    if (enablePw) { enablePw.addEventListener('change', togglePw); }
    togglePw();

    var roleSel = document.getElementById('adminRoleId');
    var syncBlock = document.getElementById('syncServersBlock');
    var syncIds = <?= json_encode($syncRoleIds) ?>;
    function toggleSync() {
        if (syncBlock && roleSel) {
            syncBlock.style.display = (syncIds.indexOf(String(roleSel.value)) !== -1) ? '' : 'none';
        }
    }
    if (roleSel) { roleSel.addEventListener('change', toggleSync); }
    toggleSync();

    var extReq = document.getElementById('adminExternalAuthReq');
    var extBlock = document.getElementById('externalAuthKeyBlock');
    var pwSection = document.getElementById('adminPasswordSection');
    function toggleExt() {
        var on = extReq && extReq.checked;
        if (extBlock) extBlock.style.display = on ? '' : 'none';
        if (pwSection) pwSection.style.display = on ? 'none' : '';
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
