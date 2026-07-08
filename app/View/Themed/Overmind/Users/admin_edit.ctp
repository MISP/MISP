<?php
if (empty($ajax)) {
    $this->set('headerTitle', __('Edit user'));
}

$u = $this->request->data['User'] ?? [];
$isTotp = isset($u['totp']);
$advancedAuthkeys = !empty(Configure::read('Security.advanced_authkeys'));
$customAuth = (bool)Configure::read('Plugin.CustomAuth_enable');
$customAuthName = Configure::read('Plugin.CustomAuth_name') ?: __('External authentication');
$syncRoleIds = array_values(array_map('strval', array_keys($syncRoles)));

// BS5 switch (checkbox) helper.
$switch = function ($field, $label, $disabled = false) {
    $sid = 'sw_' . $field;
    return '<div class="col-md-6"><div class="form-check form-switch">'
        . $this->Form->checkbox($field, [
            'class' => 'form-check-input',
            'id' => $sid,
            'hiddenField' => true,
            'disabled' => $disabled,
        ])
        . $this->Form->label($sid, $label, ['class' => 'form-check-label' . ($disabled ? ' text-muted' : '')])
        . '</div></div>';
};

echo $this->Form->create('User', [
    'id' => 'AdminUserEditForm',
    'url' => '/admin/users/edit/' . h($id),
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
            <i class="fas fa-pen-to-square text-primary" style="font-size:1.25rem;"></i>
            <?= __('Edit user') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= h($u['email'] ?? '') ?>
        </p>
    </div>
    <i class="fas fa-user-pen text-primary" style="font-size:2rem; opacity:.5;"></i>
</div>

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
                        'class' => 'form-control bg-light',
                        'disabled' => !$canChangeLogin,
                    ]) ?>
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
                            'empty' => false,
                        ]) ?>
                    </div>
                <?php endif; ?>

                <div class="col-md-6">
                    <?= $this->Form->label('role_id', __('Role'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('role_id', $roles, [
                        'class' => 'form-select bg-light',
                        'id' => 'adminRoleId',
                        'empty' => false,
                    ]) ?>
                </div>

                <?php if (!$advancedAuthkeys && isset($u['authkey'])): ?>
                    <div class="col-md-12">
                        <?= $this->Form->label('authkey', __('Auth key'), ['class' => 'form-label fw-semibold']) ?>
                        <div class="d-flex gap-2 align-items-center">
                            <?= $this->Form->text('authkey', [
                                'class' => 'form-control bg-light font-monospace',
                                'disabled' => true,
                            ]) ?>
                            <button type="button" class="btn btn-outline-warning btn-sm flex-shrink-0"
                                    onclick="document.getElementById('resetAuthKeyForm').submit();">
                                <i class="fas fa-rotate me-1"></i><?= __('Reset') ?>
                            </button>
                        </div>
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
                    'disabled' => !$canChangePassword,
                ]) ?>
                <?= $this->Form->label('adminEnablePassword', __('Set a new password'), ['class' => 'form-check-label' . ($canChangePassword ? '' : ' text-muted')]) ?>
            </div>
            <div id="adminPasswordFields" style="display:none;">
                <div class="row g-3">
                    <div class="col-md-6">
                        <?= $this->Form->label('password', __('Password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('password', [
                            'class' => 'form-control bg-light',
                            'autocomplete' => 'new-password',
                            'value' => '',
                        ]) ?>
                        <div class="form-text"><?= __('Min length %s — complexity: %s', h($length), h($complexity)) ?></div>
                    </div>
                    <div class="col-md-6">
                        <?= $this->Form->label('confirm_password', __('Confirm password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('confirm_password', [
                            'class' => 'form-control bg-light',
                            'autocomplete' => 'new-password',
                            'value' => '',
                        ]) ?>
                    </div>
                </div>
            </div>
            <?php if ($isTotp): ?>
                <div class="mt-3">
                    <a href="#" class="btn btn-outline-danger btn-sm"
                       onclick="event.preventDefault(); openModalChained('<?= $baseurl ?>/users/totp_delete/<?= h($u['id']) ?>', 'sm');">
                        <i class="fas fa-mobile-screen me-1"></i><?= __('Delete TOTP token') ?>
                    </a>
                </div>
            <?php endif; ?>
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

        <!-- FLAGS -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Account flags') ?>
            </div>
            <div class="row g-2">
                <?= $switch('termsaccepted', __('Terms accepted')) ?>
                <?= $switch('change_pw', __('User must change password'), !$canChangePassword) ?>
                <?= $switch('contactalert', __('Receive "Contact reporter" request emails')) ?>
                <?= $switch('disabled', __('Immediately disable this account')) ?>
            </div>
        </div>

        <!-- NOTIFICATIONS -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Notifications') ?>
            </div>
            <div class="row g-2">
                <?= $switch('autoalert', __('Event published notification')) ?>
                <?= $switch('notification_weekly', __('Weekly notifications')) ?>
                <?= $switch('notification_daily', __('Daily notifications')) ?>
                <?= $switch('notification_monthly', __('Monthly notifications')) ?>
            </div>
        </div>

        <?php if (Configure::read('Security.require_password_confirmation')): ?>
            <!-- CONFIRM -->
            <div class="w-100 px-2">
                <div class="text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Confirm changes') ?>
                </div>
                <?= $this->Form->label('current_password', __('Enter your current password to save'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->password('current_password', [
                    'class' => 'form-control bg-light',
                    'autocomplete' => 'current-password',
                    'value' => '',
                ]) ?>
            </div>
        <?php endif; ?>

    </div>
</div>

<!-- ── FOOTER ───────────────────────────────────────────────── -->
<div class="px-4 py-3 d-flex align-items-center justify-content-end gap-2 border-top">
    <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
        <i class="fas fa-times me-1"></i><?= __('Discard') ?>
    </button>
    <?= $this->Form->button(
        '<i class="fas fa-check me-1"></i>' . __('Save changes'),
        ['class' => 'btn btn-primary btn-sm', 'escapeTitle' => false]
    ) ?>
</div>

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

    // Toggle the password fields with the "Set a new password" switch.
    var enablePw = document.getElementById('adminEnablePassword');
    var pwFields = document.getElementById('adminPasswordFields');
    function togglePw() { if (pwFields) pwFields.style.display = (enablePw && enablePw.checked) ? '' : 'none'; }
    if (enablePw) { enablePw.addEventListener('change', togglePw); }
    togglePw();

    // Show the sync-server picker only when the selected role is a sync role.
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

    // External-auth toggle (CustomAuth plugin): swap password section for key.
    var extReq = document.getElementById('adminExternalAuthReq');
    var extBlock = document.getElementById('externalAuthKeyBlock');
    var pwSection = document.getElementById('adminPasswordSection');
    function toggleExt() {
        var on = extReq && extReq.checked;
        if (extBlock) extBlock.style.display = on ? '' : 'none';
        if (pwSection) pwSection.style.display = on ? 'none' : '';
    }
    if (extReq) { extReq.addEventListener('change', toggleExt); toggleExt(); }
})();
</script>
