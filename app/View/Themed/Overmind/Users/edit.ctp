<?php
/**
 * Edit own profile
 *
 */

if (empty($ajax)) {
    $this->set('headerTitle', __('Edit profile'));
}

$canFetchPgpKey = !empty($canFetchPgpKey);

// Strip PCRE delimiters from the complexity regex so it can feed a JS RegExp.
$pwRegexBody = (string)$complexity;
if (strlen($pwRegexBody) >= 2 && $pwRegexBody[0] === '/') {
    $pwRegexBody = substr($pwRegexBody, 1, strrpos($pwRegexBody, '/') - 1);
}

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

echo $this->Form->create('User', [
    'id' => 'UserEditForm',
    'url' => '/users/edit',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Profile'),
    'title' => __('Edit profile'),
    'description' => __('Update your account details, notification preferences and cryptographic keys.'),
    'icon' => 'fas fa-user-pen',
    'isEdit' => true,
]) ?>

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
                <div class="col-md-6">
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

                <div class="col-md-6">
                    <?= $this->Form->label('nids_sid', __('NIDS SID'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('nids_sid', ['class' => 'form-control font-monospace']) ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'text' => __('Starting rule ID for the NIDS exports you generate.'),
                    ]) ?>
                </div>
            </div>
        </div>

        <?php if ($canChangePassword): ?>
            <!-- PASSWORD -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Password'),
                ]) ?>
                <div class="row g-2">
                    <?= $switchTile('enable_password', __('Set a new password'), [
                        'id' => 'profileEnablePassword',
                        'icon' => 'fas fa-key',
                        'col' => 'col-12',
                        'note' => __('Leave off to keep the password you already have.'),
                    ]) ?>
                </div>
                <div id="profilePasswordFields" class="d-none mt-3 p-3 border rounded-3">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <?= $this->Form->label('password', __('New password'), ['class' => 'form-label fw-semibold']) ?>
                            <?= $this->Form->password('password', [
                                'class' => 'form-control',
                                'id' => 'profilePassword',
                                'autocomplete' => 'new-password',
                                'value' => '',
                            ]) ?>
                            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                                'text' => __('At least %s characters, mixing case with a number or a symbol.', h($length)),
                            ]) ?>
                            <div id="profilePasswordFeedback" class="small mt-1"></div>
                        </div>
                        <div class="col-md-6">
                            <?= $this->Form->label('confirm_password', __('Confirm new password'), ['class' => 'form-label fw-semibold']) ?>
                            <?= $this->Form->password('confirm_password', [
                                'class' => 'form-control',
                                'id' => 'profileConfirm',
                                'autocomplete' => 'new-password',
                                'value' => '',
                            ]) ?>
                            <div id="profileConfirmFeedback" class="small mt-1"></div>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>

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
                    ? __('Paste your armoured public key, or look it up on the CIRCL key server by the email address above.')
                    : __('Paste your armoured public key. Encrypted notifications need it.'),
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

        <!-- NOTIFICATIONS -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Notifications'),
            ]) ?>
            <div class="row g-2">
                <?= $switchTile('autoalert', __('Event published'), [
                    'icon' => 'fas fa-bullhorn',
                    'note' => __('One email per published event you can see.'),
                ]) ?>
                <?= $switchTile('contactalert', __('Contact reporter requests'), [
                    'icon' => 'fas fa-comment-dots',
                    'note' => __('Receives the emails sent through "Contact reporter".'),
                ]) ?>
                <!-- Three digests, so thirds: 6+6 then 4+4+4 both fill their row. -->
                <?= $switchTile('notification_daily', __('Daily digest'), [
                    'icon' => 'fas fa-calendar-day',
                    'col' => 'col-md-4',
                    'note' => __('One summary a day of the events you can see.'),
                ]) ?>
                <?= $switchTile('notification_weekly', __('Weekly digest'), [
                    'icon' => 'fas fa-calendar-week',
                    'col' => 'col-md-4',
                    'note' => __('The same summary, once a week.'),
                ]) ?>
                <?= $switchTile('notification_monthly', __('Monthly digest'), [
                    'icon' => 'fas fa-calendar-days',
                    'col' => 'col-md-4',
                    'note' => __('The same summary, once a month.'),
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
                <?= $this->Form->label('current_password', __('Your current password'), ['class' => 'form-label fw-semibold']) ?>
                <div class="row">
                    <div class="col-md-6">
                        <?= $this->Form->password('current_password', [
                            'class' => 'form-control',
                            'id' => 'profileCurrentPassword',
                            'autocomplete' => 'current-password',
                            'value' => '',
                        ]) ?>
                    </div>
                </div>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('This instance asks you to confirm your identity before saving your profile.'),
                ]) ?>
            </div>
        <?php endif; ?>

    </div>
</div>

<?= $this->element('genericElementsBS5/Forms/modal_footer', [
    'bleed' => true,
    'isEdit' => true,
    'meta' => [['label' => __('User'), 'id' => $id]],
    'submit' => ['label' => __('Save changes'), 'icon' => 'fas fa-check'],
]) ?>

<?= $this->Form->end() ?>

<script>
(function () {
    var form = document.getElementById('UserEditForm');
    if (!form) return;

    /* initPgpKeyLookup() lives in mispOvermind.js, which the layout loads at the
     * end of the body — after this script on a full-page render. openModal()
     * already calls it for the modal path, so wait for the document either way;
     * it is idempotent, so calling it twice is free. */
    function boot() {
        if (typeof initPgpKeyLookup === 'function') { initPgpKeyLookup(form); }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    // ── Toggle (password) ─────────────────────────────────────────
    var enablePw = document.getElementById('profileEnablePassword');
    var pwFields = document.getElementById('profilePasswordFields');
    function togglePw() {
        if (pwFields) { pwFields.classList.toggle('d-none', !(enablePw && enablePw.checked)); }
    }
    if (enablePw) { enablePw.addEventListener('change', togglePw); }
    togglePw();

    // ── Real-time password validation ─────────────────────────────
    var pw = document.getElementById('profilePassword');
    var cf = document.getElementById('profileConfirm');
    var pwFb = document.getElementById('profilePasswordFeedback');
    var cfFb = document.getElementById('profileConfirmFeedback');
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
})();
</script>
