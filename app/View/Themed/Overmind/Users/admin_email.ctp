<?php
$actionOptions    = [__('Custom message'), __('Welcome message'), __('Reset password')];
$recipientOptions = [__('A single user'), __('All users'), __('All users of the same organisation')];
$recipientsData = [];
foreach ($users as $u) {
    $recipientsData[] = [
        'id'    => (int)$u['User']['id'],
        'email' => $u['User']['email'],
        'orgId' => isset($u['Organisation']['id']) ? (int)$u['Organisation']['id'] : null,
    ];
}
?>

<?php
echo $this->Form->create('User', [
    'url'   => $baseurl . '/admin/users/email',
    'id'    => 'omContactForm',
    'class' => 'm-0',
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-primary"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Users') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-envelope-open-text text-primary" style="font-size:1.25rem;"></i>
            <?= __('Contact users') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Send a message or temporary credentials to one or many users.') ?>
        </p>
    </div>
    <i class="fas fa-envelope text-primary" style="font-size:2rem; opacity:.5;"></i>
</div>

<!-- ── STEP 1: FORM ─────────────────────────────────────────── -->
<div id="omFormStep">
    <div class="container-fluid px-4 py-4">
        <div class="d-flex flex-column gap-4">

            <!-- ACTION -->
            <div>
                <label for="UserAction" class="text-primary fw-bold text-uppercase mb-1" style="font-size:.65rem;">
                    <?= __('Action') ?>
                </label>
                <?= $this->Form->select('action', $actionOptions, [
                    'id'    => 'UserAction',
                    'class' => 'form-select',
                    'div'   => false,
                    'value' => 0,
                ]) ?>
                <div class="form-text">
                    <?= __('A welcome or reset action generates a temporary password for each recipient.') ?>
                </div>
            </div>

            <!-- SUBJECT (custom message only) -->
            <div id="omSubjectField">
                <label for="UserSubject" class="text-primary fw-bold text-uppercase mb-1" style="font-size:.65rem;">
                    <?= __('Subject') ?>
                </label>
                <?= $this->Form->text('subject', [
                    'id'          => 'UserSubject',
                    'class'       => 'form-control',
                    'div'         => false,
                    'placeholder' => __('Email subject'),
                ]) ?>
            </div>

            <!-- RECIPIENT -->
            <div>
                <label for="UserRecipient" class="text-primary fw-bold text-uppercase mb-1" style="font-size:.65rem;">
                    <?= __('Recipients') ?>
                </label>
                <?= $this->Form->select('recipient', $recipientOptions, [
                    'id'    => 'UserRecipient',
                    'class' => 'form-select',
                    'div'   => false,
                    'value' => 0,
                ]) ?>
            </div>

            <!-- SINGLE USER -->
            <div id="omRecipientEmailField">
                <label for="UserRecipientEmailList" class="text-primary fw-bold text-uppercase mb-1" style="font-size:.65rem;">
                    <?= __('Recipient email') ?>
                </label>
                <?= $this->Form->select('recipientEmailList', $recipientEmail, [
                    'id'               => 'UserRecipientEmailList',
                    'class'            => 'form-select tom-select',
                    'div'              => false,
                    'data-placeholder' => __('Select a user'),
                ]) ?>
            </div>

            <!-- ORGANISATION -->
            <div id="omOrgNameField">
                <label for="UserOrgNameList" class="text-primary fw-bold text-uppercase mb-1" style="font-size:.65rem;">
                    <?= __('Recipient organisation') ?>
                </label>
                <?= $this->Form->select('orgNameList', $orgName, [
                    'id'               => 'UserOrgNameList',
                    'class'            => 'form-select tom-select',
                    'div'              => false,
                    'data-placeholder' => __('Select an organisation'),
                ]) ?>
            </div>

            <!-- CUSTOM MESSAGE TOGGLE (welcome / reset only) -->
            <div id="omCustomMessageField" class="form-check">
                <?= $this->Form->checkbox('customMessage', [
                    'id'    => 'UserCustomMessage',
                    'class' => 'form-check-input',
                ]) ?>
                <label for="UserCustomMessage" class="form-check-label">
                    <?= __('Write a custom message') ?>
                </label>
            </div>

            <!-- MESSAGE -->
            <div id="omMessageField">
                <label for="UserMessage" class="text-primary fw-bold text-uppercase mb-1" style="font-size:.65rem;">
                    <?= __('Message') ?>
                </label>
                <?= $this->Form->textarea('message', [
                    'id'          => 'UserMessage',
                    'class'       => 'form-control',
                    'div'         => false,
                    'rows'        => 8,
                    'placeholder' => __('Write your message…'),
                ]) ?>
                <div class="form-text">
                    <?= __('The temporary password is appended automatically when a welcome or reset action is selected.') ?>
                </div>
            </div>

        </div>
    </div>

    <!-- FOOTER (step 1) -->
    <div class="px-4 py-3 d-flex justify-content-end gap-2 border-top">
        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
            <?= __('Discard') ?>
        </button>
        <button type="button" class="btn btn-primary" id="omReviewBtn">
            <i class="fas fa-list-check me-1"></i><?= __('Review & send') ?>
        </button>
    </div>
</div>

<!-- ── STEP 2: CONFIRMATION ─────────────────────────────────── -->
<div id="omConfirmStep" class="d-none">
    <div class="container-fluid px-4 py-4">
        <div id="omConfirmEmpty" class="alert alert-warning d-none mb-0 d-flex align-items-center gap-2">
            <i class="fas fa-triangle-exclamation"></i>
            <span><?= __('No eligible recipient matches this selection.') ?></span>
        </div>
        <div id="omConfirmBody">
            <p class="mb-2">
                <?= __('You are about to send this e-mail to') ?>
                <strong id="omConfirmCount">0</strong>
                <?= __('recipient(s):') ?>
            </p>
            <div id="omConfirmList" class="border rounded"
                 style="max-height:16rem; overflow:auto;"></div>
        </div>
    </div>

    <!-- FOOTER (step 2) -->
    <div class="px-4 py-3 d-flex justify-content-end gap-2 border-top">
        <button type="button" class="btn btn-outline-secondary" id="omBackBtn">
            <i class="fas fa-arrow-left me-1"></i><?= __('Back') ?>
        </button>
        <button type="submit" class="btn btn-primary" id="omSendBtn">
            <i class="fas fa-paper-plane me-1"></i><?= __('Send') ?>
        </button>
    </div>
</div>

<?= $this->Form->end() ?>

<script type="application/json" id="omContactRecipients"><?= json_encode($recipientsData, JSON_HEX_TAG | JSON_HEX_AMP) ?></script>

<script>
(function () {
    var form = document.getElementById('omContactForm');
    if (!form) { return; }

    var actionSel   = document.getElementById('UserAction');
    var recipientSel = document.getElementById('UserRecipient');
    var customMsgChk = document.getElementById('UserCustomMessage');
    var subjectInput = document.getElementById('UserSubject');
    var messageArea  = document.getElementById('UserMessage');
    var emailSel     = document.getElementById('UserRecipientEmailList');
    var orgSel       = document.getElementById('UserOrgNameList');

    var subjectField        = document.getElementById('omSubjectField');
    var recipientEmailField = document.getElementById('omRecipientEmailField');
    var orgNameField        = document.getElementById('omOrgNameField');
    var customMessageField  = document.getElementById('omCustomMessageField');
    var messageField        = document.getElementById('omMessageField');

    var formStep     = document.getElementById('omFormStep');
    var confirmStep  = document.getElementById('omConfirmStep');
    var confirmBody  = document.getElementById('omConfirmBody');
    var confirmEmpty = document.getElementById('omConfirmEmpty');
    var confirmList  = document.getElementById('omConfirmList');
    var confirmCount = document.getElementById('omConfirmCount');
    var reviewBtn    = document.getElementById('omReviewBtn');
    var backBtn      = document.getElementById('omBackBtn');
    var sendBtn      = document.getElementById('omSendBtn');

    var org = <?= json_encode((string)$org, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var subjects = [
        '',
        '[' + org + ' MISP] ' + <?= json_encode(__('New user registration'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>,
        '[' + org + ' MISP] ' + <?= json_encode(__('Password reset'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>
    ];
    var standardTexts = ['', <?= json_encode((string)$newUserText, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>, <?= json_encode((string)$passwordResetText, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>];

    var recipients = [];
    try {
        recipients = JSON.parse(document.getElementById('omContactRecipients').textContent);
    } catch (e) { recipients = []; }

    function setAll() {
        [subjectField, recipientEmailField, orgNameField, customMessageField, messageField]
            .forEach(function (el) { if (el) { el.classList.add('d-none'); } });

        var action = actionSel.value;
        var recip  = recipientSel.value;
        var custom = customMsgChk && customMsgChk.checked;

        if (action === '0' || custom) { messageField.classList.remove('d-none'); }
        if (action === '0') { subjectField.classList.remove('d-none'); }
        else { customMessageField.classList.remove('d-none'); }
        if (recip === '0') { recipientEmailField.classList.remove('d-none'); }
        if (recip === '2') { orgNameField.classList.remove('d-none'); }
    }

    function populateSubject() {
        var i = parseInt(actionSel.value, 10) || 0;
        subjectInput.value = subjects[i] || '';
        messageArea.value  = standardTexts[i] || '';
    }

    function computeRecipients() {
        var recip = recipientSel.value;
        if (recip === '0') {
            var id = parseInt(emailSel.value, 10);
            return recipients.filter(function (r) { return r.id === id; });
        }
        if (recip === '2') {
            var orgId = parseInt(orgSel.value, 10);
            return recipients.filter(function (r) { return r.orgId === orgId; });
        }
        return recipients.slice(); // all users
    }

    function showConfirm() {
        var list = computeRecipients();
        confirmCount.textContent = list.length;
        confirmList.innerHTML = '';
        list.forEach(function (r) {
            var row = document.createElement('div');
            row.className = 'px-3 py-2 border-bottom small';
            row.textContent = r.email;
            confirmList.appendChild(row);
        });

        var empty = list.length === 0;
        confirmEmpty.classList.toggle('d-none', !empty);
        confirmBody.classList.toggle('d-none', empty);
        sendBtn.disabled = empty;

        formStep.classList.add('d-none');
        confirmStep.classList.remove('d-none');
    }

    actionSel.addEventListener('change', function () { populateSubject(); setAll(); });
    recipientSel.addEventListener('change', setAll);
    if (customMsgChk) { customMsgChk.addEventListener('change', setAll); }
    reviewBtn.addEventListener('click', showConfirm);
    backBtn.addEventListener('click', function () {
        confirmStep.classList.add('d-none');
        formStep.classList.remove('d-none');
    });

    populateSubject();
    setAll();
})();
</script>
