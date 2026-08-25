<?php

$presetUserId = $this->request->data['UserSetting']['user_id'] ?? null;
$userDisabled = count($users) === 1;
$settingDisabled = (bool)$setting;

$formUrl = $baseurl . '/user_settings/setSetting';
if (!empty($presetUserId)) {
    $formUrl .= '/' . rawurlencode($presetUserId);
    if (!empty($setting)) {
        $formUrl .= '/' . rawurlencode($setting);
    }
}

$settingOptions = array_combine(array_keys($validSettings), array_keys($validSettings));
$valueSelectOptions = (!empty($setting) && !empty($validSettings[$setting]['options']))
    ? $validSettings[$setting]['options']
    : [];
$hasValueSelect = !empty($valueSelectOptions);

echo $this->Form->create('UserSetting', [
    'url' => $formUrl,
    'novalidate' => true,
    'class' => 'm-0',
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--bs-primary);">
    <div>
        <div class="text-primary text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('User settings') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $settingDisabled ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $settingDisabled ? __('Edit user setting') : __('Set user setting') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Store a per-user preference (dashboard, homepage, alert filters, UI theme…).') ?>
        </p>
    </div>
    <i class="fas fa-sliders text-primary" style="font-size:2rem; opacity:.4;"></i>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="container-fluid px-4 py-4">
    <div class="row g-3">

        <!-- USER -->
        <div class="col-md-6">
            <?= $this->Form->label('user_id', __('User'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->select('user_id', $users, [
                'id' => 'UserSettingUserId',
                'class' => 'form-select' . ($userDisabled ? '' : ' tom-select'),
                'disabled' => $userDisabled,
                'empty' => false,
            ]) ?>
            <?php if ($userDisabled): ?>
                <div class="form-text"><?= __('You may only manage your own settings.') ?></div>
            <?php endif; ?>
        </div>

        <!-- SETTING -->
        <div class="col-md-6">
            <?= $this->Form->label('setting', __('Setting'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->select('setting', $settingOptions, [
                'id' => 'UserSettingSetting',
                'class' => 'form-select' . ($settingDisabled ? '' : ' tom-select'),
                'default' => $setting,
                'disabled' => $settingDisabled,
                'empty' => false,
            ]) ?>
            <?php if ($settingDisabled): ?>
                <div class="form-text"><?= __('The setting cannot be changed while editing an existing entry.') ?></div>
            <?php endif; ?>
        </div>

        <!-- VALUE (free text) -->
        <div class="col-12 us-value-wrap<?= $hasValueSelect ? ' d-none' : '' ?>">
            <?= $this->Form->label('value', __('Value'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->textarea('value', [
                'id' => 'UserSettingValue',
                'class' => 'form-control font-monospace',
                'rows' => 6,
                'required' => false,
            ]) ?>
        </div>

        <!-- VALUE (constrained select) -->
        <div class="col-12 us-value-select-wrap<?= $hasValueSelect ? '' : ' d-none' ?>">
            <?= $this->Form->label('value_select', __('Value'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->select('value_select', $valueSelectOptions, [
                'id' => 'UserSettingValueSelect',
                'class' => 'form-select',
                'default' => isset($current_setting) ? $current_setting : null,
                'empty' => false,
            ]) ?>
        </div>

        <!-- EXAMPLE -->
        <div class="col-12 us-example-wrap<?= $hasValueSelect ? ' d-none' : '' ?>">
            <label class="form-label fw-semibold text-muted mb-1" style="font-size:.75rem;">
                <i class="fas fa-circle-info me-1"></i><?= __('Example value') ?>
            </label>
            <pre id="UserSettingExample"
                 class="bg-body-secondary border rounded p-2 small mb-0"
                 style="white-space:pre-wrap; word-break:break-word;"></pre>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-end align-items-center mt-4 pt-3 gap-2"
         style="border-top:1px solid var(--bs-border-color);">
        <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
            <i class="fas fa-times me-1"></i><?= __('Cancel') ?>
        </button>
        <?= $this->Form->button(
            '<i class="fas fa-check me-1"></i> ' . __('Submit'),
            [
                'class' => 'btn btn-primary btn-sm',
                'escapeTitle' => false,
                'title' => __('Submit'),
                'aria-label' => __('Submit'),
            ]
        ) ?>
    </div>
</div>

<?= $this->Form->end(); ?>

<script>
(function () {
    var root = document.getElementById('mainModalBody') || document;
    var validSettings = <?= json_encode($validSettings, JSON_UNESCAPED_SLASHES); ?>;

    var userSel        = root.querySelector('#UserSettingUserId');
    var settingSel     = root.querySelector('#UserSettingSetting');
    var valueField     = root.querySelector('#UserSettingValue');
    var valueSelect    = root.querySelector('#UserSettingValueSelect');
    var valueWrap      = root.querySelector('.us-value-wrap');
    var valueSelectWrap = root.querySelector('.us-value-select-wrap');
    var exampleWrap    = root.querySelector('.us-example-wrap');
    var exampleEl      = root.querySelector('#UserSettingExample');

    if (!settingSel) { return; }

    function refreshPlaceholder() {
        var setting = settingSel.value;
        var cfg = validSettings[setting];
        if (!cfg) { return; }

        var example = JSON.stringify(cfg.placeholder, undefined, 4);
        if (valueField) { valueField.setAttribute('placeholder', 'Example:\n' + example); }
        if (exampleEl)  { exampleEl.textContent = example; }

        if (cfg.options) {
            // Constrained value → swap the free-text field for a <select>.
            if (valueSelect) {
                valueSelect.innerHTML = '';
                cfg.options.forEach(function (opt) {
                    var o = document.createElement('option');
                    o.value = opt;
                    o.textContent = opt;
                    valueSelect.appendChild(o);
                });
                valueSelect.selectedIndex = 0;
            }
            if (valueSelectWrap) { valueSelectWrap.classList.remove('d-none'); }
            if (valueWrap)       { valueWrap.classList.add('d-none'); }
            if (exampleWrap)     { exampleWrap.classList.add('d-none'); }
        } else {
            // Free-text value → empty the select so it never wins in the model.
            if (valueSelect)     { valueSelect.innerHTML = ''; }
            if (valueSelectWrap) { valueSelectWrap.classList.add('d-none'); }
            if (valueWrap)       { valueWrap.classList.remove('d-none'); }
            if (exampleWrap)     { exampleWrap.classList.remove('d-none'); }
        }
    }

    function loadValue() {
        var userId  = userSel ? userSel.value : '';
        var setting = settingSel.value;
        if (!setting) { return; }

        fetch(baseurl + '/user_settings/getSetting/' + encodeURIComponent(userId) + '/' + encodeURIComponent(setting) + '.json', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (resp) {
            if (resp.status === 404) {
                if (valueField)  { valueField.value = ''; }
                if (valueSelect && valueSelectWrap && !valueSelectWrap.classList.contains('d-none')) {
                    valueSelect.value = '';
                }
                return null;
            }
            if (!resp.ok) { throw new Error('HTTP ' + resp.status); }
            return resp.json();
        }).then(function (data) {
            if (!data || !data.UserSetting) { return; }
            var value = data.UserSetting.value;
            if (typeof value === 'object' && value !== null) {
                if (valueField) { valueField.value = JSON.stringify(value, undefined, 4); }
            } else if (valueField) {
                valueField.value = (value === undefined || value === null) ? '' : value;
            }
            if (valueSelect && valueSelectWrap && !valueSelectWrap.classList.contains('d-none')) {
                valueSelect.value = value;
            }
        }).catch(function () { /* leave the field as-is on transient errors */ });
    }

    refreshPlaceholder();
    loadValue();

    ['change'].forEach(function (evt) {
        settingSel.addEventListener(evt, function () { refreshPlaceholder(); loadValue(); });
        if (userSel) { userSel.addEventListener(evt, function () { refreshPlaceholder(); loadValue(); }); }
    });

    if (valueSelect) {
        valueSelect.addEventListener('change', function () {
            if (valueField) { valueField.value = valueSelect.value; }
        });
    }
})();
</script>
