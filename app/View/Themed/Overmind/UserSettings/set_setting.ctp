<?php

$presetUserId = $this->request->data['UserSetting']['user_id'] ?? null;
$userDisabled = count($users) === 1;
$settingDisabled = (bool)$setting;
$settingDescriptions = $settingDescriptions ?? [];

$formUrl = $baseurl . '/user_settings/setSetting';
if (!empty($presetUserId)) {
    $formUrl .= '/' . rawurlencode($presetUserId);
    if (!empty($setting)) {
        $formUrl .= '/' . rawurlencode($setting);
    }
}

$settingOptions = array_combine(array_keys($validSettings), array_keys($validSettings));
$initialSetting = $setting ?: '';
$hasValueSelect = !empty($validSettings[$initialSetting]['options']);
$hasJsonValue = $initialSetting !== '' && !$hasValueSelect;

// Card glyph and gloss per option of the settings that take a fixed set of values.
$choiceMeta = [
    'ui_theme' => [
        'Default' => ['icon' => 'fas fa-desktop', 'sub' => __('The classic MISP interface')],
        'Overmind' => ['icon' => 'fas fa-wand-magic-sparkles', 'sub' => __('The Bootstrap 5 interface')],
        'UiBeta' => ['icon' => 'fas fa-flask', 'sub' => __('Interface features in beta')],
        'EventTest' => ['icon' => 'fas fa-vial', 'sub' => __('Event view test theme')],
    ],
    'dashboard_theme' => [
        'auto' => ['icon' => 'fas fa-circle-half-stroke', 'sub' => __('Follow the browser')],
        'light' => ['icon' => 'fas fa-sun', 'sub' => __('Always light')],
        'dark' => ['icon' => 'fas fa-moon', 'sub' => __('Always dark')],
    ],
    'event_template_user_form_mode' => [
        'all' => ['icon' => 'fas fa-list', 'sub' => __('Every step at once')],
        'wizard' => ['icon' => 'fas fa-list-ol', 'sub' => __('One step at a time')],
    ],
];
// In edit mode only the setting being edited can be picked, so only its group is drawn.
$choiceSettings = array_filter($validSettings, function ($config, $name) use ($setting) {
    return !empty($config['options']) && (empty($setting) || $name === $setting);
}, ARRAY_FILTER_USE_BOTH);

echo $this->Form->create('UserSetting', [
    'url' => $formUrl,
    'novalidate' => true,
    'class' => 'm-0',
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('User settings'),
    'title' => $settingDisabled ? __('Edit user setting') : __('Set user setting'),
    'description' => __('Store a per-user preference (dashboard, homepage, alert filters, UI theme…).'),
    'icon' => 'fas fa-sliders',
    'isEdit' => $settingDisabled,
]) ?>

<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <div class="row g-3">
            <div class="col-md-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('User'),
                    'for' => 'UserSettingUserId',
                ]) ?>
                <?= $this->Form->select('user_id', $users, [
                    'id' => 'UserSettingUserId',
                    'class' => 'form-select' . ($userDisabled ? '' : ' tom-select'),
                    'disabled' => $userDisabled,
                    'empty' => true,
                ]) ?>
                <?php if ($userDisabled): ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'icon' => 'fas fa-lock mt-1',
                        'text' => __('You may only manage your own settings.'),
                    ]) ?>
                <?php endif; ?>
            </div>

            <div class="col-md-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Setting'),
                    'for' => 'UserSettingSetting',
                ]) ?>
                <?= $this->Form->select('setting', $settingOptions, [
                    'id' => 'UserSettingSetting',
                    'class' => 'form-select font-monospace' . ($settingDisabled ? '' : ' tom-select'),
                    'default' => $setting,
                    'disabled' => $settingDisabled,
                    'empty' => true,
                ]) ?>
                <?php if ($settingDisabled): ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'icon' => 'fas fa-lock mt-1',
                        'text' => __('The setting cannot be changed while editing an existing entry.'),
                    ]) ?>
                <?php endif; ?>
            </div>

            <div class="col-12<?= empty($settingDescriptions[$initialSetting]) ? ' d-none' : '' ?>" id="UserSettingDescription">
                <div class="d-flex align-items-start gap-2 p-2 px-3 rounded-2 border bg-body-tertiary small">
                    <i class="fas fa-circle-info text-primary mt-1" aria-hidden="true"></i>
                    <span class="text-body-secondary" data-description-text><?= h($settingDescriptions[$initialSetting] ?? '') ?></span>
                </div>
            </div>
        </div>

        <?php
        /* Only the settings with no `options` land here, and every one of them
         * validates as JSON — a constrained setting gets the choice cards below. */
        ?>
        <div class="us-value-wrap<?= $hasJsonValue ? '' : ' d-none' ?>">
            <?= $this->element('genericElementsBS5/Forms/json_field', [
                'field' => 'value',
                'label' => __('Value'),
                'id' => 'UserSettingValue',
                'rows' => 6,
                'minHeight' => '150px',
            ]) ?>
        </div>

        <div class="us-value-select-wrap<?= $hasValueSelect ? '' : ' d-none' ?>">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Value'),
            ]) ?>
            <?php foreach ($choiceSettings as $choiceSetting => $choiceConfig):
                $cards = [];
                foreach ($choiceConfig['options'] as $option) {
                    $cards[] = [
                        'value' => $option,
                        'title' => $option,
                        'icon' => $choiceMeta[$choiceSetting][$option]['icon'] ?? 'fas fa-circle-dot',
                        'sub' => $choiceMeta[$choiceSetting][$option]['sub'] ?? null,
                    ];
                }
            ?>
                <div class="<?= $choiceSetting === $initialSetting ? '' : 'd-none' ?>" data-setting-choices="<?= h($choiceSetting) ?>">
                    <?= $this->element('genericElementsBS5/Forms/choice_cards', [
                        'field' => 'value_select',
                        'id' => 'UserSettingValueSelect-' . $choiceSetting,
                        'options' => $cards,
                        'value' => ($choiceSetting === $setting && isset($current_setting) && !is_array($current_setting))
                            ? $current_setting
                            : null,
                        'ariaLabel' => $choiceSetting,
                    ]) ?>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="us-example-wrap<?= $hasJsonValue ? '' : ' d-none' ?>">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Example'),
                'accent' => 'secondary',
            ]) ?>
            <div class="ov-copy-target position-relative border rounded-2 bg-body-tertiary focus-ring"
                 role="button" tabindex="0"
                 title="<?= h(__('Click to copy')) ?>"
                 data-copy-msg="<?= h(__('Example copied to clipboard')) ?>">
                <i class="far fa-copy position-absolute top-0 end-0 m-2 text-body-secondary" aria-hidden="true"></i>
                <pre id="UserSettingExample" class="mb-0 p-2 pe-5 small overflow-auto text-body"></pre>
            </div>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $settingDisabled,
        'hint' => __('The value is checked against the setting before it is saved.'),
        'submit' => ['label' => $settingDisabled ? __('Save Changes') : __('Set setting')],
    ]) ?>
</div>

<?= $this->Form->end(); ?>

<script type="application/json" id="UserSettingConfig"><?= json_encode([
    'settings' => $validSettings,
    'descriptions' => $settingDescriptions,
], JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP) ?></script>

<script>
(function () {
    var root = document.getElementById('mainModalBody') || document;
    var config = JSON.parse(root.querySelector('#UserSettingConfig').textContent);
    var validSettings = config.settings;
    var descriptions = config.descriptions;

    var userSel         = root.querySelector('#UserSettingUserId');
    var settingSel      = root.querySelector('#UserSettingSetting');
    var valueField      = root.querySelector('#UserSettingValue');
    var choiceGroups    = root.querySelectorAll('[data-setting-choices]');
    var valueWrap       = root.querySelector('.us-value-wrap');
    var valueSelectWrap = root.querySelector('.us-value-select-wrap');
    var exampleWrap     = root.querySelector('.us-example-wrap');
    var exampleEl       = root.querySelector('#UserSettingExample');
    var exampleBox      = exampleEl ? exampleEl.parentNode : null;
    var descriptionWrap = root.querySelector('#UserSettingDescription');

    if (!settingSel) { return; }

    function choiceSelect(setting) {
        var group = root.querySelector('[data-setting-choices="' + setting + '"]');
        return group ? group.querySelector('select') : null;
    }

    function refreshSetting() {
        var setting = settingSel.value;
        var cfg = validSettings[setting] || null;

        var description = cfg ? (descriptions[setting] || '') : '';
        if (descriptionWrap) {
            descriptionWrap.classList.toggle('d-none', description === '');
            descriptionWrap.querySelector('[data-description-text]').textContent = description;
        }

        if (exampleEl && cfg) {
            exampleEl.textContent = typeof cfg.placeholder === 'string'
                ? cfg.placeholder
                : JSON.stringify(cfg.placeholder, undefined, 4);
        }

        // Only the active group posts value_select: a disabled select is not submitted.
        var constrained = !!(cfg && cfg.options);
        Array.prototype.forEach.call(choiceGroups, function (group) {
            var active = group.dataset.settingChoices === setting;
            group.classList.toggle('d-none', !active);
            group.querySelector('select').disabled = !active;
        });
        if (valueSelectWrap) { valueSelectWrap.classList.toggle('d-none', !constrained); }
        if (valueWrap)       { valueWrap.classList.toggle('d-none', !cfg || constrained); }
        if (exampleWrap)     { exampleWrap.classList.toggle('d-none', !cfg || constrained); }
    }

    function loadValue() {
        var userId  = userSel ? userSel.value : '';
        var setting = settingSel.value;
        if (!setting) { return; }

        fetch(baseurl + '/user_settings/getSetting/' + encodeURIComponent(userId) + '/' + encodeURIComponent(setting) + '.json', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (resp) {
            if (resp.status === 404) {
                if (valueField) { valueField.value = ''; }
                return null;
            }
            if (!resp.ok) { throw new Error('HTTP ' + resp.status); }
            return resp.json();
        }).then(function (data) {
            if (!data || !data.UserSetting) { return; }
            var value = data.UserSetting.value;
            if (valueField) {
                valueField.value = (typeof value === 'object' && value !== null)
                    ? JSON.stringify(value, undefined, 4)
                    : (value === undefined || value === null ? '' : value);
                valueField.dispatchEvent(new Event('input', { bubbles: true }));
            }
            var select = choiceSelect(setting);
            if (select && Array.prototype.some.call(select.options, function (o) { return o.value === value; })) {
                select.value = value;
                select.dispatchEvent(new Event('change', { bubbles: true }));
            }
        }).catch(function () { /* leave the field as-is on transient errors */ });
    }

    function copyExample() {
        copyValueToClipboard(exampleEl.textContent, exampleBox.dataset.copyMsg);
    }
    if (exampleBox) {
        exampleBox.addEventListener('click', copyExample);
        exampleBox.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copyExample(); }
        });
    }

    refreshSetting();
    loadValue();

    settingSel.addEventListener('change', function () { refreshSetting(); loadValue(); });
    if (userSel) { userSel.addEventListener('change', function () { refreshSetting(); loadValue(); }); }

})();
</script>
