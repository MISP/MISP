<?php
/**
 * One server setting, as a row of the section tables.
 *
 * Rendered both by `healthElementsBS5/settings_sections` (initial render) and
 * by ServersController::serverSettingsReloadSetting(), which swaps the row in
 * place after an inline edit — hence the DOM id built from `$k` alone: the
 * reload endpoint is handed the very same id the row was created with.
 *
 * Params:
 *  - setting  array  a single entry of Server::serverSettingsRead()
 *  - k        mixed  stable row identifier (also the `id` of the edit URLs)
 */

App::uses('ServerSettingGroups', 'Tools');

if (ServerSettingGroups::isHidden($setting['setting'])) {
    return;
}

$levels = ServerSettingGroups::levels();
$level = isset($levels[$setting['level']]) ? (int)$setting['level'] : 3;

$value = $setting['value'];
if ($setting['type'] === 'boolean') {
    $value = $value === true ? 'true' : 'false';
}
if (isset($setting['options'])) {
    $value = empty($setting['options'][$value]) ? null : $setting['options'][$value];
}
if (!empty($setting['redacted'])) {
    $value = '*****';
}
$hasValue = $value !== null && $value !== '';

$posture = array();
if (!empty($setting['cli_only'])) {
    $posture[] = array(
        'class' => 'text-bg-danger',
        'text' => __('CLI only'),
        'title' => __('This setting can only be changed from the command line.'),
    );
}
if (!empty($setting['file_only'])) {
    $posture[] = array(
        'class' => 'text-bg-dark',
        'text' => __('File only'),
        'title' => __('For security reasons this setting is always stored in the config file, never in the database.'),
    );
}
if (!empty($setting['redacted'])) {
    $posture[] = array(
        'class' => 'text-bg-warning',
        'text' => __('Redacted'),
        'title' => __('The value of this setting is hidden in the UI.'),
    );
}
if (isset($setting['editable']) && !$setting['editable']) {
    $posture[] = array(
        'class' => 'text-bg-secondary',
        'text' => __('Read only'),
        'title' => __('This setting cannot be edited from the UI.'),
    );
}

$editable = (!isset($setting['editable']) || $setting['editable']) && empty($setting['cli_only']);
$inError = isset($setting['error']) && $setting['level'] < 3;

/*
 * No search index is emitted: the filter derives it from the row's own text
 * on first use. Shipping a lowercased copy of every description would nearly
 * double the payload, which the Plugin tab (700+ rows) cannot afford.
 */
?>
<tr id="setting_row_<?= h($k) ?>"
    class="ss-row <?= $inError ? 'ss-row-error ss-lvl-' . $level : '' ?>">

    <td class="ss-col-priority">
        <span class="ss-prio ss-lvl-<?= $level ?>">
            <i class="fas fa-<?= h($levels[$level]['icon']) ?>"></i>
            <?= h($levels[$level]['label']) ?>
        </span>
    </td>

    <td class="ss-col-setting">
        <span class="ss-setting-name"><?= h($setting['setting']) ?></span>
        <?php foreach ($posture as $flag): ?>
            <span class="badge <?= h($flag['class']) ?> ss-posture"
                  title="<?= h($flag['title']) ?>"><?= h($flag['text']) ?></span>
        <?php endforeach; ?>
    </td>

    <td class="ss-col-value <?= $editable ? 'ss-editable' : '' ?>"
        id="setting_value_<?= h($k) ?>"
        <?php if ($editable): ?>
            data-setting="<?= h($setting['setting']) ?>"
            data-setting-id="<?= h($k) ?>"
            role="button"
            tabindex="0"
            title="<?= h(__('Click to edit this setting')) ?>"
        <?php endif; ?>>
        <span class="ss-value">
            <?php if ($hasValue): ?>
                <?= nl2br(h($value)) ?>
            <?php else: ?>
                <span class="text-muted fst-italic"><?= __('not set') ?></span>
            <?php endif; ?>
        </span>
        <?php if ($editable): ?>
            <i class="fas fa-pen ss-edit-hint"></i>
        <?php endif; ?>
    </td>

    <td class="ss-col-description text-muted"><?= $setting['description'] ?></td>

    <td class="ss-col-error">
        <?php if (!empty($setting['errorMessage'])): ?>
            <span class="ss-error-msg"><?= h($setting['errorMessage']) ?></span>
        <?php endif; ?>
    </td>
</tr>
