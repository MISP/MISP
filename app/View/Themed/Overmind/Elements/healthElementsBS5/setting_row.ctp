<?php
/**
 * One server setting, as a row of a settings table.
 *
 * Rendered by the settings pages and by
 * ServersController::serverSettingsReloadSetting(), which swaps the row in
 * place after an inline edit — hence the DOM id built from `$k` alone: the
 * reload endpoint is handed the very same id the row was created with, plus
 * the variant and destination the row carries in its data attributes.
 *
 * The data-ss-* attributes are what server-settings.js filters on.
 *
 * Params:
 *  - setting             array  a single entry of Server::serverSettingsRead()
 *  - k                   string stable row identifier (also the `id` of the edit URLs)
 *  - variant             string standard (default) | essential (label + value only)
 *  - tiered              bool   hide advanced and deprecated rows until asked for
 *  - rowDestination      string optional destination id, linked under the name
 *  - rowDestinationTitle string its title
 *  - label               string essential variant: what to call the setting (default: its Essentials label)
 */

App::uses('ServerSettingGroups', 'Tools');

if (ServerSettingGroups::isHidden($setting['setting'])) {
    return;
}

$variant = isset($variant) && $variant === 'essential' ? 'essential' : 'standard';
$tiered = !empty($tiered);
$rowDestination = isset($rowDestination) ? (string)$rowDestination : '';
$rowDestinationTitle = isset($rowDestinationTitle) ? (string)$rowDestinationTitle : '';

$levels = ServerSettingGroups::levels();
$level = isset($levels[$setting['level']]) ? (int)$setting['level'] : 3;
$tier = ServerSettingGroups::tier($setting);
$inError = ServerSettingGroups::inError($setting);
$modified = !empty($setting['modified']);

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
// Not set: what the row shows is the default the definition declares, not a stored value.
$unset = isset($setting['errorMessage']) && $setting['errorMessage'] === __('Value not set.');

$flags = array();
if ($modified) {
    $flags[] = array('class' => 'ss-flag-modified', 'text' => __('modified'),
        'title' => __('The current value differs from the default.'));
}
if ($tier === 'advanced' || $tier === 'deprecated') {
    $flags[] = array('class' => 'ss-flag-' . $tier, 'text' => $tier === 'advanced' ? __('advanced') : __('deprecated'),
        'title' => $tier === 'advanced' ? __('Rarely needs changing.') : __('No longer used, can be removed.'));
}
if (!empty($setting['cli_only'])) {
    $flags[] = array('class' => 'text-bg-danger', 'text' => __('CLI only'),
        'title' => __('This setting can only be changed from the command line.'));
}
if (!empty($setting['file_only'])) {
    $flags[] = array('class' => 'text-bg-dark', 'text' => __('File only'),
        'title' => __('For security reasons this setting is always stored in the config file, never in the database.'));
}
if (!empty($setting['redacted'])) {
    $flags[] = array('class' => 'text-bg-warning', 'text' => __('Redacted'),
        'title' => __('The value of this setting is hidden in the UI.'));
}
if (isset($setting['editable']) && !$setting['editable']) {
    $flags[] = array('class' => 'text-bg-secondary', 'text' => __('Read only'),
        'title' => __('This setting cannot be edited from the UI.'));
}

$editable = (!isset($setting['editable']) || $setting['editable']) && empty($setting['cli_only']);
$hidden = $tiered && ($tier === 'advanced' || $tier === 'deprecated');
$essentials = ServerSettingGroups::essentials();
if (!isset($label) || $label === '') {
    $label = isset($essentials[$setting['setting']]) ? $essentials[$setting['setting']] : '';
}
?>
<tr id="setting_row_<?= h($k) ?>"
    class="ss-row<?= $inError ? ' ss-row-error ss-lvl-' . $level : '' ?><?= $hidden ? ' d-none' : '' ?>"
    data-setting-name="<?= h($setting['setting']) ?>"
    data-ss-tier="<?= h($tier) ?>"
    data-ss-error="<?= $inError ? 1 : 0 ?>"
    data-ss-modified="<?= $modified ? 1 : 0 ?>"
    data-ss-variant="<?= h($variant) ?>"
    <?php if ($label !== ''): ?>data-ss-label="<?= h($label) ?>"<?php endif; ?>
    <?php if (!empty($setting['module'])): ?>data-ss-module-row="<?= h($setting['module']) ?>"<?php endif; ?>
    <?php if ($rowDestination !== ''): ?>
        data-ss-dest="<?= h($rowDestination) ?>"
        data-ss-dest-title="<?= h($rowDestinationTitle) ?>"
    <?php endif; ?>>

    <?php if ($variant === 'standard'): ?>
        <td class="ss-col-priority">
            <span class="ss-prio ss-lvl-<?= $level ?>">
                <i class="fas fa-<?= h($levels[$level]['icon']) ?>"></i>
                <?= h($levels[$level]['label']) ?>
            </span>
        </td>
    <?php endif; ?>

    <td class="ss-col-setting">
        <?php if ($variant === 'essential' && $label !== ''): ?>
            <div class="fw-semibold"><?= h($label) ?></div>
        <?php endif; ?>
        <span class="ss-setting-name<?= $variant === 'essential' && $label !== '' ? ' text-muted' : '' ?>"><?= h($setting['setting']) ?></span>
        <?php foreach ($flags as $flag): ?>
            <span class="badge <?= h($flag['class']) ?> ss-posture"
                  title="<?= h($flag['title']) ?>"><?= h($flag['text']) ?></span>
        <?php endforeach; ?>
        <?php if ($rowDestination !== ''): ?>
            <div>
                <a class="ss-dest-link" href="<?= $baseurl ?>/servers/serverSettings/<?= h($rowDestination) ?>#setting=<?= h($setting['setting']) ?>"
                   data-ss-nav="<?= h($rowDestination) ?>" data-ss-nav-setting="<?= h($setting['setting']) ?>">
                    <?= h($rowDestinationTitle) ?> <i class="fas fa-arrow-right fa-xs"></i>
                </a>
            </div>
        <?php endif; ?>
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
            <?php if ($hasValue && $unset): ?>
                <span class="text-muted" title="<?= h(__('Not set: the default applies.')) ?>"><?= nl2br(h($value)) ?></span>
                <span class="text-muted fst-italic small"><?= __('(default)') ?></span>
            <?php elseif ($hasValue): ?>
                <?= nl2br(h($value)) ?>
            <?php else: ?>
                <span class="text-muted fst-italic"><?= __('not set') ?></span>
            <?php endif; ?>
        </span>
        <?php if ($editable): ?>
            <i class="fas fa-pen ss-edit-hint"></i>
        <?php endif; ?>
        <?php if ($inError && !empty($setting['errorMessage'])): ?>
            <div class="ss-error-msg"><?= h($setting['errorMessage']) ?></div>
        <?php endif; ?>
    </td>

    <?php if ($variant === 'standard'): ?>
        <td class="ss-col-description text-muted"><?= $setting['description'] ?></td>
    <?php endif; ?>
</tr>
