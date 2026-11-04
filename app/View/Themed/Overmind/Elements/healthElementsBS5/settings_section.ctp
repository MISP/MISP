<?php
/**
 * One section of settings: a card with its table of rows.
 *
 * Params:
 *  - section array  a ServerSettingGroups section (with `uid` and `errorsByLevel`)
 *  - tiered  bool   hide advanced and deprecated rows until asked for
 *  - title   string optional replacement for the section title
 */

App::uses('ServerSettingGroups', 'Tools');

$levels = ServerSettingGroups::levels();
$tiered = !empty($tiered);
$hiddenCount = 0;
if ($tiered) {
    foreach ($section['settings'] as $setting) {
        if (in_array(ServerSettingGroups::tier($setting), array('advanced', 'deprecated'), true)) {
            $hiddenCount++;
        }
    }
}
$rowPrefix = preg_replace('/[^A-Za-z0-9_-]/', '', $section['uid']);
?>
<div class="card shadow-sm mb-3 ss-section<?= $tiered && $hiddenCount === count($section['settings']) ? ' d-none' : '' ?>"
     data-ss-section
     style="--ss-accent: <?= h($section['accent']) ?>;">
    <div class="card-header ss-section-header" style="cursor: default;">
        <span class="ss-section-icon"><i class="fas fa-<?= h($section['icon']) ?>"></i></span>
        <div class="flex-grow-1 min-w-0">
            <div class="fw-semibold"><?= h(isset($title) ? $title : $section['title']) ?></div>
            <div class="text-muted" style="font-size:.78rem;"><?= h($section['description']) ?></div>
        </div>
        <?php foreach ($section['errorsByLevel'] as $level => $errorCount): ?>
            <?php if (empty($errorCount)) { continue; } ?>
            <span class="ss-prio ss-lvl-<?= (int)$level ?>"
                  title="<?= h(__('%s %s settings incorrectly or not set', $errorCount, $levels[$level]['label'])) ?>">
                <i class="fas fa-<?= h($levels[$level]['icon']) ?>"></i>
                <?= h($errorCount) ?>
            </span>
        <?php endforeach; ?>
    </div>

    <?php if (!empty($section['errorsByLevel'][0])): ?>
        <div class="ss-section-alert">
            <i class="fas fa-triangle-exclamation me-1"></i>
            <?= __('This section reports some potential critical misconfigurations.') ?>
        </div>
    <?php endif; ?>

    <div class="table-responsive">
        <table class="table table-sm align-middle ss-table mb-0">
            <thead>
                <tr>
                    <th class="ss-col-priority"><?= __('Priority') ?></th>
                    <th class="ss-col-setting"><?= __('Setting') ?></th>
                    <th class="ss-col-value"><?= __('Value') ?></th>
                    <th class="ss-col-description"><?= __('Description') ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($section['settings'] as $index => $setting): ?>
                    <?= $this->element('healthElementsBS5/setting_row', array(
                        'setting' => $setting,
                        'k' => $rowPrefix . '-' . $index,
                        'tiered' => $tiered,
                    )) ?>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <?php if ($hiddenCount > 0): ?>
        <div class="ss-advanced-bar" data-ss-advanced-bar>
            <button type="button" class="btn btn-link btn-sm text-decoration-none" data-ss-toggle="advanced">
                <i class="fas fa-eye me-1"></i><?= h(__n('Show %s advanced setting', 'Show %s advanced settings', $hiddenCount, $hiddenCount)) ?>
            </button>
        </div>
    <?php endif; ?>
</div>
