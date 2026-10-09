<?php
/**
 * The settings of one destination: a filter bar and one card per section.
 *
 * Advanced and deprecated settings are hidden until the Advanced toggle is
 * on; searching, or filtering on problems or modified settings, reaches
 * every row regardless.
 *
 * Params:
 *  - sections array  the destination's sections (ServerSettingGroups::byDestination())
 *  - tiered   bool   apply the advanced/deprecated hiding
 *  - grouped  array  optional [destination => sections] rendered with a heading each (All settings)
 *  - intro    string optional HTML shown between the filter bar and the sections (never filtered)
 */

App::uses('ServerSettingGroups', 'Tools');

$tiered = !empty($tiered);
$groups = isset($grouped) ? $grouped : array('' => $sections);

$hiddenCount = 0;
$modifiedCount = 0;
$errorCount = 0;
foreach ($groups as $groupSections) {
    foreach ($groupSections as $section) {
        foreach ($section['settings'] as $setting) {
            if (in_array(ServerSettingGroups::tier($setting), array('advanced', 'deprecated'), true)) {
                $hiddenCount++;
            }
            if (!empty($setting['modified'])) {
                $modifiedCount++;
            }
            if (ServerSettingGroups::inError($setting)) {
                $errorCount++;
            }
        }
    }
}
$panelId = 'ssFilters' . dechex(mt_rand());
?>
<div class="ss-settings" data-ss-settings<?= $tiered ? ' data-ss-tiered' : '' ?>>
    <?php // Same bar as the indexes (IndexTable/filter_bar), filtering client-side. ?>
    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <div class="d-flex flex-wrap gap-2 align-items-center">
                <div class="flex-grow-1" style="max-width: 600px">
                    <div class="input-group">
                        <input class="form-control" type="search" data-ss-filter autocomplete="off"
                               aria-label="<?= h(__('Filter the settings of this page')) ?>"
                               placeholder="<?= h(__('Search settings by name, value or description')) ?>">
                        <button class="btn btn-primary" type="button" data-ss-filter-apply
                                aria-label="<?= h(__('Search')) ?>">
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                </div>
                <button type="button" class="btn btn-outline-primary flex-shrink-0" data-ss-toggle="problems" aria-pressed="false">
                    <i class="fas fa-triangle-exclamation me-1"></i><?= __('Only problems') ?>
                    <span class="badge bg-secondary ms-1"><?= h($errorCount) ?></span>
                </button>
                <button type="button" class="btn btn-outline-primary flex-shrink-0" data-ss-toggle="modified" aria-pressed="false">
                    <i class="fas fa-pen me-1"></i><?= __('Only modified') ?>
                    <span class="badge bg-secondary ms-1"><?= h($modifiedCount) ?></span>
                </button>
                <?php if ($tiered && $hiddenCount > 0): ?>
                    <?= $this->element('genericElementsBS5/IndexTable/filter_toggle', array(
                        'target' => $panelId,
                        'count' => 0,
                        'open' => false,
                    )) ?>
                <?php endif; ?>
            </div>

            <?php if ($tiered && $hiddenCount > 0): ?>
                <div class="collapse" id="<?= h($panelId) ?>">
                    <hr>
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" role="switch"
                               id="<?= h($panelId) ?>-advanced" data-ss-advanced-switch>
                        <label class="form-check-label fw-semibold" for="<?= h($panelId) ?>-advanced">
                            <?= h(__n('Show %s advanced setting', 'Show %s advanced settings', $hiddenCount, $hiddenCount)) ?>
                        </label>
                        <div class="form-text"><?= __('Settings that rarely need changing, and deprecated ones that are no longer used.') ?></div>
                    </div>
                </div>
            <?php endif; ?>

            <div class="mt-2 d-none align-items-center flex-wrap gap-2" data-ss-active>
                <strong class="me-1"><?= __('Active filters') ?>:</strong>
                <span class="d-flex flex-wrap gap-2" data-ss-chips></span>
                <button type="button" class="btn btn-sm btn-outline-danger ms-auto" data-ss-clear>
                    <i class="fas fa-times"></i>
                    <?= __('Clear all') ?>
                </button>
            </div>
        </div>
    </div>

    <?= isset($intro) ? $intro : '' ?>

    <?php foreach ($groups as $groupId => $groupSections): ?>
        <div data-ss-group>
        <?php if ($groupId !== '' && !empty($groupSections)): ?>
            <?php $groupDefinition = $destinations[$groupId]; ?>
            <div class="ss-group-heading">
                <a href="<?= $baseurl ?>/servers/serverSettings/<?= h($groupId) ?>" data-ss-nav="<?= h($groupId) ?>"
                   class="text-decoration-none text-body">
                    <i class="fas fa-<?= h($groupDefinition['icon']) ?> fa-fw me-1" style="color: <?= h($groupDefinition['accent']) ?>;"></i>
                    <?= h($groupDefinition['title']) ?>
                </a>
            </div>
        <?php endif; ?>
        <?php foreach ($groupSections as $section): ?>
            <?= $this->element('healthElementsBS5/settings_section', array(
                'section' => $section,
                'tiered' => $tiered,
            )) ?>
        <?php endforeach; ?>
        </div>
    <?php endforeach; ?>

    <?php if (empty($groups) || (count($groups) === 1 && empty(reset($groups)))): ?>
        <div class="card shadow-sm"><div class="card-body text-center text-muted py-5">
            <?= __('This page has no settings on this instance.') ?>
        </div></div>
    <?php endif; ?>

    <div class="card shadow-sm d-none" data-ss-no-result>
        <div class="card-body d-flex flex-column align-items-center text-center text-muted py-5">
            <i class="fas fa-magnifying-glass fa-2x mb-3 opacity-50"></i>
            <?= __('No setting matches the active filters.') ?>
        </div>
    </div>
</div>
