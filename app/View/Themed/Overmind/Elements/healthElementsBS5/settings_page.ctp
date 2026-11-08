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
$toggles = array(
    array('key' => 'problems', 'label' => __('Only problems'), 'icon' => 'fas fa-triangle-exclamation', 'count' => $errorCount),
    array('key' => 'modified', 'label' => __('Only modified'), 'icon' => 'fas fa-pen', 'count' => $modifiedCount),
);
if ($tiered && $hiddenCount > 0) {
    $toggles[] = array(
        'key' => 'advanced', 'label' => __('Show advanced settings'), 'icon' => 'fas fa-eye', 'count' => $hiddenCount,
        'title' => __('Settings that rarely need changing, and deprecated ones that are no longer used.'),
    );
}
?>
<div class="ss-settings" data-ss-settings<?= $tiered ? ' data-ss-tiered' : '' ?>>
    <?= $this->element('healthElementsBS5/settings_filter_bar', array(
        'search' => array(
            'attr' => 'data-ss-filter',
            'label' => __('Filter the settings of this page'),
            'placeholder' => __('Search settings by name, value or description'),
        ),
        'toggles' => $toggles,
        'toggleAttr' => 'data-ss-toggle',
    )) ?>

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
