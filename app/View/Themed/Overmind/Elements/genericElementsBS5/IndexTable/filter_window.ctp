<?php
/**
 * The Filters panel of a picker bar, opened by the bar's Filters button
 * (index-filters.js): the bar's toggles, then its pickers in sections.
 *
 * A child's `group` names its section; children without one share a section.
 *
 * @var string $id
 * @var array $items picker, time and value_match children, in bar order
 * @var array $toggles button children
 * @var IndexFilterState $state
 * @var callable $keysOf child => the unprefixed URL keys it sets
 * @var array $activeKeys unprefixed keys of the pickers that have a value
 * @var int $activeCount those, plus the toggles pressed
 * @var string $resetUrl
 * @var array $currentFilters
 * @var string $filterId
 */
$sections = [];
foreach ($items as $child) {
    $sections[(string)($child['group'] ?? '')][] = $child;
}
// A toggle that sets a scope key stays on through Reset, as through Clear all.
$canReset = $resetUrl !== $state->clearUrl(array_keys($state->filters()));
$section = 0;
?>
<div class="ifp-panel" id="<?= h($id) ?>" role="region" aria-label="<?= h(__('Filters')) ?>" hidden>
    <div class="ifp-panel-body">
        <?php if ($toggles): ?>
            <div class="ifp-quicks">
                <?php foreach ($toggles as $child): ?>
                    <?= $this->element('genericElementsBS5/IndexTable/filter_quick', ['child' => $child]) ?>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php foreach ($sections as $group => $children): ?>
            <?php
            $keys = [];
            foreach ($children as $child) {
                $keys = array_merge($keys, $keysOf($child));
            }
            $set = count(array_intersect($activeKeys, $keys));
            if ($group === '') {
                $group = count($sections) === 1 ? __('Filters') : __('Other filters');
            }
            ?>
            <section class="ifp-sec">
                <div class="ifp-sec-label" data-ifp-swap="sec-<?= $section++ ?>"><?= h($group) ?><?php
                    if ($set): ?><span class="badge rounded-pill bg-primary"><?= $set ?></span><?php endif; ?></div>
                <div class="ifp-grid">
                    <?php foreach ($children as $child): ?>
                        <?php if ($child['type'] === 'picker'): ?>
                            <?= $this->element('genericElementsBS5/IndexTable/filter_picker', [
                                'child' => $child,
                                'state' => $state,
                            ]) ?>
                        <?php elseif ($child['type'] === 'time'): ?>
                            <?= $this->element('genericElementsBS5/IndexTable/filter_time', [
                                'child' => $child,
                                'state' => $state,
                            ]) ?>
                        <?php else: ?>
                            <?= $this->element('genericElementsBS5/IndexTable/filter_value_match', [
                                'child' => $child,
                                'value' => urldecode((string)($currentFilters[$child['name']] ?? '')),
                                'inputId' => $filterId . '-value-match',
                                'picker' => true,
                            ]) ?>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>
            </section>
        <?php endforeach; ?>
    </div>

    <div class="ifp-win-foot" data-ifp-swap="win-foot">
        <span class="ifp-win-sum"><?php
            if ($activeCount) {
                echo sprintf(h(__n('%s active filter', '%s active filters', $activeCount)), '<b>' . (int)$activeCount . '</b>');
            } else {
                echo h(__('No filter active'));
            }
        ?></span>
        <?php if ($canReset): ?>
            <a href="<?= h($resetUrl) ?>" class="btn btn-sm btn-outline-secondary" data-ifp-nav data-ifp-reset>
                <i class="fas fa-rotate-left me-1" aria-hidden="true"></i><?= h(__('Reset filters')) ?>
            </a>
        <?php else: ?>
            <span class="btn btn-sm btn-outline-secondary disabled" aria-disabled="true">
                <i class="fas fa-rotate-left me-1" aria-hidden="true"></i><?= h(__('Reset filters')) ?>
            </span>
        <?php endif; ?>
        <button type="button" class="btn btn-sm btn-primary" data-ifp-done><?= h(__('Done')) ?></button>
    </div>
</div>
