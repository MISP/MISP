<?php
/**
 * The Enrichment tab's module list: select-all and Run on top, then "All
 * answers" and one entry per module (its state dot, description, where the
 * value goes, last answer, whether the profile preselected it), then the
 * modules the profile names that an administrator turned off.
 *
 * The checkbox stages a module for Run; the entry itself opens it on the
 * right. value-intelligence.js keeps the dot, the state and the counts.
 *
 * @var array $enrichment
 * @var bool $canRun
 * @var string $noRun
 * @var int $heldCount
 */
$modules = $enrichment['modules'];
$picked = array();
if (!empty($enrichment['profile']['selected'])) {
    foreach ($enrichment['profile']['selected'] as $entry) {
        $picked[$entry['name']] = $entry['type'];
    }
}
$turnedOff = array();
foreach (isset($enrichment['profile']['conditions']) ? $enrichment['profile']['conditions'] : array() as $condition) {
    if ($condition['id'] === 'module.disabled' && !empty($condition['module'])) {
        $turnedOff[] = $condition['module'];
    }
}
$chosen = count($picked);
$heldCount = isset($heldCount) ? (int)$heldCount : 0;
?>
<div class="vp-e-rail">
    <?php // Sticks under the page header while a long answer scrolls by. ?>
    <div class="vp-e-railinner">
    <div class="vp-e-railhead">
        <label class="vp-e-selall">
            <input type="checkbox" class="form-check-input" data-vp-e-select-all
                   <?= $chosen > 0 && $chosen === count($modules) ? 'checked' : '' ?>
                   <?= $canRun ? '' : 'disabled' ?>
                   aria-label="<?= h(__('Select every module')) ?>">
            <span><span data-vp-e-picked><?= h($chosen) ?></span> <?= h(sprintf(__('of %d selected'), count($modules))) ?></span>
        </label>
        <button type="button" class="btn btn-sm <?= $canRun ? 'btn-primary' : 'btn-outline-secondary disabled' ?> vp-e-runsel"
                <?= ($canRun && $chosen > 0) ? '' : 'disabled' ?>
                <?= $canRun ? '' : 'title="' . h($noRun) . '"' ?>
                data-vp-e-run-selected>
            <i class="fas fa-play" data-vp-e-icon aria-hidden="true"></i>
            <span data-vp-e-label><?= h(__('Run')) ?> (<span data-vp-e-runcount><?= h($chosen) ?></span>)</span>
        </button>
    </div>

    <div class="vp-e-railrow vp-e-railrow-all<?= $heldCount > 0 ? ' vp-e-railrow-on' : '' ?>" data-vp-e-row="__all">
        <button type="button" class="vp-e-railbody" data-vp-e-pick="__all" aria-pressed="<?= $heldCount > 0 ? 'true' : 'false' ?>">
            <span class="vp-e-railrow-name">
                <i class="fas fa-layer-group" aria-hidden="true"></i><?= h(__('All answers')) ?>
            </span>
            <span class="vp-e-railrow-foot" data-vp-e-allsub>
                <?= h($heldCount > 0
                    ? sprintf(__n('%s answer', '%s answers', $heldCount), number_format($heldCount))
                    : __('Nothing run yet')) ?>
            </span>
        </button>
    </div>

    <?php foreach ($modules as $module): ?>
        <?php
        $mine = isset($picked[$module['name']]);
        $runType = $mine ? $picked[$module['name']] : $module['type'];
        $local = isset($module['locality']) && $module['locality'] === 'local';
        $stored = isset($module['stored']) ? $module['stored'] : null;
        $inFlight = $stored !== null && !$stored['held'];
        ?>
        <div class="vp-e-railrow" data-vp-e-row="<?= h($module['name']) ?>">
            <label class="vp-e-selbox">
                <input type="checkbox" class="form-check-input"
                       data-vp-e-select="<?= h($module['name']) ?>"
                       data-vp-e-seltype="<?= h($runType) ?>"
                       data-vp-e-external="<?= $local ? '0' : '1' ?>"
                       <?= $mine ? 'checked' : '' ?>
                       <?= $canRun ? '' : 'disabled' ?>
                       aria-label="<?= h(sprintf(__('Select %s'), $module['name'])) ?>">
            </label>
            <button type="button" class="vp-e-railbody" data-vp-e-pick="<?= h($module['name']) ?>" aria-pressed="false">
                <span class="vp-e-railrow-name">
                    <span class="vp-e-dot <?= $stored !== null && !$inFlight ? 'vp-e-dot-ok' : 'vp-e-dot-none' ?>" data-vp-e-dot></span>
                    <span class="vp-e-railrow-label"><?= h($module['name']) ?></span>
                    <span class="vp-e-railrow-n d-none" data-vp-e-count></span>
                </span>
                <?php if (!empty($module['description'])): ?>
                    <span class="vp-e-railrow-desc" title="<?= h($module['description']) ?>"><?= h($module['description']) ?></span>
                <?php endif; ?>
                <span class="vp-e-railrow-foot">
                    <?php if ($local): ?>
                        <span class="vp-e-where is-local" title="<?= h(__('The module answers from data on this instance.')) ?>">
                            <i class="fas fa-house" aria-hidden="true"></i><?= h(__('local')) ?>
                        </span>
                    <?php else: ?>
                        <span class="vp-e-where is-out" title="<?= h(__('Running it sends the value outside this instance.')) ?>">
                            <i class="fas fa-arrow-up-right-from-square" aria-hidden="true"></i><?= h(__('leaves the instance')) ?>
                        </span>
                    <?php endif; ?>
                    <span class="vp-e-railrow-state" data-vp-e-state>
                        <?php if ($inFlight): ?>
                            <?= h(__('being asked')) ?>
                        <?php elseif ($stored !== null): ?>
                            <?= h(__('answered')) ?> <?= $this->element('Values/View/value_enrichment_age', array('askedAge' => $stored['age'])) ?>
                        <?php else: ?>
                            <?= h(__('never asked')) ?>
                        <?php endif; ?>
                    </span>
                    <?php if ($mine): ?>
                        <span class="vp-e-railrow-mine" title="<?= h(__('Preselected by your Analyst Profile. Nothing runs until you press Run.')) ?>"><?= h(__('profile')) ?></span>
                    <?php endif; ?>
                </span>
            </button>
        </div>
    <?php endforeach; ?>

    <?php if (!empty($turnedOff)): ?>
        <div class="vp-e-railoff">
            <i class="fas fa-toggle-off" aria-hidden="true"></i>
            <span><?= h(__('Also in your profile, turned off by an administrator:')) ?>
                <?= implode(', ', array_map(function ($name) {
                    return '<span class="font-monospace">' . h($name) . '</span>';
                }, $turnedOff)) ?></span>
        </div>
    <?php endif; ?>
    </div>
</div>
