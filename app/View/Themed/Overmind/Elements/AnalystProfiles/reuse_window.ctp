<?php
/**
 * How long a module's answer is reused, as what happens to it: the
 * module answers, everyone in the organisation is shown that answer for
 * the window, then it is no longer reused. Under the steps, a slider
 * from one hour to a day, and Custom past it for any whole number of
 * hours; a value is saved when the slider is let go or the box is left
 * (analyst-profile-settings.js).
 *
 * @var array $block The enrichment section's `max_age_hours` block
 * @var bool $editable
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

$field = $block['fields'][0];
$hours = $field['value'] ?? $field['default'] ?? 24;
$hours = max(1, (int)$hours);
$custom = $hours > 24;

// The page redraws these as the slider moves, from the same templates.
$say = function ($hours) {
    $text = sprintf(__n('%s hour', '%s hours', $hours), $hours);
    if ($hours > 24) {
        $days = round($hours / 24, 1);
        $text .= ' · ' . sprintf(__n('%s day', '%s days', (int)ceil($days)),
            $days == (int)$days ? (int)$days : $days);
    }
    return $text;
};
$id = AnalystProfileFormTool::fieldId($field['path']);
$ticks = array(1, 6, 12, 18, 24);
?>
<?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?>
<div class="ap-reuse<?= $custom ? ' is-custom' : '' ?>" data-ap-reuse
     data-hour="<?= h(__('%s hour')) ?>" data-hours="<?= h(__('%s hours')) ?>"
     data-day="<?= h(__('%s day')) ?>" data-days="<?= h(__('%s days')) ?>"
     data-kept="<?= h(__('Kept for %s')) ?>">
    <ol class="ap-reuse-steps">
        <li>
            <span class="ap-reuse-n">1</span>
            <span class="ap-reuse-t">
                <b><?= h(__('A module answers')) ?></b>
                <span><?= h(__('About a value, when you press Run or when it is set to run on its own.')) ?></span>
            </span>
        </li>
        <li class="is-kept">
            <span class="ap-reuse-n">2</span>
            <span class="ap-reuse-t">
                <b data-ap-reuse-kept><?= h(sprintf(__('Kept for %s'), $say($hours))) ?></b>
                <span><?= h(__('Everyone in your organisation is shown that answer instead of the module being asked again.')) ?></span>
            </span>
        </li>
        <li class="is-end">
            <span class="ap-reuse-n">3</span>
            <span class="ap-reuse-t">
                <b><?= h(__('Then no longer reused')) ?></b>
                <span><?= h(__('The next answer is a new question to the module.')) ?></span>
            </span>
        </li>
    </ol>

    <?php if ($editable): ?>
        <div class="wb-field ap-reuse-unit" data-ap-unit="<?= h(implode('.', $field['path'])) ?>">
            <div class="ap-reuse-head">
                <label for="<?= h($id) ?>-range"><?= h($field['label']) ?></label>
                <span class="ap-reuse-value" data-ap-reuse-value><?= h($say($hours)) ?></span>
            </div>
            <div class="ap-reuse-row">
                <div class="ap-reuse-track">
                    <input type="range" class="ap-reuse-range" id="<?= h($id) ?>-range"
                           min="1" max="24" step="1" value="<?= h(min($hours, 24)) ?>"
                           style="--ratio: <?= h((min($hours, 24) - 1) / 23) ?>"
                           data-ap-reuse-range>
                    <div class="ap-reuse-ticks" aria-hidden="true">
                        <?php foreach ($ticks as $tick): ?>
                            <span style="--at: <?= h(($tick - 1) / 23) ?>"><?=
                                h(sprintf(__('%s h'), $tick)) ?></span>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php // Past a day: any whole number of hours, typed. ?>
                <button type="button" class="ap-reuse-more" data-ap-reuse-toggle
                        aria-pressed="<?= $custom ? 'true' : 'false' ?>"><?= h(__('Custom')) ?></button>
            </div>
            <div class="ap-reuse-custom" data-ap-reuse-custom<?= $custom ? '' : ' hidden' ?>>
                <label for="<?= h($id) ?>"><?= h(__('Custom duration')) ?></label>
                <input type="number" class="form-control form-control-sm num" id="<?= h($id) ?>"
                       name="<?= h(AnalystProfileFormTool::fieldName($field['path'])) ?>"
                       min="1" step="1" required value="<?= h($hours) ?>"
                       data-ap-field="1" data-ap-was="<?= h($field['value'] === null ? '' : $hours) ?>"
                       data-ap-reuse-from="<?= h($hours) ?>" data-ap-reuse-hours>
                <span class="wb-unit"><?= h(__('hours')) ?></span>
            </div>
        </div>
    <?php endif; ?>

    <p class="ap-reuse-foot">
        <i class="fas fa-play" aria-hidden="true"></i>
        <?= h(__('It bounds only what happens on its own: pressing Run always asks again.')) ?>
    </p>
</div>
