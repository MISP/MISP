<?php
/**
 * A module before its answer is on the page: the path the value takes when
 * it runs (the value as a type, answered here or sent outside, the answer
 * kept for the organisation), then where things stand and the button.
 *
 * A kept answer is shown as soon as the module is opened
 * (value-intelligence.js presses Show the answer, which asks nobody), so
 * this is mostly read for a module never asked.
 *
 * @var array $module
 * @var array $service
 * @var bool $canRun
 * @var string $noRun
 * @var string $value
 */
$stored = isset($module['stored']) ? $module['stored'] : null;
$inFlight = $stored !== null && !$stored['held'];
$local = isset($module['locality']) && $module['locality'] === 'local';
$runType = $stored !== null && !$inFlight ? $stored['type'] : $module['type'];
$sends = $module['format'] === 'misp_standard'
    ? __('Sends the attribute row this value sits in, as MISP stores it (misp_standard).')
    : __('Sends this value and its type.');
?>
<div class="vp-e-brief">
    <div class="vp-e-flow">
        <span class="vp-e-flow-node" title="<?= h($sends) ?>">
            <span class="font-monospace vp-e-flow-value"><?= h($value) ?></span>
            <?= h(__('as')) ?> <span class="vp-e-type"><?= h($runType) ?></span>
        </span>
        <i class="fas fa-arrow-right vp-e-flow-arrow" aria-hidden="true"></i>
        <?php if ($local): ?>
            <span class="vp-e-flow-node is-local"><i class="fas fa-house" aria-hidden="true"></i><?= h(__('answered on this instance')) ?></span>
        <?php else: ?>
            <span class="vp-e-flow-node is-out"><i class="fas fa-arrow-up-right-from-square" aria-hidden="true"></i><?= h(__('sent outside this instance')) ?></span>
        <?php endif; ?>
        <i class="fas fa-arrow-right vp-e-flow-arrow" aria-hidden="true"></i>
        <span class="vp-e-flow-node"><i class="fas fa-database" aria-hidden="true"></i><?= h(__('answer kept for your organisation')) ?></span>
        <span class="vp-e-flow-limit"><?= h(sprintf(__('gives up after %d s'), $service['timeout'])) ?></span>
    </div>

    <div class="vp-e-brief-state">
        <?php if ($inFlight): ?>
            <b><?= h(__('Being asked')) ?></b>
            <span><?= h(__('Somebody in your organisation is running it right now. Its answer will be kept and shown here.')) ?></span>
        <?php elseif ($stored !== null): ?>
            <b><?= h(__('Answered')) ?> <?= $this->element('Values/View/value_enrichment_age', array('askedAge' => $stored['age'])) ?></b>
            <span><?= h(sprintf(__('Asked as %s; the answer was kept. Showing it asks nobody anything.'), $stored['type'])) ?></span>
        <?php else: ?>
            <b><?= h(__('Never asked')) ?></b>
            <span><?= h($local
                ? __('Nothing has been sent for this value. This module answers from data on this instance.')
                : __('Nothing has been sent for this value. Running it sends the value to whoever operates the module, which spends the instance\'s quota and tells them somebody is looking.')) ?></span>
        <?php endif; ?>
        <?php if (!empty($module['config'])): ?>
            <span class="vp-e-brief-settings"><?= h(sprintf(__n(
                'It declares %d setting; whether it is required only the run can say.',
                'It declares %d settings; whether any is required only the run can say.',
                count($module['config'])
            ), count($module['config']))) ?></span>
        <?php endif; ?>
    </div>

    <?php if (!$inFlight): ?>
        <div class="vp-e-brief-acts">
            <?php if ($stored !== null): ?>
                <?= $this->element('Values/View/value_enrichment_button', array(
                    'module' => $module,
                    'canRun' => $canRun,
                    'noRun' => $noRun,
                    'label' => __('Show the answer'),
                    'mode' => 'stored',
                    'variant' => 'secondary',
                    'runType' => $stored['type'],
                )) ?>
            <?php endif; ?>
            <?= $this->element('Values/View/value_enrichment_button', array(
                'module' => $module,
                'canRun' => $canRun,
                'noRun' => $noRun,
                'label' => $stored === null ? sprintf(__('Run %s'), $module['name']) : __('Ask again'),
                'variant' => $stored === null ? 'primary' : null,
            )) ?>
        </div>
    <?php endif; ?>
</div>
