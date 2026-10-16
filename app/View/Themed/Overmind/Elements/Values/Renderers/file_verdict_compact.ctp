<?php
/**
 * How many engines called it, out of how many answered.
 *
 * The ratio is the widget. A bar under it is the only visual that
 * earns its place at this size, because the number a reader reacts to
 * is *what fraction*, and 54/72 and 5/72 are the same width of text.
 *
 * **The colour is the reading, not the fraction.** A middling ratio is
 * deliberately neither: multi-engine services disagree with each other
 * most in exactly that band, and colouring it amber would assert a
 * suspicion the reading refuses to make.
 *
 * @var array $data
 */
$report = $data['headline'];
$mark = $report['reading'] === 'threat'
    ? 'mal'
    : ($report['reading'] === 'benign' ? 'ben' : 'unknown');
$share = $report['engines'] > 0
    ? min(1, $report['detected'] / $report['engines'])
    : 0;
?>
<div class="vp-rw-in vp-rw-fv">
    <div class="vp-rw-verdict vp-rw-v-<?= h($mark) ?>"><?=
        h($report['ratio']) ?></div>
    <div class="vp-rw-sub"><?= h(sprintf(
        __('of %s engines'),
        number_format($report['engines'])
    )) ?></div>
    <div class="vp-rw-bar" role="img" aria-label="<?= h(sprintf(
        __('%1$s of %2$s engines detected this file'),
        $report['detected'],
        $report['engines']
    )) ?>">
        <span class="vp-rw-bar-fill vp-rw-bar-<?= h($mark) ?>"
              style="width: <?= h(round($share * 100, 1)) ?>%"></span>
    </div>
    <?php if ($report['first_submission'] !== null): ?>
        <div class="vp-rw-note"><?= h(sprintf(
            __('first seen %s'),
            date('Y-m-d', $report['first_submission'])
        )) ?></div>
    <?php endif; ?>
</div>
