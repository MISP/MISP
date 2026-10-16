<?php
/**
 * The Conflict rules pane's primer: what a rule does to the lean, and
 * in which order this profile tries them.
 *
 * @var array $primer AnalystProfileFormTool::escalationPrimer()
 */
$share = sprintf('%d%%', round($primer['supermajority'] * 100));
?>
<div class="sig-pop-body" aria-labelledby="sig-pop-title-escalations">
    <div class="sig-pop-head">
        <div class="sig-pop-titles">
            <p class="sig-pop-title" id="sig-pop-title-escalations"><?=
                h($primer['label']) ?></p>
            <p class="sig-pop-sub"><?= h(__('Read this once; each'
                . ' rule\'s own "How it works" says the rest.')) ?></p>
        </div>
        <button type="button" class="sig-pop-close" data-ap-help-close
                aria-label="<?= h(__('Close')) ?>">
            <i class="fa-solid fa-xmark" aria-hidden="true"></i>
        </button>
    </div>
    <div class="sig-pop-grid">
        <div class="sig-pop-col" data-col="a">
            <h4><?= h(__('Two true facts that disagree')) ?></h4>
            <p><?= h(__('A warninglist calls the value harmless, and several'
                . ' organisations flag it. Both are deliberate judgements.'
                . ' Counting would pick the heavier side and hide the'
                . ' other; a conflict rule names the pair instead.')) ?></p>
            <h4><?= h(__('It can only say contested')) ?></h4>
            <p><?= h(__('When a rule fires, the reading becomes')) ?>
                <span class="pill t-plain"><?= h(__('Contested')) ?></span>
                <?= h(__('and carries the rule\'s sentence naming the two'
                    . ' facts. A rule never makes a value harmful or'
                    . ' harmless, adds no points and leaves the signal'
                    . ' strength alone.')) ?></p>
        </div>
        <div class="sig-pop-col" data-col="b">
            <h4><?= h(__('The order they are tried in')) ?></h4>
            <?php if (!empty($primer['order'])): ?>
                <ol class="sig-pop-order">
                    <?php foreach ($primer['order'] as $i => $rule): ?>
                        <li><span class="sig-pop-step"><?= $i + 1 ?></span>
                            <span><?= h($rule['name']) ?>
                                <span class="sig-pop-id"><?= h($rule['id'])
                                ?></span></span></li>
                    <?php endforeach; ?>
                </ol>
            <?php endif; ?>
            <p><?= h(__('The first ticked rule that fires decides, and the'
                . ' rest are not asked. An unticked rule is skipped.')) ?></p>
            <h4><?= h(__('When none fires')) ?></h4>
            <p><?= h(sprintf(__('A false-positive list makes the value'
                . ' harmless unless a clear majority flags it. Otherwise'
                . ' the organisations decide: %s of the voices on one side'
                . ' settles it, and anything closer reads contested.'),
                $share)) ?></p>
            <p class="sig-pop-note">
                <i class="fa-solid fa-circle-info" aria-hidden="true"></i>
                <span><?= h(__('Unticking a rule does not remove the'
                    . ' contradiction; it lets the next step decide. A'
                    . ' warninglist hit\'s negative points can still contest'
                    . ' the result')) ?>
                    (<?= h(__('Signals')) ?> →
                    <code>lifecycle.warninglist</code>).</span>
            </p>
        </div>
        <div class="sig-pop-col" data-col="c">
            <h4><?= h(__('Try it')) ?></h4>
            <ul class="sig-pop-recipes">
                <li>
                    <span class="want"><?= h(__('See what a rule changes'))
                        ?></span>
                    <span class="do"><?= h(__('Put a value that is on a'
                        . ' warninglist on the bench, untick the rule, and'
                        . ' watch the assessment on the right.')) ?></span>
                </li>
                <li>
                    <span class="want"><?= h(__('Let another rule speak'
                        . ' first')) ?></span>
                    <span class="do"><?= sprintf(h(__('Move its entry up'
                        . ' under %s in the Raw JSON pane: that order is the'
                        . ' order they are tried in.')),
                        '<code>escalations</code>') ?></span>
                </li>
                <li>
                    <span class="want"><?= h(__('Switch a rule off'))
                        ?></span>
                    <span class="do"><?= h(__('Untick its box. Its settings'
                        . ' are kept.')) ?></span>
                </li>
            </ul>
        </div>
    </div>
</div>
