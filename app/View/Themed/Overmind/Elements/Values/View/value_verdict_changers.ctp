<?php
/**
 * What would change this — the falsification card.
 *
 * An assessment that cannot say what would move it is an opinion. Each
 * line names a condition and the axis it would move, so the reader can
 * check the value against it themselves rather than wait for the record
 * to drift.
 *
 * The actions under them are the three ways a reader can supply exactly
 * that evidence.
 *
 * @var array $valueIntelligence
 * @var string $noWrites Why every action here is disabled
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');

$verdict = $valueIntelligence['verdict'];
$changers = $verdict['changers'] ?? array();
$actions = $verdict['changer_actions'] ?? array();
?>
<?php if (!empty($changers)): ?>
    <div class="card shadow-sm mb-3 vp-panel vp-aside"
         style="<?= h(ValueLean::directionStyle(
             $verdict['lean']
         )) ?>">

        <div class="vp-aside-head">
            <i class="fas fa-arrows-turn-to-dots"
               style="color: var(--primary);"></i>
            <span class="vp-aside-title">
                <?= __('What would change this') ?>
            </span>
        </div>

        <div class="p-3 vp-changers">

            <?= $this->element(
                'Values/View/value_verdict_changer_rows',
                array('changers' => $changers)
            ) ?>

            <?php if (!empty($actions)): ?>
                <div class="vp-changer-actions">
                    <?php foreach ($actions as $action): ?>
                        <button type="button"
                                class="vp-changer-action<?=
                                    empty($action['emphasis'])
                                        ? ''
                                        : ' vp-changer-action-strong' ?>
                                       disabled"
                                disabled
                                title="<?= h($noWrites) ?>"
                                style="--vp-action-color: <?=
                                    h($action['colour']) ?>;">
                            <i class="<?= h($action['icon']) ?>"></i>
                            <?= h($action['label']) ?>
                        </button>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

        </div>

    </div>
<?php endif; ?>
