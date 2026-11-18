<?php
/**
 * The assessment switch, beside the hover card it governs: the tried
 * value's own readings when there is one, what each reading answers
 * otherwise, and an empty slot while the switch is off. Flipping it
 * saves at once (analyst-profile-settings.js), and the page shows the
 * other state before the save returns.
 *
 * @var array $block
 * @var bool $editable
 * @var array|null $axes The tried value's readings
 * @var string|null $benchValue
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');
App::uses('ValueLean', 'Tools/ValueIntelligence');

$field = $block['fields'][0];
$on = !empty($field['value']);
$axes = isset($axes) ? $axes : null;
$benchValue = isset($benchValue) ? $benchValue : null;

if ($axes !== null) {
    $lean = $axes['lean']['after'];
    $relevance = $axes['relevance']['after'] === null
        ? __('no clock')
        : (($axes['relevance']['label'] ?? '') !== ''
            ? $axes['relevance']['label']
            : $axes['relevance']['after']);
}
?>
<div class="ap-assess<?= $on ? '' : ' is-off' ?>" data-ap-switch-scope>
    <div class="ap-assess-main">
        <p class="wb-h wb-bh"><?= h($block['title']) ?></p>
        <div class="wb-field ap-assess-unit" data-ap-unit="<?= h(implode('.', $field['path'])) ?>">
            <label class="visually-hidden" for="<?= h(AnalystProfileFormTool::fieldId($field['path'])) ?>"><?=
                h($field['label']) ?></label>
            <?php if ($editable): ?>
                <?= $this->element('AnalystProfiles/field', array(
                    'field' => $field,
                    'editable' => true,
                )) ?>
            <?php else: ?>
                <p class="ap-assess-state">
                    <i class="fas fa-<?= $on ? 'eye' : 'eye-slash' ?>" aria-hidden="true"></i>
                    <?= h($on ? $field['on_label'] : $field['off_label']) ?>
                </p>
            <?php endif; ?>
        </div>
        <p class="ap-assess-say is-on-only">
            <?= h(__('Value pages, hover cards and the value worklist show the'
                . ' lean, relevance and signal strength, as in the preview.')) ?>
            <?php if ($editable): ?><?= h(__('Saved as soon as you flip it.')) ?><?php endif; ?>
        </p>
        <p class="ap-assess-say is-off-only">
            <?= h(__('Readers see the evidence only, and the assessment is not'
                . ' computed. The evidence tabs and the REST API are unchanged.')) ?>
        </p>
    </div>

    <figure class="ap-assess-card">
        <figcaption>
            <?php if ($axes !== null): ?>
                <span class="ap-assess-v" title="<?= h($benchValue) ?>"><?= h($benchValue) ?></span>
            <?php endif; ?>
            <span class="ap-assess-eyebrow"><?= h(__('Hover card preview')) ?></span>
        </figcaption>
        <div class="ap-assess-reads is-on-only">
            <?php if ($axes !== null): ?>
                <div class="ap-assess-read is-lean" style="--ap-lean: <?= h(ValueLean::colour($lean))
                    ?>; --ap-lean-ink: <?= h(ValueLean::ink($lean)) ?>">
                    <span class="k"><?= h(__('Lean')) ?></span>
                    <b><i class="<?= h(ValueLean::icon($lean)) ?>" aria-hidden="true"></i><?=
                        h(ValueLean::label($lean)) ?></b>
                </div>
                <div class="ap-assess-read">
                    <span class="k"><?= h(__('Signal strength')) ?></span>
                    <b><span class="num"><?= h($axes['signal_strength']['after']) ?></span>
                        <span class="pill t-plain"><?= h($axes['band']['after']) ?></span></b>
                </div>
                <div class="ap-assess-read">
                    <span class="k"><?= h(__('Relevance')) ?></span>
                    <b><?= h($relevance) ?></b>
                </div>
            <?php else: ?>
                <?php
                // No value tried: what each reading answers, rather than made-up numbers.
                $answers = array(
                    array(__('Lean'), __('what the record asserts')),
                    array(__('Signal strength'), __('how well it is evidenced')),
                    array(__('Relevance'), __('whether it still holds')),
                );
                ?>
                <?php foreach ($answers as $answer): ?>
                    <div class="ap-assess-read is-blank">
                        <span class="k"><?= h($answer[0]) ?></span>
                        <span class="hint"><?= h($answer[1]) ?></span>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
        <div class="ap-assess-none is-off-only">
            <i class="fas fa-eye-slash" aria-hidden="true"></i>
            <?= h(__('No lean, relevance or signal strength')) ?>
        </div>
        <p class="ap-assess-foot">
            <?php if ($axes !== null): ?>
                <?= h(__('The value tried above, read by this profile. The evidence is shown either way.')) ?>
            <?php else: ?>
                <?= h(__('Try a value above to preview its own readings. The evidence is shown either way.')) ?>
            <?php endif; ?>
        </p>
    </figure>
</div>
