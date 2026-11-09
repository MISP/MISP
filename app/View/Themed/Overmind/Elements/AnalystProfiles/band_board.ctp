<?php
/**
 * The signal-strength bands: the strip against what the enabled signals
 * can reach, then a tile per band with the thresholds that start it,
 * each changed where it is read (inline_value.ctp).
 *
 * @var array $block The `signal_strength_bands` strip block
 * @var array|null $marks
 * @var bool $editable
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

$fields = array();
foreach ($block['fields'] as $field) {
    $fields[$field['key']] = $field;
}
$number = function ($key) use ($fields) {
    return (int)($fields[$key]['value'] ?? $fields[$key]['default']);
};
$medium = $number('medium');
$high = $number('high');

// One threshold of a band: its words, then its value, changed in place.
$setting = function ($key, $lead) use ($fields, $editable) {
    $field = $fields[$key];
    ob_start();
    ?>
    <div class="ap-band-set"<?= $editable ? ' data-ap-set="' . h(implode('.', $field['path'])) . '"' : '' ?>
         data-ap-unit="<?= h(implode('.', $field['path'])) ?>">
        <label class="ap-band-k" for="<?= h(AnalystProfileFormTool::fieldId($field['path'])) ?>"><?= h($lead) ?></label>
        <?php if ($editable): ?>
            <?= $this->element('AnalystProfiles/inline_value', array('field' => $field, 'unit' => $field['unit'] ?? null)) ?>
        <?php else: ?>
            <b><?= h($field['value'] ?? $field['default']) ?></b> <span class="wb-unit"><?= h($field['unit'] ?? '') ?></span>
        <?php endif; ?>
    </div>
    <?php
    return ob_get_clean();
};
?>
<?= $this->element('AnalystProfiles/block_strip', array(
    'strip' => array('fields' => array()) + $block,
    'marks' => isset($marks) ? $marks : array(),
    'editable' => false,
)) ?>
<div class="ap-bands">
    <section class="ap-band is-low">
        <p class="ap-band-h"><i class="ap-band-sw" aria-hidden="true"></i><?= h(__('Low')) ?></p>
        <p class="ap-band-r"><?= h(sprintf(__('Below %s points'), $medium)) ?></p>
        <p class="ap-band-k ap-band-note"><?= h(__('Where every value starts: nothing to set.')) ?></p>
    </section>
    <section class="ap-band is-medium">
        <p class="ap-band-h"><i class="ap-band-sw" aria-hidden="true"></i><?= h(__('Medium')) ?></p>
        <p class="ap-band-r"><?= h(sprintf(__('%1$s to %2$s points'), $medium, max($medium, $high - 1))) ?></p>
        <?= $setting('medium', __('From')) ?>
    </section>
    <section class="ap-band is-high">
        <p class="ap-band-h"><i class="ap-band-sw" aria-hidden="true"></i><?= h(__('High')) ?></p>
        <p class="ap-band-r"><?= h(sprintf(__('%s points or more'), $high)) ?></p>
        <?= $setting('high', __('From')) ?>
        <?= $setting('signal_strength_high_min_signals', __('With at least')) ?>
    </section>
</div>
