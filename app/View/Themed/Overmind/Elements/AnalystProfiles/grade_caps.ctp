<?php
/**
 * The single-source cap per reporter grade, a tile per grade: its
 * letter and meaning, then the band a lone source of that grade may
 * reach, changed where it is read (inline_value.ctp).
 *
 * @var array $block The `thin_record_clamp_by_grade` fields block
 * @var bool $editable
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');
?>
<?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?>
<ol class="ap-grades is-caps">
    <?php foreach ($block['fields'] as $field): ?>
        <?php $set = $field['value'] !== null && $field['value'] !== ''; ?>
        <li class="ap-grade t-<?= h($field['tone'] ?? 'flat') ?><?= $set ? ' is-changed' : '' ?>"
            data-ap-unit="<?= h(implode('.', $field['path'])) ?>"<?=
            $editable ? ' data-ap-set="' . h(implode('.', $field['path'])) . '"' : '' ?>>
            <div class="ap-grade-h">
                <span class="ap-grade-badge" aria-hidden="true"><?= h($field['badge']) ?></span>
                <label class="ap-grade-m" for="<?= h(AnalystProfileFormTool::fieldId($field['path'])) ?>"><?=
                    h($field['meaning']) ?></label>
            </div>
            <div class="ap-grade-v">
                <span class="ap-grade-x"><?= h(__('up to')) ?></span>
                <?php if ($editable): ?>
                    <?= $this->element('AnalystProfiles/inline_value', array('field' => $field)) ?>
                <?php else: ?>
                    <b><?= h($set ? $field['value'] : __('same as above')) ?></b>
                <?php endif; ?>
            </div>
        </li>
    <?php endforeach; ?>
</ol>
