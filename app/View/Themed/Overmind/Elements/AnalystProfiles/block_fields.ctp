<?php
/**
 * A labelled group of settings.
 *
 * One sentence visible per field and the rest behind an `i`: the pane
 * is where somebody changes a number, and a paragraph above every box
 * is a paragraph nobody reads twice.
 *
 * @var array $block
 * @var bool $editable
 */
?>
<?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?>

<div class="wb-fields<?= ($block['layout'] ?? '') === 'dense'
    ? ' is-dense' : '' ?>">
    <?php foreach ($block['fields'] as $field): ?>
        <?php
        /*
         * `help` is split at the first sentence: the rest is a tooltip.
         * Splitting here rather than in the tool keeps the whole
         * sentence in the API's answer, where a reader has room for it.
         */
        $help = isset($field['help']) ? trim($field['help']) : '';
        $rest = '';
        if ($help !== '' && preg_match('/^(.+?[.!?])\s+(.*)$/s', $help, $m)) {
            $help = $m[1];
            $rest = $m[2];
        }
        ?>
        <div class="wb-field">
            <label for="<?= h(AnalystProfileFormTool::fieldId($field['path'])) ?>">
                <?= h($field['label']) ?>
                <?php
                /*
                 * A setting nothing reads yet, marked where the eye
                 * lands rather than only in the sentence underneath.
                 * `inert` was declared on the field and read by
                 * nothing, so the reuse window looked exactly like the
                 * settings around it that do something — and a box
                 * holding `24` that governs nothing is worse than an
                 * absent one, because it reads as a decision somebody
                 * made.
                 */
                ?>
                <?php if (!empty($field['inert'])): ?>
                    <?php
                    /*
                     * `t-off` and not `t-missing`: the red one is for
                     * a module this instance does not have, which is a
                     * problem. A window that governs nothing yet is
                     * not a problem, it is a fact.
                     */
                    ?>
                    <span class="pill t-off"><?= h(
                        isset($field['inert_note'])
                            ? $field['inert_note']
                            : __('not used yet')) ?></span>
                <?php endif; ?>
            </label>
            <div class="wb-inline">
                <?= $this->element('AnalystProfiles/field', array(
                    'field' => $field,
                    'editable' => $editable,
                )) ?>
                <?php if (!empty($field['unit'])): ?>
                    <span class="wb-unit"><?= h($field['unit']) ?></span>
                <?php endif; ?>
            </div>
            <?php if ($help !== ''): ?>
                <p class="help">
                    <?= h($help) ?>
                    <?php if ($rest !== ''): ?>
                        <a href="#" class="wb-i" onclick="return false;"
                           title="<?= h($rest) ?>">i</a>
                    <?php endif; ?>
                </p>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
