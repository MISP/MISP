<?php
/**
 * A labelled group of settings, one row each: the question and its one
 * sentence of help on the left, the answer on the right, as the server
 * settings page lays a setting out. A dense group (one per grade, say)
 * is a grid of small tiles instead.
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
        <?php
        // A live block's setting is changed where it is read, a switch excepted.
        $inline = $editable && !empty($block['live']) && ($field['type'] ?? '') !== 'bool';
        ?>
        <div class="wb-field" data-ap-unit="<?= h(implode('.', $field['path'])) ?>"<?=
            $inline ? ' data-ap-set="' . h(implode('.', $field['path'])) . '"' : '' ?>>
            <div class="wb-field-k">
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
            <?php if ($help !== ''): ?>
                <?php
                // The `i` holds on to the last word, so it never wraps alone.
                $cut = $rest === '' ? false : strrpos($help, ' ');
                ?>
                <p class="help"><?php if ($cut === false): ?><?= h($help) ?><?php else: ?><?=
                    h(substr($help, 0, $cut + 1)) ?><span class="text-nowrap"><?= h(substr($help, $cut + 1)) ?> <a href="#"
                    class="wb-i" onclick="return false;" title="<?= h($rest) ?>">i</a></span><?php endif; ?></p>
            <?php endif; ?>
            </div>
            <div class="wb-inline">
                <?php if ($inline): ?>
                    <?= $this->element('AnalystProfiles/inline_value', array(
                        'field' => $field,
                        'unit' => $field['unit'] ?? null,
                    )) ?>
                <?php else: ?>
                    <?= $this->element('AnalystProfiles/field', array(
                        'field' => $field,
                        'editable' => $editable,
                    )) ?>
                    <?php if (!empty($field['unit'])): ?>
                        <span class="wb-unit"><?= h($field['unit']) ?></span>
                    <?php endif; ?>
                <?php endif; ?>
                <?php // What the number does, in words, while it is read. ?>
                <?php if ((!$editable || $inline) && !empty($field['reading'])): ?>
                    <span class="wb-reading"><?= h($field['reading']) ?></span>
                <?php endif; ?>
            </div>
        </div>
    <?php endforeach; ?>
</div>
