<?php
/**
 * An ordered list: the visualisations this profile wants promoted,
 * best first, as tiles in the order the Overview draws them.
 *
 * The fifth block kind, and the first whose **order is the setting**.
 * A map's rows can be drawn in any order without changing what the
 * document means; here the position is the whole of what is being
 * said, so the row carries a hidden input holding its shape id and the
 * position is the input's index. Reordering renumbers the inputs and
 * nothing else moves.
 *
 * A `live` list is edited where it is read: Edit shows the remove
 * buttons and the frame that adds one, and a tile is dragged into
 * place or moved with the arrow keys (analyst-profile-settings.js).
 *
 * Like a map, it **replaces** on save rather than merging: a row the
 * analyst removed posts nothing and a merge cannot tell that from a
 * row the form never drew. `__present` is what says the block was on
 * screen, and a present marker with no rows means *ranked nothing*
 * rather than *unchanged*.
 *
 * @var array $block
 * @var bool $editable
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

$entries = $block['entries'];
$cap = isset($block['cap']) ? (int)$block['cap'] : 0;
$name = AnalystProfileFormTool::fieldName($block['path']);
$live = !empty($block['live']);
$canAdd = $editable && !empty($block['add']['options']);
$descriptions = $block['add']['descriptions'] ?? array();
?>
<?php if ($live): ?>
    <div class="ap-live-head">
        <div class="ap-live-head-t"><?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?></div>
        <div class="ap-live-tools">
            <?php if ($editable): ?>
                <button type="button" class="btn btn-sm btn-outline-primary" data-ap-live-edit>
                    <i class="fas fa-pen me-1" aria-hidden="true"></i><span><?= h(__('Edit')) ?></span>
                </button>
            <?php endif; ?>
        </div>
    </div>
<?php else: ?>
    <?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?>
<?php endif; ?>
<div class="ap-order<?= $live ? ' is-sortable' : '' ?>" data-ap-order
     data-ap-order-name="<?= h($name) ?>"
     data-ap-order-cap="<?= h($cap) ?>"
     data-ap-order-remove-label="<?= h(__('Stop ranking it')) ?>">

    <?php if ($editable): ?>
        <input type="hidden"
               name="<?= h(AnalystProfileFormTool::fieldName(
                   $block['path'], array('__present'))) ?>"
               value="1">
    <?php endif; ?>

    <?php if ($canAdd): ?>
        <div class="ap-order-add ap-map-add" data-ap-order-add>
            <?php if (!empty($block['add']['title'])): ?>
                <p class="ap-map-add-h"><?= h($block['add']['title']) ?></p>
            <?php endif; ?>
            <div class="ap-map-find">
                <label for="<?= h(AnalystProfileFormTool::fieldId(
                    $block['path'], array('add'))) ?>"<?= $live ? ' class="visually-hidden"' : '' ?>>
                    <i class="fa-solid fa-plus" aria-hidden="true"></i>
                    <?= h($block['add']['label']) ?>
                </label>
                <?php // The page swaps it for the search box the other lists use. ?>
                <select class="form-select form-select-sm"
                        id="<?= h(AnalystProfileFormTool::fieldId(
                            $block['path'], array('add'))) ?>"
                        data-ap-order-pick
                        data-ap-add-filter="1"
                        data-ap-pick-placeholder="<?= h($block['add']['placeholder'] ?? '') ?>"
                        data-ap-pick-head="<?= h($block['add']['pick_head'] ?? '') ?>"
                        data-ap-pick-none="<?= h($block['add']['pick_none'] ?? __('no match')) ?>"
                        data-ap-pick-hint="<?= h(__('every visualisation is already ranked')) ?>">
                    <option value=""><?= h(__('pick one…')) ?></option>
                    <?php foreach ($block['add']['options'] as $key => $label): ?>
                        <option value="<?= h($key) ?>"<?= empty($descriptions[$key]) ? ''
                            : ' data-desc="' . h($descriptions[$key]) . '"' ?>><?= h($label) ?></option>
                    <?php endforeach; ?>
                </select>
                <?php if (!empty($block['add']['help'])): ?>
                    <p class="ap-map-add-help"><?= h($block['add']['help']) ?></p>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>

    <div class="wb-empty" data-ap-order-empty
         <?= empty($entries) ? '' : 'hidden' ?>>
        <span class="wb-empty-h"><?= h($block['empty_label']) ?></span>
        <?php if (!empty($block['empty_note'])): ?>
            <span><?= h($block['empty_note']) ?></span>
        <?php endif; ?>
    </div>

    <ol class="ap-order-list" data-ap-order-list
        <?= empty($entries) ? 'hidden' : '' ?>>
        <?php foreach ($entries as $i => $entry): ?>
            <?php
            /*
             * Both marks are drawn here as well as by the page, so
             * the first paint is already right: the script renumbers
             * after a move.
             */
            $classes = 'ap-order-row';
            if ($entry['standing'] !== 'ok') {
                $classes .= ' is-dim';
            }
            if ($cap > 0 && $i >= $cap) {
                $classes .= ' is-past-cap';
            }
            ?>
            <li class="<?= h($classes) ?>"
                data-ap-order-row
                data-ap-key="<?= h($entry['key']) ?>"<?= $entry['description'] === null ? ''
                    : ' title="' . h($entry['description']) . '"' ?>>
                <?php
                /*
                 * The position is carried by the index and the value
                 * is the shape id, which is the inverse of every other
                 * block here and is what makes a reorder a renumber
                 * rather than a rewrite.
                 */
                ?>
                <input type="hidden" data-ap-order-input
                       name="<?= h($name) ?>[<?= h($i) ?>]"
                       value="<?= h($entry['key']) ?>">
                <span class="ap-order-rank" data-ap-order-rank><?=
                    h($i + 1) ?></span>
                <span class="ap-order-body">
                    <span class="fw-semibold"><?=
                        h($entry['label']) ?></span>
                    <?php if ($entry['description'] !== null): ?>
                        <span class="wb-sub"><?=
                            h($entry['description']) ?></span>
                    <?php endif; ?>
                    <?php if ($entry['note'] !== null): ?>
                        <span class="ap-order-note"><?=
                            h($entry['note']) ?></span>
                    <?php endif; ?>
                </span>
                <?php if ($editable): ?>
                    <button type="button" class="wb-drop" data-ap-order-remove
                            title="<?= h(__('Stop ranking it')) ?>"
                            aria-label="<?= h(sprintf(__('Stop ranking %s'), $entry['label'])) ?>">
                        <i class="fa-solid fa-trash-can" aria-hidden="true"></i>
                    </button>
                <?php endif; ?>
            </li>
        <?php endforeach; ?>
    </ol>

    <?php if (!empty($block['cap_note'])): ?>
        <?php
        /*
         * Said only once the ranking is long enough for it to be true
         * of this document. A note about the sixth entry on a profile
         * with two of them is noise.
         */
        ?>
        <p class="wb-sub ap-order-cap" data-ap-order-capnote
           <?= count($entries) > $cap ? '' : 'hidden' ?>><?=
            h($block['cap_note']) ?></p>
    <?php endif; ?>
</div>
