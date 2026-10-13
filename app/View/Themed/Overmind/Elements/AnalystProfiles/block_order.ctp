<?php
/**
 * An ordered list: the visualisations this profile wants promoted,
 * best first.
 *
 * The fifth block kind, and the first whose **order is the setting**.
 * A map's rows can be drawn in any order without changing what the
 * document means; here the position is the whole of what is being
 * said, so the row carries a hidden input holding its shape id and the
 * position is the input's index. Reordering renumbers the inputs and
 * nothing else moves.
 *
 * **Up and down rather than drag.** Two buttons work with a keyboard,
 * work on a phone, need no library, and say what they do; a drag
 * handle is none of those and would be the only one on the page. The
 * list is at most a dozen rows, which is the length where buttons stop
 * being tedious and start being precise.
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
$canAdd = $editable && !empty($block['add']['options']);
?>
<?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?>
<div class="ap-order" data-ap-order
     data-ap-order-name="<?= h($name) ?>"
     data-ap-order-cap="<?= h($cap) ?>">

    <?php if ($editable): ?>
        <input type="hidden"
               name="<?= h(AnalystProfileFormTool::fieldName(
                   $block['path'], array('__present'))) ?>"
               value="1">
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
             * after a move, and a class only it knew about would mean
             * a ranking of seven looked like a ranking of seven equals
             * until somebody dragged something.
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
                data-ap-key="<?= h($entry['key']) ?>">
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
                    <span class="ap-order-moves">
                        <button type="button"
                                class="btn btn-sm btn-link"
                                data-ap-order-up
                                title="<?= h(__('Move up')) ?>"
                                aria-label="<?= h(sprintf(
                                    __('Move %s up'),
                                    $entry['label']
                                )) ?>">&uarr;</button>
                        <button type="button"
                                class="btn btn-sm btn-link"
                                data-ap-order-down
                                title="<?= h(__('Move down')) ?>"
                                aria-label="<?= h(sprintf(
                                    __('Move %s down'),
                                    $entry['label']
                                )) ?>">&darr;</button>
                        <button type="button"
                                class="btn btn-sm btn-link"
                                data-ap-order-remove
                                title="<?= h(__('Remove')) ?>"
                                aria-label="<?= h(sprintf(
                                    __('Stop ranking %s'),
                                    $entry['label']
                                )) ?>">&times;</button>
                    </span>
                <?php endif; ?>
            </li>
        <?php endforeach; ?>
    </ol>

    <?php if (!empty($block['cap_note'])): ?>
        <?php
        /*
         * Said only once the ranking is long enough for it to be true
         * of this document. A note about the sixth entry on a profile
         * with two of them is noise, and the one thing an editor's
         * notes must stay is worth reading.
         */
        ?>
        <p class="wb-sub ap-order-cap" data-ap-order-capnote
           <?= count($entries) > $cap ? '' : 'hidden' ?>><?=
            h($block['cap_note']) ?></p>
    <?php endif; ?>

    <?php if ($canAdd): ?>
        <div class="ap-order-add ap-map-add" data-ap-order-add
             data-ap-order-options="<?= h(json_encode(
                 $block['add']['options'])) ?>">
            <label for="<?= h(AnalystProfileFormTool::fieldId(
                $block['path'], array('add'))) ?>">
                <i class="fa-solid fa-plus" aria-hidden="true"></i>
                <?= h($block['add']['label']) ?>
            </label>
            <select class="form-select form-select-sm"
                    id="<?= h(AnalystProfileFormTool::fieldId(
                        $block['path'], array('add'))) ?>"
                    data-ap-order-pick
                    style="max-width:16rem">
                <option value=""><?= h(__('pick one…')) ?></option>
                <?php foreach ($block['add']['options']
                    as $key => $label): ?>
                    <option value="<?= h($key) ?>"><?=
                        h($label) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
    <?php endif; ?>
</div>
