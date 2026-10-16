<?php
/**
 * A page control over rows the fragment already holds.
 *
 * No second request, no Paginator, no `paginate()` in the controller:
 * this pass pages client-side over the rows the panel was rendered with.
 * The markup is nonetheless the real Bootstrap control, so when these
 * panels go live the change is the data source and not the chrome.
 *
 * The first page is rendered here rather than left to the script, so a
 * load that never runs JavaScript still shows a truthful range instead
 * of an empty control.
 *
 * Expected:
 * @var int    $size  Rows per page
 * @var int    $shown Rows this panel was given
 * @var int    $total The value's own count, which filtering never changes
 * @var mixed  $noun  Optional label for the range line. A string is
 *                    printed as given; `['one' => …, 'many' => …]` is
 *                    counted, and the script swaps the two as the range
 *                    changes under a filter
 * @var array  $sizes Optional page sizes to offer; absent for a caller
 *                    that wants the fixed size it passed
 * @var string $totalNote What to say about `total` instead of *"in
 *                    total"*, for the one caller whose total is not the
 *                    value's own count. The co-occurrence panel passes
 *                    the fold's *match* count when a narrowing is
 *                    active, which is a different sentence: *"of 100
 *                    rows (10,003 match)"* says the filter left more
 *                    than the page carries, where *"in total"* would
 *                    claim the value has 10,003 neighbours when it has
 *                    10,040. Printed under the same
 *                    `total !== shown` condition
 * @var string $totalGroup Which roll-up the total counts, for a caller
 *                    whose pager pages more than one. The range beside
 *                    it follows the roll-up on screen, so on the
 *                    co-occurrence panel's event pane a value total
 *                    would read *"of 18 rows (10,040 in total)"* — two
 *                    units on one line. Named here, the group switch
 *                    puts the number away with the rows it counts, and
 *                    each pane heading states its own total anyway
 */
$size = max(1, (int)($size ?? 10));
$shown = (int)($shown ?? 0);
$total = (int)($total ?? $shown);
$noun = $noun ?? null;
/*
 * A counted noun needs both forms in the markup, because the number
 * beside it changes client-side and `__n()` has long since run. Callers
 * that pass a plain string get exactly what they passed.
 */
$nounOne = is_array($noun) ? $noun['one'] : null;
$nounMany = is_array($noun) ? $noun['many'] : null;
$sizes = $sizes ?? null;
$totalNote = $totalNote ?? null;
$totalGroup = $totalGroup ?? null;

$pages = max(1, (int)ceil($shown / $size));
$to = min($size, $shown);
$from = $shown > 0 ? 1 : 0;
?>
<div class="d-flex align-items-center justify-content-between gap-3 flex-wrap">

    <?php
    /*
     * `total` is the value's count and not this panel's, so a filtered
     * table cannot end up claiming the value has fewer rows than it has.
     */
    ?>
    <span class="small text-muted">
        <span data-vp-page-from><?= h($from) ?></span>–<span
            data-vp-page-to><?= h($to) ?></span>
        <?= __('of') ?>
        <span data-vp-page-of><?= h($shown) ?></span>
        <?php if ($nounOne !== null): ?>
            <span data-vp-plural="pager"
                  data-vp-one="<?= h($nounOne) ?>"
                  data-vp-many="<?= h($nounMany) ?>"><?=
                h($shown === 1 ? $nounOne : $nounMany) ?></span>
        <?php elseif ($noun !== null): ?>
            <?= h($noun) ?>
        <?php endif; ?>
        <?php
        /*
         * Its own element so a caller can say which rows it counts.
         * `data-vp-group-only` is the page's existing switch: the group
         * pills already put away everything belonging to a roll-up
         * nobody is looking at, and this number is one of those things.
         */
        ?>
        <?php if ($total !== $shown): ?>
            <span data-vp-page-total<?= $totalGroup === null
                ? ''
                : ' data-vp-group-only="' . h($totalGroup) . '"' ?>><?=
                h($totalNote === null
                    ? sprintf(__('(%d in total)'), $total)
                    : $totalNote) ?></span>
        <?php endif; ?>
    </span>

    <?php if ($sizes !== null): ?>
        <?php
        /*
         * How many rows a page holds is the reader's call, not the
         * panel's. The control rewrites the pager's own
         * `data-vp-page-size` and the script repages what is already
         * here — no request, same as every other narrowing control on
         * this page.
         */
        ?>
        <label class="d-inline-flex align-items-center gap-1 small
                      text-muted mb-0">
            <span><?= __('Per page') ?></span>
            <select class="form-select form-select-sm w-auto"
                    data-vp-page-size-pick
                    aria-label="<?= __('Rows per page') ?>">
                <?php foreach ($sizes as $option): ?>
                    <option value="<?= h($option) ?>"
                            <?= (int)$option === $size ? 'selected' : '' ?>>
                        <?= h($option) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </label>
    <?php endif; ?>

    <nav data-vp-pager
         data-vp-page-size="<?= h($size) ?>"
         class="<?= $pages < 2 ? 'd-none' : '' ?>"
         aria-label="<?= __('Page navigation') ?>">
        <ul class="pagination pagination-sm mb-0">
            <?php
            // Arrows are dead at the ends rather than present and inert.
            ?>
            <li class="page-item disabled">
                <button type="button" class="page-link"
                        data-vp-page="0" disabled>&laquo;</button>
            </li>
            <?php
            // Page one's window; the script redraws it on every move.
            $window = $pages <= 7
                ? range(1, $pages)
                : array(1, 2, 3, 4, 5, null, $pages);
            ?>
            <?php foreach ($window as $n): ?>
                <?php if ($n === null): ?>
                    <li class="page-item disabled vp-page-gap">
                        <span class="page-link">…</span>
                    </li>
                <?php else: ?>
                    <li class="page-item<?= $n === 1 ? ' active' : '' ?>">
                        <button type="button" class="page-link"
                                data-vp-page="<?= h($n) ?>"
                                <?= $n === 1 ? 'aria-current="page"' : '' ?>>
                            <?= h($n) ?>
                        </button>
                    </li>
                <?php endif; ?>
            <?php endforeach; ?>
            <li class="page-item<?= $pages < 2 ? ' disabled' : '' ?>">
                <button type="button" class="page-link"
                        data-vp-page="2"
                        <?= $pages < 2 ? 'disabled' : '' ?>>&raquo;</button>
            </li>
        </ul>
    </nav>

</div>
