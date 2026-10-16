<?php
/**
 * One group of counted facets.
 *
 * The honesty rules a count carries live here rather than in each tab's
 * template, because they are what make the count worth reading: a group
 * of zeroes is not rendered, a long tail is cut visibly, and a group
 * whose counts disagree with a number already on the page says so.
 *
 * Expected:
 * @var string $key      Facet key; rows carry `key:value` tokens
 * @var string $title    Group heading
 * @var array  $values   [['label' =>, 'count' =>, 'value' =>?, 'html' =>?], …]
 *                       `html` renders MISP's own component — a
 *                       distribution badge, a tag chip — in place of the
 *                       plain label, and is the caller's to escape.
 *                       `partition` marks an entry that divides the set
 *                       rather than naming a member of it; see below.
 * @var string $icon     Optional glyph for the heading
 * @var string $note     Optional honesty line; caller-escaped HTML so it
 *                       can emphasise the numbers it contrasts
 * @var int    $limit    Rows shown before the tail is folded (default 10)
 * @var int    $searchAt Size past which the group gets a search box (50)
 * @var array  $active   Tokens already ticked, so a group re-rendered by
 *                       the server comes back in the state it was left
 * @var bool   $local    True where the panel has no server-side
 *                       narrowing to fall back on. Then an entry whose
 *                       `listed` is zero cannot be reached at all —
 *                       ticking it could only empty the table — so it
 *                       is greyed rather than offered.
 */
$key = $key ?? null;
$values = $values ?? array();
$active = $active ?? array();
$icon = $icon ?? null;
$note = $note ?? null;
$limit = $limit ?? 10;
$searchAt = $searchAt ?? 50;
$local = $local ?? false;

/*
 * `partition` marks an entry that divides the whole set rather than
 * naming a member of it — *With a hit* and *No hit* over a group whose
 * other entries are warninglist names. Two things follow, and both are
 * about not comparing different quantities on one scale: it is left out
 * of the bar's scale, and it draws no bar. Without the first, one such
 * entry at 10,003 flattens every real entry beside it to a 0% bar.
 */
$total = 0;
$max = 0;
foreach ($values as $facet) {
    $count = (int)($facet['count'] ?? 0);
    $total += $count;
    if (empty($facet['partition'])) {
        $max = max($max, $count);
    }
}

/*
 * A facet rail of zeroes is a lie about the value: it implies rows exist
 * to be narrowed. The empty state belongs to the list, not to the
 * filter, so the group renders nothing at all.
 */
if ($key === null || empty($values) || $total === 0) {
    return;
}

$searchable = count($values) > $searchAt;
$groupId = 'vp-facet-' . preg_replace('/[^a-z0-9]+/', '-', strtolower($key));
?>
<div class="vp-facetgrp" data-vp-facet-group="<?= h($key) ?>">

    <div class="vp-subhead">
        <?php if ($icon !== null): ?>
            <i class="<?= h($icon) ?> me-1"></i>
        <?php endif; ?>
        <?= h($title) ?>
    </div>

    <?php if ($note !== null): ?>
        <div class="vp-facet-note"><?= $note ?></div>
    <?php endif; ?>

    <?php if ($searchable): ?>
        <?php
        /*
         * Past ~50 values a list is not a control a person can use. The
         * box narrows this group's own rows; it never touches the table.
         */
        ?>
        <input type="search"
               class="form-control form-control-sm mb-2"
               data-vp-facet-search
               aria-label="<?= h(sprintf(__('Search %s'), $title)) ?>"
               placeholder="<?= h(sprintf(
                   __('Search %d values'),
                   count($values)
               )) ?>">
    <?php endif; ?>

    <?php foreach ($values as $index => $facet): ?>
        <?php
        $count = (int)($facet['count'] ?? 0);
        $label = $facet['label'] ?? '';
        $value = $facet['value'] ?? preg_replace(
            '/[^a-z0-9]+/',
            '-',
            strtolower($label)
        );
        /*
         * Zero on a partition row rather than a share of a scale it is
         * not on. It paints nothing either way — `vp-facet-bar-none`
         * sees to that — but `--vp-facet-share: 47633%` sitting in the
         * markup is a number waiting to be believed by whoever next
         * removes the class.
         */
        $share = !empty($facet['partition']) || $max <= 0
            ? 0
            : round(($count / $max) * 100);
        // The tail is folded, not dropped: `n more` reveals these in
        // place, so the group never silently under-reports itself.
        $overflow = $index >= $limit;
        /*
         * A zero inside a group that has a total is not the same thing
         * as a group of zeroes. Where the caller counts against a
         * vocabulary rather than against what turned up, *undelete 0*
         * is the answer to a question the reader came with, so the row
         * stays — dimmed, and not offering a filter that could only
         * ever empty the list.
         */
        $zero = $count === 0;
        /*
         * Counted over the whole fold, reachable only through the rows
         * the panel carries. Where those are two different numbers and
         * the smaller is nought, the entry is a count the reader can
         * see and a filter that can only empty the table — so it reads
         * as a fact and not as a control. Only `$local` panels can say
         * this: everywhere else the tick sends the narrowing back to
         * the server, which has the rows.
         */
        $unreachable = !$zero && $local && isset($facet['listed'])
            && (int)$facet['listed'] === 0;
        $off = $zero || $unreachable;
        ?>
        <label class="vp-facet<?= $overflow ? ' d-none' : '' ?><?=
                   $off ? ' opacity-50' : '' ?>"
               <?= $overflow ? 'data-vp-facet-overflow' : '' ?>
               <?= $zero ? 'data-vp-facet-zero' : '' ?>
               <?= $unreachable ? 'data-vp-facet-unreachable' : '' ?>
               <?= $zero
                   ? 'title="' . h(sprintf(
                       __('No entry in this panel is a %s'),
                       $facet['label'] ?? $value
                   )) . '"'
                   : '' ?>
               <?= $unreachable
                   ? 'title="' . h(sprintf(
                       __('None of the rows this panel carries is a'
                           . ' %1$s. The other %2$s are outside them,'
                           . ' and this list cannot reach them.'),
                       $facet['label'] ?? $value,
                       number_format($count)
                   )) . '"'
                   : '' ?>>
            <?php
            /*
             * `listed` is how many of the rows the panel actually
             * carries this entry reaches. Where a caller supplies it
             * and it falls short of the count, narrowing on this entry
             * cannot be answered from the markup alone — which is the
             * one thing a client-side filter has to know before it
             * claims an empty table.
             */
            ?>
            <input type="checkbox"
                   class="form-check-input"
                   data-vp-facet-key="<?= h($key) ?>"
                   value="<?= h($value) ?>"
                   <?= isset($facet['listed'])
                       ? 'data-vp-facet-listed="'
                           . h((int)$facet['listed']) . '"'
                       : '' ?>
                   <?= isset($facet['listed'])
                       && (int)$facet['listed'] === $count
                       ? 'data-vp-complete="1"' : '' ?>
                   <?= in_array((string)$value, $active, true)
                       ? 'checked' : '' ?>
                   <?= $off ? 'disabled' : '' ?>
                   id="<?= h($groupId . '-' . $index) ?>">
            <span class="vp-facet-label">
                <?= isset($facet['html']) ? $facet['html'] : h($label) ?>
            </span>
            <span class="vp-facet-count"><?= h($count) ?></span>
            <span class="vp-facet-bar<?= empty($facet['partition'])
                      ? ''
                      : ' vp-facet-bar-none' ?>"
                  style="--vp-facet-share: <?= h($share) ?>%"></span>
        </label>
    <?php endforeach; ?>

    <?php if (count($values) > $limit): ?>
        <button type="button"
                class="vp-filter-clear mt-1"
                data-vp-facet-more>
            <?= h(sprintf(
                __('%d more'),
                count($values) - $limit
            )) ?>
        </button>
    <?php endif; ?>

</div>
