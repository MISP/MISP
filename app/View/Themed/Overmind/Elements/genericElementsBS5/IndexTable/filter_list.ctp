<?php
/**
 * A filter's values drawn as a list in the Filters panel: each with how many
 * rows it keeps and a bar for its share. A value is a link that sets the
 * filter to it alone, or drops it when it is set; past `fold` the values wait
 * behind "+N more" (index-filters.js). A `list` child of the bar (a dropdown
 * with `display => 'list'`), and a picker's `top` values.
 *
 * - name      : filter name, unprefixed
 * - label     : heading; none under a picker, whose button heads it
 * - icon      : classes of the heading's icon
 * - options   : [{value, label, html, count}], most rows first; `html`
 *               draws the value, already escaped, `label` names it
 * - total     : what the bars are a share of; the counts' sum when absent
 * - fold      : values shown before "+N more"
 * - separator : between values in the URL, for a filter that takes several
 * - swap      : swap key, `list-<name>` when absent
 *
 * @var array $child
 * @var IndexFilterState $state
 */
$name = $child['name'];
$separator = $child['separator'] ?? '|';
$set = [];
foreach (IndexFilterState::pieces((string)$state->get($name), $separator) as [$value, $excluded]) {
    if (!$excluded) {
        $set[] = (string)$value;
    }
}
$options = $child['options'];
$listed = array_map('strval', array_column($options, 'value'));
foreach ($set as $value) {
    // Set, though nothing beside the other filters carries it: listed to drop it.
    if (!in_array($value, $listed, true)) {
        $options[] = ['value' => $value, 'label' => $value, 'html' => null, 'count' => 0];
    }
}
$total = (int)($child['total'] ?? 0);
if ($total <= 0) {
    $total = array_sum(array_column($options, 'count'));
}
$fold = max(1, (int)($child['fold'] ?? 6));
$folded = 0;
$whole = count($options) === 1 && empty($set) && (int)$options[0]['count'] === $total;
?>
<div class="ifp-list<?= $set ? ' has-on' : '' ?>" data-ifp-swap="<?= h($child['swap'] ?? 'list-' . $name) ?>" data-ifp-key="<?= h($state->key($name)) ?>">
    <?php if (!empty($child['label'])): ?>
        <div class="ifp-list-h">
            <?php if (!empty($child['icon'])): ?>
                <i class="<?= h($child['icon']) ?>" aria-hidden="true"></i>
            <?php endif; ?>
            <span><?= h($child['label']) ?></span>
            <span class="ifp-list-n"><?= h(number_format(count($options))) ?></span>
        </div>
    <?php endif; ?>
    <?php if ($whole): ?>
        <div class="ifp-list-all"><?= h(sprintf(__('All %s:'), number_format($total))) ?>
            <span><?= $options[0]['html'] ?? h($options[0]['label']) ?></span></div>
    <?php else: ?>
        <?php foreach ($options as $at => $option): ?>
            <?php
            $value = (string)$option['value'];
            $on = in_array($value, $set, true);
            $count = (int)$option['count'];
            $share = $total > 0 ? $count / $total : 0;
            $rest = array_values(array_diff($set, [$value]));
            $hide = $at >= $fold && !$on;
            $folded += $hide ? 1 : 0;
            ?>
            <a class="ifp-lv<?= $on ? ' is-on' : '' ?>" data-ifp-nav
               href="<?= h($state->url([$name => $on ? ($rest ? implode($separator, $rest) : null) : $value])) ?>"
               title="<?= h(sprintf(
                   $on ? __('%1$s: %2$s of %3$s rows (%4$s%%). Click to drop this filter.') : __('%1$s: %2$s of %3$s rows (%4$s%%)'),
                   $option['label'],
                   number_format($count),
                   number_format($total),
                   round($share * 100)
               )) ?>"<?= $on ? ' aria-current="true"' : '' ?><?= $hide ? ' hidden data-ifp-lv-fold' : '' ?>>
                <span class="ifp-lv-l"><?= $option['html'] ?? h($option['label']) ?></span>
                <span class="ifp-lv-n"><?= h(number_format($count)) ?></span>
                <span class="ifp-lv-bar" aria-hidden="true"><i style="width: <?= h(round(min(1, $share) * 100, 1)) ?>%;"></i></span>
            </a>
        <?php endforeach; ?>
        <?php if ($folded): ?>
            <button type="button" class="ifp-list-more" data-ifp-list-more><?= h(sprintf(__('+%s more'), number_format($folded))) ?></button>
        <?php endif; ?>
    <?php endif; ?>
</div>
